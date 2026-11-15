#include "config.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Config grammar (whitespace-separated tokens, '#' comments to EOL):
 *
 *   listen 127.0.0.1:8080
 *   upstream 127.0.0.1:9000
 *   max_conns 10000
 *   header_timeout_ms 10000
 *   idle_timeout_ms 60000
 *
 *   limit ip {
 *     algorithm token_bucket        # or sliding_window
 *     rate 100                      # token bucket: tokens/sec
 *     burst 200                     # token bucket: capacity
 *   }
 *   limit token {
 *     algorithm sliding_window
 *     limit 1000                    # sliding window: max requests
 *     window_ms 60000               # sliding window: window
 *   }
 *   route /api/heavy {
 *     algorithm token_bucket
 *     rate 20
 *     burst 40
 *   }
 */

typedef struct { const char *p; size_t n; } tok_t;

static int tokenize(const char *b, tok_t *t, int max)
{
    int n = 0;
    const char *p = b;
    for (;;) {
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '#') { while (*p && *p != '\n') p++; continue; }
        if (!*p) break;
        if (n >= max) break;
        if (*p == '{' || *p == '}') {
            t[n].p = p; t[n].n = 1; n++; p++;
            continue;
        }
        const char *s = p;
        while (*p && !isspace((unsigned char)*p) && *p != '{' && *p != '}' && *p != '#') p++;
        t[n].p = s; t[n].n = (size_t)(p - s); n++;
    }
    return n;
}

static int teq(tok_t t, const char *s)
{
    size_t sl = strlen(s);
    return sl == t.n && memcmp(t.p, s, t.n) == 0;
}

static long tnum(tok_t t)
{
    char tmp[64];
    size_t n = t.n < sizeof(tmp) - 1 ? t.n : sizeof(tmp) - 1;
    memcpy(tmp, t.p, n);
    tmp[n] = '\0';
    return strtol(tmp, NULL, 10);
}

static void tstr(tok_t t, char *out, size_t cap)
{
    size_t n = t.n < cap - 1 ? t.n : cap - 1;
    memcpy(out, t.p, n);
    out[n] = '\0';
}

static void limit_defaults(limit_params_t *p)
{
    p->alg = ALG_TOKEN_BUCKET;
    p->rate = 100;
    p->burst = 200;
    p->limit = 1000;
    p->window_ms = 60000;
}

static int validate_limit(const limit_params_t *p, const char *what, char *err, size_t errcap)
{
    if (p->alg == ALG_TOKEN_BUCKET) {
        if (p->rate <= 0 || p->burst < 1) {
            snprintf(err, errcap, "%s: token_bucket needs rate>0 and burst>=1", what);
            return -1;
        }
    } else {
        if (p->limit < 1 || p->window_ms < 100) {
            snprintf(err, errcap, "%s: sliding_window needs limit>=1 and window_ms>=100", what);
            return -1;
        }
    }
    return 0;
}

/* *pi points at the token after '{'; consumes up to and including '}'. */
static int parse_limit_block(tok_t *t, int n, int *pi, limit_params_t *p,
                             const char *what, char *err, size_t errcap)
{
    int i = *pi;
    while (i < n && !teq(t[i], "}")) {
        if (i + 1 >= n) break;
        if (teq(t[i], "algorithm")) {
            if (teq(t[i + 1], "token_bucket")) p->alg = ALG_TOKEN_BUCKET;
            else if (teq(t[i + 1], "sliding_window")) p->alg = ALG_SLIDING_WINDOW;
            else {
                snprintf(err, errcap, "%s: unknown algorithm", what);
                return -1;
            }
            i += 2;
        } else if (teq(t[i], "rate")) {
            p->rate = (double)tnum(t[i + 1]); i += 2;
        } else if (teq(t[i], "burst")) {
            p->burst = (double)tnum(t[i + 1]); i += 2;
        } else if (teq(t[i], "limit")) {
            p->limit = (int)tnum(t[i + 1]); i += 2;
        } else if (teq(t[i], "window_ms")) {
            p->window_ms = (int)tnum(t[i + 1]); i += 2;
        } else {
            snprintf(err, errcap, "%s: unknown key '%.*s'", what, (int)t[i].n, t[i].p);
            return -1;
        }
    }
    if (i >= n || !teq(t[i], "}")) {
        snprintf(err, errcap, "%s: missing '}'", what);
        return -1;
    }
    i++;
    *pi = i;
    return validate_limit(p, what, err, errcap);
}

int config_load(const char *path, config_t *c, char *err, size_t errcap)
{
    /* defaults */
    memset(c, 0, sizeof(*c));
    snprintf(c->listen, sizeof(c->listen), "127.0.0.1:8080");
    snprintf(c->upstream, sizeof(c->upstream), "127.0.0.1:9000");
    c->max_conns = 10000;
    c->header_timeout_ms = 10000;
    c->idle_timeout_ms = 60000;
    c->ip_on = 1;
    c->token_on = 0;
    limit_defaults(&c->ip);
    limit_defaults(&c->token);

    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errcap, "cannot open %s", path);
        return -1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0 || sz > 1 << 20) {
        fclose(f);
        snprintf(err, errcap, "bad config size");
        return -1;
    }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); snprintf(err, errcap, "oom"); return -1; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf); fclose(f);
        snprintf(err, errcap, "read error");
        return -1;
    }
    fclose(f);
    buf[sz] = '\0';

    tok_t *toks = malloc(4096 * sizeof(tok_t));
    if (!toks) { free(buf); snprintf(err, errcap, "oom"); return -1; }
    int n = tokenize(buf, toks, 4096);

    int rc = -1;
    int i = 0;
    while (i < n) {
        if (teq(toks[i], "listen") && i + 1 < n) {
            tstr(toks[i + 1], c->listen, sizeof(c->listen)); i += 2;
        } else if (teq(toks[i], "upstream") && i + 1 < n) {
            tstr(toks[i + 1], c->upstream, sizeof(c->upstream)); i += 2;
        } else if (teq(toks[i], "max_conns") && i + 1 < n) {
            c->max_conns = (int)tnum(toks[i + 1]); i += 2;
        } else if (teq(toks[i], "header_timeout_ms") && i + 1 < n) {
            c->header_timeout_ms = (int)tnum(toks[i + 1]); i += 2;
        } else if (teq(toks[i], "idle_timeout_ms") && i + 1 < n) {
            c->idle_timeout_ms = (int)tnum(toks[i + 1]); i += 2;
        } else if (teq(toks[i], "limit") && i + 2 < n) {
            limit_params_t *dst;
            int *on;
            if (teq(toks[i + 1], "ip"))        { dst = &c->ip;    on = &c->ip_on; }
            else if (teq(toks[i + 1], "token")) { dst = &c->token; on = &c->token_on; }
            else {
                snprintf(err, errcap, "limit: expected 'ip' or 'token'");
                goto out;
            }
            if (!teq(toks[i + 2], "{")) {
                snprintf(err, errcap, "limit: expected '{'");
                goto out;
            }
            i += 3;
            *on = 1;
            if (parse_limit_block(toks, n, &i, dst, "limit", err, errcap) < 0) goto out;
        } else if (teq(toks[i], "route") && i + 2 < n) {
            if (c->nroutes >= MAX_ROUTES) {
                snprintf(err, errcap, "too many routes (max %d)", MAX_ROUTES);
                goto out;
            }
            route_cfg_t *r = &c->routes[c->nroutes];
            tstr(toks[i + 1], r->prefix, sizeof(r->prefix));
            if (r->prefix[0] != '/') {
                snprintf(err, errcap, "route: prefix must start with '/'");
                goto out;
            }
            if (!teq(toks[i + 2], "{")) {
                snprintf(err, errcap, "route: expected '{'");
                goto out;
            }
            i += 3;
            limit_defaults(&r->p);
            if (parse_limit_block(toks, n, &i, &r->p, "route", err, errcap) < 0) goto out;
            c->nroutes++;
        } else {
            snprintf(err, errcap, "unknown token '%.*s'", (int)toks[i].n, toks[i].p);
            goto out;
        }
    }
    rc = 0;
out:
    free(toks);
    free(buf);
    return rc;
}
