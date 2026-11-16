#include "config.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>

void config_init_defaults(config_t *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->listen_host, sizeof(c->listen_host), "0.0.0.0");
    c->listen_port = 8080;
    snprintf(c->upstream_host, sizeof(c->upstream_host), "127.0.0.1");
    c->upstream_port = 9000;
    snprintf(c->token_header, sizeof(c->token_header), "X-User-Token");
    c->max_conns = 10000;
    c->idle_timeout_ms = 30000;
    c->head_timeout_ms = 10000;
    c->stats_interval_s = 0;
    c->trust_xff = 0;
    c->nzones = 0;
}

int64_t config_mtime_ms(const char *path) {
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    return (int64_t)st.st_mtimespec.tv_sec * 1000
         + st.st_mtimespec.tv_nsec / 1000000;
}

static void cfgerr(char *err, size_t errlen, int line, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = snprintf(err, errlen, "line %d: ", line);
    if (n < 0) n = 0;
    vsnprintf(err + n, errlen - (size_t)n, fmt, ap);
    va_end(ap);
}

/* Split a line into whitespace-separated tokens, in place. */
static int tokenize(char *s, char **tok, int max) {
    int n = 0;
    while (*s && n < max) {
        while (*s && isspace((unsigned char)*s)) s++;
        if (!*s) break;
        tok[n++] = s;
        while (*s && !isspace((unsigned char)*s)) s++;
        if (*s) *s++ = '\0';
    }
    return n;
}

static int parse_kv(const char *tok, const char *key, const char **val) {
    size_t klen = strlen(key);
    if (strncmp(tok, key, klen) != 0 || tok[klen] != '=') return 0;
    *val = tok + klen + 1;
    return 1;
}

int config_load(const char *path, config_t *out, char *err, size_t errlen) {
    config_t c;
    config_init_defaults(&c);

    FILE *f = fopen(path, "r");
    if (!f) {
        snprintf(err, errlen, "open %s: %s", path, strerror(errno));
        return -1;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    int lineno = 0;
    int rc = -1;

    while ((len = getline(&line, &cap, f)) != -1) {
        lineno++;
        char *p = line;
        while (*p && isspace((unsigned char)*p)) p++;
        if (*p == '\0' || *p == '#') continue;
        char *nl = p + strlen(p);
        while (nl > p && isspace((unsigned char)nl[-1])) *--nl = '\0';

        char *tok[32];
        int ntok = tokenize(p, tok, 32);
        if (ntok == 0) continue;

        if (strcmp(tok[0], "listen") == 0) {
            if (ntok != 2) { cfgerr(err, errlen, lineno, "listen needs host:port"); goto done; }
            char *colon = strrchr(tok[1], ':');
            if (!colon) { cfgerr(err, errlen, lineno, "bad listen address"); goto done; }
            *colon = '\0';
            int port = atoi(colon + 1);
            if (port <= 0 || port > 65535) { cfgerr(err, errlen, lineno, "bad port"); goto done; }
            snprintf(c.listen_host, sizeof(c.listen_host), "%s", tok[1]);
            c.listen_port = port;
        } else if (strcmp(tok[0], "upstream") == 0) {
            if (ntok != 2) { cfgerr(err, errlen, lineno, "upstream needs host:port"); goto done; }
            char *colon = strrchr(tok[1], ':');
            if (!colon) { cfgerr(err, errlen, lineno, "bad upstream address"); goto done; }
            *colon = '\0';
            int port = atoi(colon + 1);
            if (port <= 0 || port > 65535) { cfgerr(err, errlen, lineno, "bad port"); goto done; }
            snprintf(c.upstream_host, sizeof(c.upstream_host), "%s", tok[1]);
            c.upstream_port = port;
        } else if (strcmp(tok[0], "token_header") == 0) {
            if (ntok != 2) { cfgerr(err, errlen, lineno, "token_header needs one value"); goto done; }
            snprintf(c.token_header, sizeof(c.token_header), "%s", tok[1]);
        } else if (strcmp(tok[0], "max_conns") == 0) {
            if (ntok != 2 || (c.max_conns = (int)parse_u64(tok[1], strlen(tok[1]))) <= 0) {
                cfgerr(err, errlen, lineno, "bad max_conns"); goto done;
            }
        } else if (strcmp(tok[0], "idle_timeout_ms") == 0) {
            long long v = ntok == 2 ? parse_u64(tok[1], strlen(tok[1])) : -1;
            if (v <= 0) { cfgerr(err, errlen, lineno, "bad idle_timeout_ms"); goto done; }
            c.idle_timeout_ms = (int)v;
        } else if (strcmp(tok[0], "head_timeout_ms") == 0) {
            long long v = ntok == 2 ? parse_u64(tok[1], strlen(tok[1])) : -1;
            if (v <= 0) { cfgerr(err, errlen, lineno, "bad head_timeout_ms"); goto done; }
            c.head_timeout_ms = (int)v;
        } else if (strcmp(tok[0], "stats_interval_s") == 0) {
            long long v = ntok == 2 ? parse_u64(tok[1], strlen(tok[1])) : -1;
            if (v < 0) { cfgerr(err, errlen, lineno, "bad stats_interval_s"); goto done; }
            c.stats_interval_s = (int)v;
        } else if (strcmp(tok[0], "trust_xff") == 0) {
            if (ntok != 2 || (strcmp(tok[1], "on") && strcmp(tok[1], "off"))) {
                cfgerr(err, errlen, lineno, "trust_xff expects on|off"); goto done;
            }
            c.trust_xff = strcmp(tok[1], "on") == 0;
        } else if (strcmp(tok[0], "zone") == 0) {
            if (c.nzones >= 64) { cfgerr(err, errlen, lineno, "too many zones (max 64)"); goto done; }
            if (ntok < 6) {
                cfgerr(err, errlen, lineno,
                       "zone needs: name type=.. key=.. alg=.. rate=.. [burst=..]");
                goto done;
            }
            zone_cfg_t *z = &c.zones[c.nzones];
            memset(z, 0, sizeof(*z));
            snprintf(z->name, sizeof(z->name), "%s", tok[1]);
            const char *val;
            for (int i = 2; i < ntok; i++) {
                if (parse_kv(tok[i], "type", &val)) {
                    if (!strcmp(val, "ip")) z->type = ZT_IP;
                    else if (!strcmp(val, "token")) z->type = ZT_TOKEN;
                    else if (!strcmp(val, "route")) z->type = ZT_ROUTE;
                    else { cfgerr(err, errlen, lineno, "bad zone type"); goto done; }
                } else if (parse_kv(tok[i], "key", &val)) {
                    snprintf(z->match, sizeof(z->match), "%s", val);
                } else if (parse_kv(tok[i], "alg", &val)) {
                    if (!strcmp(val, "token_bucket")) z->params.alg = ALG_TOKEN_BUCKET;
                    else if (!strcmp(val, "sliding_log")) z->params.alg = ALG_SLIDING_LOG;
                    else { cfgerr(err, errlen, lineno, "bad alg"); goto done; }
                } else if (parse_kv(tok[i], "rate", &val)) {
                    z->params.rate = parse_rate(val, strlen(val),
                                                &z->params.window_ms);
                    if (z->params.rate <= 0) {
                        cfgerr(err, errlen, lineno, "bad rate (e.g. 100/s, 6000/m)");
                        goto done;
                    }
                } else if (parse_kv(tok[i], "burst", &val)) {
                    z->params.burst = parse_u64(val, strlen(val));
                    if (z->params.burst <= 0) {
                        cfgerr(err, errlen, lineno, "bad burst"); goto done;
                    }
                } else {
                    cfgerr(err, errlen, lineno, "unknown zone key '%s'", tok[i]);
                    goto done;
                }
            }
            if (z->match[0] == '\0' && z->type == ZT_ROUTE) {
                cfgerr(err, errlen, lineno, "route zone needs key=/prefix"); goto done;
            }
            if (z->params.burst == 0)
                z->params.burst = z->params.rate; /* no separate burst given */
            if (z->params.alg == ALG_SLIDING_LOG && z->params.rate > 100000) {
                cfgerr(err, errlen, lineno, "sliding_log rate capped at 100000");
                goto done;
            }
            c.nzones++;
        } else {
            cfgerr(err, errlen, lineno, "unknown directive '%s'", tok[0]);
            goto done;
        }
    }
    if (ferror(f)) {
        snprintf(err, errlen, "read %s: %s", path, strerror(errno));
        goto done;
    }
    *out = c;
    rc = 0;
done:
    free(line);
    fclose(f);
    return rc;
}
