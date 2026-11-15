/*
 * rlreplay — traffic replay / load generation tool for rlproxy.
 *
 * Modes:
 *   --serve ADDR                        run a trivial keep-alive upstream
 *   load generation (default):
 *     --target ADDR                     proxy address (default 127.0.0.1:8080)
 *     --duration SEC                    test duration (default 10)
 *     --rps R                           baseline request rate
 *     --burst-rps R2 --burst-start S --burst-dur D
 *                                       burst window inside the test
 *     --conns N                         max concurrent connections
 *     --paths /a,/b,/c                  rotate request paths
 *     --tokens K                        rotate K bearer tokens (tok-0..tok-K-1)
 *     --model FILE                      replay recorded traffic:
 *                                       "offset_ms METHOD /path token" per line
 *                                       ("-" = no token), loops over --duration
 *     --slow N --slow-ms M              N slowloris-style connections sending
 *                                       one header line every M ms, never finishing
 *
 * Reports latency percentiles and pass rate (2xx vs 429 vs other).
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "buf.h"
#include "evloop.h"
#include "http.h"

/* ---------------- options ---------------- */

static char   opt_host[256] = "127.0.0.1";
static int    opt_port = 8080;
static int    opt_duration = 10;
static double opt_rps = 100;
static double opt_burst_rps = 0, opt_burst_start = 0, opt_burst_dur = 0;
static int    opt_conns = 100;
static int    opt_npaths = 0;
static int    opt_ntokens = 1;
static const char *opt_model = NULL;
static int    opt_slow = 0;
static int    opt_slow_ms = 200;
static int    opt_serve = 0;

static evloop_t *L;

/* ---------------- stats ---------------- */

static uint64_t *lats;          /* ms, completed requests */
static size_t    nlats, caplats;
static uint64_t n_sent, n_ok, n_429, n_other, n_err, n_stall;
static uint64_t n_slow_created, n_slow_killed;
static uint64_t stat_sent, stat_ok, stat_429;

static void push_lat(uint64_t v)
{
    if (nlats == caplats) {
        caplats = caplats ? caplats * 2 : 65536;
        lats = realloc(lats, caplats * sizeof(uint64_t));
        if (!lats) { fprintf(stderr, "oom\n"); exit(1); }
    }
    lats[nlats++] = v;
}

/* ---------------- connections ---------------- */

enum { ST_CONNECTING, ST_IDLE, ST_RECV_HDR, ST_RECV_BODY, ST_RECV_CHUNK, ST_SLOW };

typedef struct {
    int      fd;
    int      state;
    int      is_slow;
    buf_t    in, out;
    uint32_t mask;
    uint64_t t_send;
    long     body_left;
    int      status;
    chunk_parser_t chunk;
    uint64_t next_slow;
} rc_t;

static rc_t **conns;
static size_t nconns, capconns;

static struct sockaddr_storage target_addr;
static socklen_t target_addrlen;

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void rc_free(rc_t *c)
{
    ev_del(L, c->fd);
    close(c->fd);
    buf_free(&c->in);
    buf_free(&c->out);
    /* swap-remove from array */
    for (size_t i = 0; i < nconns; i++) {
        if (conns[i] == c) {
            conns[i] = conns[--nconns];
            break;
        }
    }
    free(c);
}

static void rc_events(rc_t *c);

static void rc_done(rc_t *c)
{
    uint64_t lat = now_ms() - c->t_send;
    push_lat(lat);
    if (c->status == 429) { n_429++; stat_429++; }
    else if (c->status / 100 == 2) { n_ok++; stat_ok++; }
    else n_other++;
    c->state = ST_IDLE;
    c->in.len = 0;
}

static void rc_process(rc_t *c)
{
    while (c->in.len) {
        if (c->state == ST_RECV_HDR) {
            http_resp_t r;
            int pr = http_parse_response(c->in.p, c->in.len, &r);
            if (pr == 0) return;
            if (pr < 0) { n_err++; rc_free(c); return; }
            c->status = r.status;
            buf_consume(&c->in, r.header_len);
            if (r.chunked) {
                c->state = ST_RECV_CHUNK;
                chunk_init(&c->chunk);
            } else if (r.content_length > 0) {
                c->state = ST_RECV_BODY;
                c->body_left = r.content_length;
            } else {
                rc_done(c);
                if (c->state == ST_IDLE && c->in.len == 0) return;
                continue;
            }
        } else if (c->state == ST_RECV_BODY) {
            size_t take = c->in.len < (size_t)c->body_left ? c->in.len : (size_t)c->body_left;
            buf_consume(&c->in, take);
            c->body_left -= (long)take;
            if (c->body_left == 0) {
                rc_done(c);
                continue;
            }
            return;
        } else if (c->state == ST_RECV_CHUNK) {
            int done = 0;
            size_t used = chunk_consume(&c->chunk, c->in.p, c->in.len, &done);
            if (used == (size_t)-1) { n_err++; rc_free(c); return; }
            buf_consume(&c->in, used);
            if (done) {
                rc_done(c);
                continue;
            }
            if (used == 0) return;
        } else {
            return;
        }
    }
}

/* returns 0 ok, -1 if connection errored and was freed */
static int rc_flush(rc_t *c)
{
    while (c->out.len > 0) {
        ssize_t n = write(c->fd, c->out.p, c->out.len);
        if (n > 0) { buf_consume(&c->out, (size_t)n); continue; }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n < 0 && errno == EINTR) continue;
        n_err++;
        rc_free(c);
        return -1;
    }
    return 0;
}

static void on_rc(void *ud, uint32_t ev)
{
    rc_t *c = ud;
    if (c->state == ST_CONNECTING) {
        int err = 0;
        socklen_t l = sizeof(err);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &l) < 0 || err) {
            n_err++;
            rc_free(c);
            return;
        }
        if (c->is_slow) {
            c->state = ST_SLOW;
            n_slow_created++;
            /* partial headers: never terminated */
            static const char partial[] = "GET / HTTP/1.1\r\nHost: target\r\n";
            buf_put(&c->out, partial, sizeof(partial) - 1);
            c->next_slow = now_ms() + (uint64_t)opt_slow_ms;
        } else {
            c->state = ST_IDLE;
        }
    }
    if (ev & EV_WRITE) {
        if (rc_flush(c) < 0) return; /* c freed */
    }
    if (ev & EV_READ) {
        char tmp[65536];
        ssize_t n = read(c->fd, tmp, sizeof(tmp));
        if (n <= 0) {
            if (c->is_slow) n_slow_killed++;
            else n_err++;
            rc_free(c);
            return;
        }
        if (c->is_slow) {
            /* discard whatever the server sent (e.g. a 400 before close) */
        } else {
            if (buf_put(&c->in, tmp, (size_t)n) < 0) { n_err++; rc_free(c); return; }
            rc_process(c);
            return; /* rc_process may have freed c */
        }
    }
    rc_events(c);
}

static void rc_events(rc_t *c)
{
    uint32_t want = EV_READ;
    if (c->state == ST_CONNECTING) want = EV_READ | EV_WRITE;
    else if (c->out.len) want |= EV_WRITE;
    if (want != c->mask) {
        ev_mod(L, c->fd, want);
        c->mask = want;
    }
}

static rc_t *rc_new(int is_slow)
{
    int fd = socket(target_addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    set_nonblock(fd);
    if (connect(fd, (struct sockaddr *)&target_addr, target_addrlen) < 0 &&
        errno != EINPROGRESS) {
        close(fd);
        n_err++;
        return NULL;
    }
    rc_t *c = calloc(1, sizeof(*c));
    if (!c) { close(fd); return NULL; }
    c->fd = fd;
    c->state = ST_CONNECTING;
    c->is_slow = is_slow;
    if (nconns == capconns) {
        capconns = capconns ? capconns * 2 : 256;
        conns = realloc(conns, capconns * sizeof(rc_t *));
        if (!conns) { fprintf(stderr, "oom\n"); exit(1); }
    }
    conns[nconns++] = c;
    ev_add(L, fd, EV_READ | EV_WRITE, on_rc, c);
    c->mask = EV_READ | EV_WRITE;
    return c;
}

static rc_t *get_idle(void)
{
    static size_t rr;
    for (size_t k = 0; k < nconns; k++) {
        size_t i = (rr + k) % nconns;
        if (!conns[i]->is_slow && conns[i]->state == ST_IDLE) {
            rr = i + 1;
            return conns[i];
        }
    }
    return NULL;
}

static size_t count_active(void)
{
    size_t n = 0;
    for (size_t i = 0; i < nconns; i++)
        if (!conns[i]->is_slow) n++;
    return n;
}

static size_t count_inflight(void)
{
    size_t n = 0;
    for (size_t i = 0; i < nconns; i++)
        if (!conns[i]->is_slow && conns[i]->state >= ST_RECV_HDR) n++;
    return n;
}

static size_t count_slow_alive(void)
{
    size_t n = 0;
    for (size_t i = 0; i < nconns; i++)
        if (conns[i]->is_slow) n++;
    return n;
}

/* ---------------- request issuing ---------------- */

static char path_pool[64][1024];
static size_t path_idx;
static uint64_t token_ctr;

static void rc_issue(rc_t *c, const char *method, const char *path, const char *token)
{
    char req[2048];
    int n;
    if (token && token[0])
        n = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\n\r\n",
            method, path, opt_host, token);
    else
        n = snprintf(req, sizeof(req),
            "%s %s HTTP/1.1\r\nHost: %s\r\n\r\n", method, path, opt_host);
    buf_reset(&c->out);
    buf_put(&c->out, req, (size_t)n);
    c->t_send = now_ms();
    c->state = ST_RECV_HDR;
    n_sent++;
    stat_sent++;
    if (rc_flush(c) < 0) return; /* c freed */
    rc_events(c);
}

static const char *next_path(void)
{
    if (opt_npaths == 0) return "/";
    const char *p = path_pool[path_idx % (size_t)opt_npaths];
    path_idx++;
    return p;
}

static char tokbuf[64];
static const char *next_token(void)
{
    snprintf(tokbuf, sizeof(tokbuf), "tok-%llu",
             (unsigned long long)(token_ctr++ % (uint64_t)opt_ntokens));
    return tokbuf;
}

/* ---------------- traffic model ---------------- */

typedef struct {
    uint64_t off;
    char     method[16];
    char     path[1024];
    char     token[256];
} mreq_t;

static mreq_t  *model;
static size_t   nmodel;
static uint64_t model_period = 1;
static size_t   model_idx;
static uint64_t model_base;

static int load_model(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) { fprintf(stderr, "cannot open model %s\n", path); return -1; }
    size_t cap = 1024;
    model = malloc(cap * sizeof(mreq_t));
    char line[1400];
    while (fgets(line, sizeof(line), f)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        if (nmodel == cap) {
            cap *= 2;
            model = realloc(model, cap * sizeof(mreq_t));
        }
        mreq_t *m = &model[nmodel];
        memset(m, 0, sizeof(*m));
        int got = sscanf(line, "%llu %15s %1023s %255s",
                         (unsigned long long *)&m->off, m->method, m->path, m->token);
        if (got < 3)
            continue;
        if (got < 4 || m->token[0] == '-')
            m->token[0] = '\0';
        nmodel++;
    }
    fclose(f);
    if (nmodel == 0) { fprintf(stderr, "empty model\n"); return -1; }
    model_period = model[nmodel - 1].off + 1;
    fprintf(stderr, "[rlreplay] model: %zu requests, period %llums\n",
            nmodel, (unsigned long long)model_period);
    return 0;
}

/* ---------------- scheduler ---------------- */

static double   next_send;      /* ms since t0 */
static uint64_t t0;
static uint64_t last_stat;

static double current_rps(double el_ms)
{
    if (opt_burst_rps > 0) {
        double bs = opt_burst_start * 1000.0;
        double be = bs + opt_burst_dur * 1000.0;
        if (el_ms >= bs && el_ms < be) return opt_burst_rps;
    }
    return opt_rps;
}

static void tick(void)
{
    uint64_t now = now_ms();
    double el = (double)(now - t0);
    double dur_ms = opt_duration * 1000.0;

    if (el < dur_ms) {
        if (opt_model) {
            for (;;) {
                if (model_idx >= nmodel) {
                    model_idx = 0;
                    model_base += model_period;
                }
                if ((double)(model[model_idx].off + model_base) > el) break;
                rc_t *c = get_idle();
                if (!c) {
                    if ((int)count_active() < opt_conns) rc_new(0);
                    break; /* wait for a free connection */
                }
                mreq_t *m = &model[model_idx];
                rc_issue(c, m->method, m->path, m->token[0] ? m->token : NULL);
                model_idx++;
            }
        } else {
            double rps_now = current_rps(el);
            double step = 1000.0 / rps_now;
            while (next_send <= el) {
                rc_t *c = get_idle();
                if (!c) {
                    if ((int)count_active() < opt_conns) {
                        if (!rc_new(0)) { next_send += step; }
                        continue;
                    }
                    n_stall++;
                    next_send += step;
                    continue;
                }
                rc_issue(c, "GET", next_path(), next_token());
                next_send += step;
            }
        }
    }

    /* slow-connection attack conns */
    for (size_t i = 0; i < nconns; i++) {
        rc_t *c = conns[i];
        if (!c->is_slow || c->state != ST_SLOW) continue;
        if (now >= c->next_slow) {
            static const char line[] = "X-Pad: 1\r\n";
            ssize_t w = write(c->fd, line, sizeof(line) - 1);
            if (w < 0 && errno != EAGAIN && errno != EINTR) {
                n_slow_killed++;
                rc_free(c);
                i--;
                continue;
            }
            c->next_slow += (uint64_t)opt_slow_ms;
        }
    }

    if (now - last_stat >= 2000) {
        last_stat = now;
        fprintf(stderr,
            "[rlreplay] t=%5.1fs sent=%-6llu ok=%-6llu 429=%-6llu err=%-5llu "
            "stall=%-6llu inflight=%-4zu conns=%-4zu slow=%zu/%d\n",
            el / 1000.0,
            (unsigned long long)n_sent, (unsigned long long)stat_ok,
            (unsigned long long)stat_429, (unsigned long long)n_err,
            (unsigned long long)n_stall, count_inflight(), count_active(),
            count_slow_alive(), opt_slow);
        stat_sent = stat_ok = stat_429 = 0;
    }
}

static int cmp_u64(const void *a, const void *b)
{
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y ? 1 : 0;
}

static double pct(double p)
{
    if (!nlats) return 0;
    size_t i = (size_t)(p * (double)(nlats - 1));
    return (double)lats[i];
}

static void report(void)
{
    uint64_t done = n_ok + n_429 + n_other;
    qsort(lats, nlats, sizeof(uint64_t), cmp_u64);
    double mean = 0;
    for (size_t i = 0; i < nlats; i++) mean += (double)lats[i];
    if (nlats) mean /= (double)nlats;

    printf("\n================ rlreplay report ================\n");
    printf("duration            : %d s\n", opt_duration);
    printf("requests sent       : %llu\n", (unsigned long long)n_sent);
    printf("responses completed : %llu\n", (unsigned long long)done);
    printf("  2xx (passed)      : %llu  (%.2f%%)\n",
           (unsigned long long)n_ok, done ? 100.0 * n_ok / done : 0.0);
    printf("  429 (limited)     : %llu  (%.2f%%)\n",
           (unsigned long long)n_429, done ? 100.0 * n_429 / done : 0.0);
    printf("  other status      : %llu\n", (unsigned long long)n_other);
    printf("conn errors         : %llu\n", (unsigned long long)n_err);
    printf("sched stalls        : %llu (offered rate exceeded conn capacity)\n",
           (unsigned long long)n_stall);
    printf("achieved rps        : %.1f\n", (double)n_sent / opt_duration);
    if (opt_slow)
        printf("slow conns          : created=%llu killed=%llu alive=%zu\n",
               (unsigned long long)n_slow_created, (unsigned long long)n_slow_killed,
               count_slow_alive());
    printf("latency ms          : p50=%.2f p90=%.2f p99=%.2f p99.9=%.2f max=%.2f mean=%.2f\n",
           pct(0.50), pct(0.90), pct(0.99), pct(0.999),
           nlats ? (double)lats[nlats - 1] : 0.0, mean);
    printf("pass rate (2xx/sent): %.2f%%\n",
           n_sent ? 100.0 * n_ok / n_sent : 0.0);
    printf("==================================================\n");
}

/* ---------------- serve mode (trivial upstream) ---------------- */

typedef struct {
    int      fd;
    buf_t    in, out;
    long     body_left;
    int      state; /* 0=headers 1=body */
    uint32_t mask;
} sv_t;

static void sv_events(sv_t *s)
{
    uint32_t want = EV_READ | (s->out.len ? EV_WRITE : 0);
    if (want != s->mask) {
        ev_mod(L, s->fd, want);
        s->mask = want;
    }
}

static void sv_free(sv_t *s)
{
    ev_del(L, s->fd);
    close(s->fd);
    buf_free(&s->in);
    buf_free(&s->out);
    free(s);
}

static void on_sv_conn(void *ud, uint32_t ev)
{
    sv_t *s = ud;
    if (ev & EV_WRITE) {
        while (s->out.len) {
            ssize_t n = write(s->fd, s->out.p, s->out.len);
            if (n > 0) { buf_consume(&s->out, (size_t)n); continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0 && errno == EINTR) continue;
            sv_free(s);
            return;
        }
    }
    if (ev & EV_READ) {
        char tmp[65536];
        ssize_t n = read(s->fd, tmp, sizeof(tmp));
        if (n <= 0) { sv_free(s); return; }
        if (buf_put(&s->in, tmp, (size_t)n) < 0) { sv_free(s); return; }
        for (;;) {
            if (s->state == 0) {
                http_req_t r;
                int pr = http_parse_request(s->in.p, s->in.len, &r);
                if (pr == 0) break;
                if (pr < 0 || r.chunked) { sv_free(s); return; }
                buf_consume(&s->in, r.header_len);
                s->body_left = r.content_length > 0 ? r.content_length : 0;
                s->state = 1;
            }
            if (s->state == 1) {
                size_t take = s->in.len < (size_t)s->body_left ? s->in.len : (size_t)s->body_left;
                buf_consume(&s->in, take);
                s->body_left -= (long)take;
                if (s->body_left > 0) break;
                static const char resp[] =
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: 13\r\n"
                    "Connection: keep-alive\r\n\r\n"
                    "hello world!\n";
                buf_put(&s->out, resp, sizeof(resp) - 1);
                s->state = 0;
                continue;
            }
        }
    }
    sv_events(s);
}

static int listen_fd = -1;

static void on_sv_listen(void *ud, uint32_t ev)
{
    (void)ud; (void)ev;
    for (;;) {
        int fd = accept(listen_fd, NULL, NULL);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break;
        }
        set_nonblock(fd);
        sv_t *s = calloc(1, sizeof(*s));
        if (!s) { close(fd); continue; }
        s->fd = fd;
        ev_add(L, fd, EV_READ, on_sv_conn, s);
        s->mask = EV_READ;
    }
}

static int resolve(const char *spec, struct sockaddr_storage *out, socklen_t *outlen,
                   int passive)
{
    char host[256], port[32];
    const char *colon = strrchr(spec, ':');
    if (!colon) {
        snprintf(port, sizeof(port), "%s", spec);
        host[0] = '\0';
    } else {
        size_t hl = (size_t)(colon - spec);
        if (hl >= sizeof(host)) hl = sizeof(host) - 1;
        memcpy(host, spec, hl);
        host[hl] = '\0';
        snprintf(port, sizeof(port), "%s", colon + 1);
    }
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (passive) hints.ai_flags = AI_PASSIVE;
    const char *h = (host[0] && strcmp(host, "*") != 0) ? host : NULL;
    if (getaddrinfo(passive ? h : (host[0] ? host : "127.0.0.1"), port, &hints, &res) != 0 || !res)
        return -1;
    memcpy(out, res->ai_addr, res->ai_addrlen);
    *outlen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static int run_serve(void)
{
    struct sockaddr_storage addr;
    socklen_t alen;
    char spec[300];
    snprintf(spec, sizeof(spec), "%s:%d", opt_host, opt_port);
    if (resolve(spec, &addr, &alen, 1) < 0) {
        fprintf(stderr, "bad listen address %s\n", spec);
        return 1;
    }
    listen_fd = socket(addr.ss_family, SOCK_STREAM, 0);
    if (listen_fd < 0) return 1;
    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(listen_fd, (struct sockaddr *)&addr, alen) < 0 ||
        listen(listen_fd, 1024) < 0) {
        perror("bind/listen");
        return 1;
    }
    set_nonblock(listen_fd);
    ev_add(L, listen_fd, EV_READ, on_sv_listen, NULL);
    fprintf(stderr, "[rlreplay] serving on %s:%d\n", opt_host, opt_port);
    for (;;) ev_wait(L, 1000);
    return 0;
}

/* ---------------- main ---------------- */

static void usage(void)
{
    fprintf(stderr,
        "rlreplay --serve ADDR\n"
        "rlreplay [--target H:P] [--duration S] [--rps R]\n"
        "         [--burst-rps R2 --burst-start S --burst-dur D]\n"
        "         [--conns N] [--paths /a,/b] [--tokens K]\n"
        "         [--model FILE] [--slow N --slow-ms M]\n");
}

static int parse_addr_opt(const char *spec)
{
    const char *colon = strrchr(spec, ':');
    if (!colon) {
        opt_port = atoi(spec);
        return 0;
    }
    size_t hl = (size_t)(colon - spec);
    if (hl >= sizeof(opt_host)) hl = sizeof(opt_host) - 1;
    memcpy(opt_host, spec, hl);
    opt_host[hl] = '\0';
    opt_port = atoi(colon + 1);
    return opt_port > 0 ? 0 : -1;
}

int main(int argc, char **argv)
{
    signal(SIGPIPE, SIG_IGN);

    char paths_csv[4096] = "";
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--serve") && i + 1 < argc) {
            opt_serve = 1;
            parse_addr_opt(argv[++i]);
        } else if (!strcmp(argv[i], "--target") && i + 1 < argc) {
            parse_addr_opt(argv[++i]);
        } else if (!strcmp(argv[i], "--duration") && i + 1 < argc) {
            opt_duration = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--rps") && i + 1 < argc) {
            opt_rps = atof(argv[++i]);
        } else if (!strcmp(argv[i], "--burst-rps") && i + 1 < argc) {
            opt_burst_rps = atof(argv[++i]);
        } else if (!strcmp(argv[i], "--burst-start") && i + 1 < argc) {
            opt_burst_start = atof(argv[++i]);
        } else if (!strcmp(argv[i], "--burst-dur") && i + 1 < argc) {
            opt_burst_dur = atof(argv[++i]);
        } else if (!strcmp(argv[i], "--conns") && i + 1 < argc) {
            opt_conns = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--paths") && i + 1 < argc) {
            snprintf(paths_csv, sizeof(paths_csv), "%s", argv[++i]);
        } else if (!strcmp(argv[i], "--tokens") && i + 1 < argc) {
            opt_ntokens = atoi(argv[++i]);
            if (opt_ntokens < 1) opt_ntokens = 1;
        } else if (!strcmp(argv[i], "--model") && i + 1 < argc) {
            opt_model = argv[++i];
        } else if (!strcmp(argv[i], "--slow") && i + 1 < argc) {
            opt_slow = atoi(argv[++i]);
        } else if (!strcmp(argv[i], "--slow-ms") && i + 1 < argc) {
            opt_slow_ms = atoi(argv[++i]);
        } else {
            usage();
            return 1;
        }
    }

    L = evloop_new();
    if (!L) { fprintf(stderr, "no event loop\n"); return 1; }

    if (opt_serve) return run_serve();

    /* split paths csv */
    if (paths_csv[0]) {
        char *save = NULL;
        for (char *p = strtok_r(paths_csv, ",", &save); p && opt_npaths < 64;
             p = strtok_r(NULL, ",", &save)) {
            snprintf(path_pool[opt_npaths], sizeof(path_pool[0]), "%s", p);
            opt_npaths++;
        }
    }

    char spec[300];
    snprintf(spec, sizeof(spec), "%s:%d", opt_host, opt_port);
    if (resolve(spec, &target_addr, &target_addrlen, 0) < 0) {
        fprintf(stderr, "cannot resolve target %s\n", spec);
        return 1;
    }

    if (opt_model && load_model(opt_model) < 0) return 1;

    /* open slow-attack connections up front */
    for (int i = 0; i < opt_slow; i++) rc_new(1);

    t0 = now_ms();
    last_stat = t0;
    next_send = 0;
    double dur_ms = opt_duration * 1000.0;

    fprintf(stderr, "[rlreplay] target=%s duration=%ds rps=%.0f conns=%d slow=%d\n",
            spec, opt_duration, opt_rps, opt_conns, opt_slow);

    for (;;) {
        uint64_t now = now_ms();
        double el = (double)(now - t0);

        /* compute wait until next scheduled action */
        int timeout = 50;
        if (el < dur_ms) {
            double next;
            if (opt_model) {
                if (model_idx >= nmodel) { model_idx = 0; model_base += model_period; }
                next = (double)(model[model_idx].off + model_base);
            } else {
                next = next_send;
            }
            double wait = next - el;
            if (wait < 0) wait = 0;
            if (wait < timeout) timeout = (int)wait;
        }
        ev_wait(L, timeout);
        tick();

        now = now_ms();
        el = (double)(now - t0);
        if (el >= dur_ms && (count_inflight() == 0 || el >= dur_ms + 3000))
            break;
    }

    report();
    return 0;
}
