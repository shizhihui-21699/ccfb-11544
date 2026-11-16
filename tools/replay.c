/* replay — traffic replayer and attack generator for rlproxy.
 *
 * It reuses the proxy's event-loop/sbuf/http code so it behaves like
 * thousands of real non-blocking clients inside one process.
 *
 * Traffic model file (line based):
 *   GET  /api/items            relative weight 1 (default)
 *   POST /api/orders    weight=3
 *   GET  /admin         weight=1 token=admin-secret
 *
 * Modes:
 *   burst  N parallel clients hammering as fast as possible
 *   slow   slowloris-style: hold connections, drip headers byte-by-byte
 *   mix    attack traffic + a benign baseline measured separately
 *   replay schedule requests at fixed rps from the model (validation)
 */
#include "event_loop.h"
#include "sbuf.h"
#include "http.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <sys/socket.h>

/* ---------------- model ---------------- */

typedef struct {
    char method[8];
    char path[256];
    char token[128];
    int  weight;
} model_entry_t;

typedef struct {
    model_entry_t e[256];
    int           n;
    int           total_weight;
} model_t;

/* ---------------- stats ---------------- */

typedef struct {
    uint64_t sent;
    uint64_t status[600];
    uint64_t allowed;       /* 2xx/3xx */
    uint64_t limited;       /* 429 */
    uint64_t errors;        /* everything else / io failure */
    int64_t *lat_ms;        /* only allowed requests */
    size_t   lat_n, lat_cap;
} stats_t;

/* ---------------- virtual client ---------------- */

typedef enum {
    VC_CONNECT, VC_SEND, VC_READ_HEAD, VC_READ_BODY, VC_SLOW_DRIP, VC_DONE
} vc_state_t;

typedef struct vclient {
    int           id;
    int           slot;        /* stable pool slot -> stable identity */
    int           fd;
    vc_state_t    state;
    sbuf_t        out;
    sbuf_t        in;
    http_resp_t   resp;
    int           head_done;
    long long     remain;
    int64_t       start_ms;
    int           is_attack;
    char          xff[64];
    char          token[128];
    model_entry_t me;
    uint64_t      timer;
    uint64_t      deadline_timer;
    int           slow_drips_left;
    int64_t       deadline_ms;
    int           cur_events;
} vclient_t;

/* ---------------- runner ---------------- */

typedef struct {
    event_loop_t *el;
    char          host[128];
    int           port;
    model_t       model;
    stats_t       benign;
    stats_t       attack;
    int           n_attack;
    int           n_benign;
    int           concurrency;
    int64_t       duration_ms;
    int           rps;
    int           mode;          /* 0 burst 1 slow 2 mix 3 replay */
    int64_t       end_at_ms;
    int64_t       hard_stop_ms;
    int           stopping;
    int           request_timeout_ms;
    vclient_t   **active;
    int           active_n;
    uint64_t      tick_timer;
    int           slow_drip_interval_ms;
    int           slow_hold_ms;
    int64_t       benign_budget; /* tokens for the replay rps pacer */
    int64_t       last_tick_ms;
    int           next_attack_id;
    int           next_benign_id;
} runner_t;

static vclient_t *vc_new(runner_t *r, int attack);
static void vc_start(vclient_t *vc);
static void vc_destroy(vclient_t *vc);
static void vc_finish(vclient_t *vc, int status, int io_fail);
static void vc_deadline(event_loop_t *el, void *arg);

/* ---------------- model loading ---------------- */

static int model_load(const char *path, model_t *m, char *err, size_t errlen) {
    FILE *f = fopen(path, "r");
    if (!f) { snprintf(err, errlen, "model: %s", strerror(errno)); return -1; }
    char line[512];
    int lineno = 0;
    while (fgets(line, sizeof(line), f)) {
        lineno++;
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0' || *p == '#' || *p == '\n') continue;
        if (m->n >= 256) break;
        model_entry_t *e = &m->e[m->n];
        e->weight = 1;
        char method[16] = "GET", pathbuf[256] = "", tok[128] = "";
        int nf = sscanf(p, "%15s %255s", method, pathbuf);
        if (nf < 2) {
            snprintf(err, errlen, "model line %d malformed", lineno);
            fclose(f);
            return -1;
        }
        char *w = strstr(p, "weight=");
        if (w) e->weight = atoi(w + 7);
        if (e->weight <= 0) e->weight = 1;
        char *t = strstr(p, "token=");
        if (t) sscanf(t + 6, "%127s", tok);
        snprintf(e->method, sizeof(e->method), "%s", method);
        snprintf(e->path, sizeof(e->path), "%s", pathbuf);
        snprintf(e->token, sizeof(e->token), "%s", tok);
        m->total_weight += e->weight;
        m->n++;
    }
    fclose(f);
    if (m->n == 0) { snprintf(err, errlen, "model is empty"); return -1; }
    return 0;
}

static const model_entry_t *model_pick(const model_t *m, int roll) {
    int acc = 0;
    for (int i = 0; i < m->n; i++) {
        acc += m->e[i].weight;
        if (roll < acc) return &m->e[i];
    }
    return &m->e[m->n - 1];
}

/* ---------------- stats ---------------- */

static void stats_record(stats_t *s, int status, int64_t lat_ms, int io_fail) {
    s->sent++;
    if (io_fail) { s->errors++; return; }
    if (status >= 200 && status < 400) {
        s->allowed++;
        if (s->lat_n == s->lat_cap) {
            size_t nc = s->lat_cap ? s->lat_cap * 2 : 1024;
            int64_t *nb = realloc(s->lat_ms, nc * sizeof(int64_t));
            if (nb) { s->lat_ms = nb; s->lat_cap = nc; }
        }
        if (s->lat_n < s->lat_cap) s->lat_ms[s->lat_n++] = lat_ms;
    } else if (status == 429) {
        s->limited++;
    } else {
        s->errors++;
    }
    if (status >= 100 && status < 600) s->status[status]++;
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return (x > y) - (x < y);
}

static int64_t percentile(stats_t *s, double q) {
    if (s->lat_n == 0) return 0;
    qsort(s->lat_ms, s->lat_n, sizeof(int64_t), cmp_i64);
    size_t idx = (size_t)(q * (double)(s->lat_n - 1) + 0.5);
    return s->lat_ms[idx];
}

/* ---------------- virtual client IO ---------------- */

static void vc_build_request(vclient_t *vc, runner_t *r) {
    sbuf_reset(&vc->out);
    const model_entry_t *e = &vc->me;
    buf_printf(&vc->out.data, &vc->out.len, &vc->out.cap,
        "%s %s HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "X-Forwarded-For: %s\r\n"
        "%s%s%s"
        "User-Agent: rl-replay/1.0\r\n"
        "Connection: close\r\n\r\n",
        e->method, e->path, r->host, r->port, vc->xff,
        vc->token[0] ? "X-User-Token: " : "",
        vc->token[0] ? vc->token : "",
        vc->token[0] ? "\r\n" : "");
}

static void vc_writable(event_loop_t *el, int fd, int events, void *arg);
static void vc_readable(event_loop_t *el, int fd, int events, void *arg);
static void vc_slow_tick(event_loop_t *el, void *arg);

/* Forward for the runner pointer stashed via a small global; the loop
 * is process-local and a replay run owns the whole process. */
static runner_t *g_runner;

static void vc_arm(vclient_t *vc, int events) {
    if (vc->cur_events == events) return;
    el_io_cb cb = (events & EL_WRITE) ? vc_writable : vc_readable;
    el_watch(g_runner->el, vc->fd, events, cb, vc);
    vc->cur_events = events;
}

static void vc_deadline(event_loop_t *el, void *arg) {
    (void)el;
    vclient_t *vc = arg;
    vc->deadline_timer = 0;
    if (vc->state != VC_DONE) vc_finish(vc, 0, 1);
}

static void vc_start(vclient_t *vc) {
    runner_t *r = g_runner;
    int roll = (int)((vc->id * 2654435761u + 17) %
                     (unsigned)r->model.total_weight);
    const model_entry_t *e = model_pick(&r->model, roll);
    vc->me = *e;
    /* Benign callers present a stable user token (one per identity);
     * attackers stay anonymous and are governed by the IP layers. */
    if (!vc->is_attack)
        snprintf(vc->token, sizeof(vc->token), "user-%d", vc->id);
    else if (e->token[0])
        snprintf(vc->token, sizeof(vc->token), "%s", e->token);

    vc->fd = connect_tcp_nb(r->host, r->port);
    if (vc->fd < 0) {
        stats_record(vc->is_attack ? &r->attack : &r->benign,
                     0, 0, 1);
        vc->state = VC_DONE;
        return;
    }
    /* Distinct source identity per virtual client; attackers and benign
     * callers live in disjoint address ranges so their per-IP keys never
     * collide. */
    unsigned base = (unsigned)vc->id;
    if (vc->is_attack)
        snprintf(vc->xff, sizeof(vc->xff), "10.%u.%u.%u",
                 (base / 65536) % 256, (base / 256) % 256,
                 (base % 256) + 1);
    else
        snprintf(vc->xff, sizeof(vc->xff), "192.168.%u.%u",
                 (base / 256) % 256, (base % 256) + 1);
    vc->start_ms = el_now(r->el);
    vc->state = VC_CONNECT;
    vc_arm(vc, EL_WRITE);
    vc->deadline_timer = el_timer_add(r->el, r->request_timeout_ms,
                                       vc_deadline, vc);
}

static int socket_ok(int fd) {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) return -1;
    return err == 0 ? 0 : -1;
}

static void vc_finish(vclient_t *vc, int status, int io_fail) {
    runner_t *r = g_runner;
    int64_t lat = el_now(r->el) - vc->start_ms;
    stats_record(vc->is_attack ? &r->attack : &r->benign,
                 status, lat, io_fail);
    vc->state = VC_DONE;
    if (vc->timer) { el_timer_cancel(r->el, vc->timer); vc->timer = 0; }
    if (vc->deadline_timer) {
        el_timer_cancel(r->el, vc->deadline_timer);
        vc->deadline_timer = 0;
    }
    if (vc->fd >= 0) {
        el_unwatch(r->el, vc->fd);
        close(vc->fd);
        vc->fd = -1;
    }
    vc->cur_events = 0;
}

static void vc_writable(event_loop_t *el, int fd, int events, void *arg) {
    (void)fd; (void)events;
    vclient_t *vc = arg;
    runner_t *r = g_runner;

    if (vc->state == VC_CONNECT) {
        if (socket_ok(vc->fd) < 0) { vc_finish(vc, 0, 1); return; }
        vc_build_request(vc, r);
        vc->state = VC_SEND;
        if (r->mode == 1 && vc->is_attack) {
            /* slowloris: send only the first line now, drip the rest */
            char *crlf = strstr(vc->out.data, "\r\n");
            size_t first = crlf ? (size_t)(crlf - vc->out.data) + 2 : 8;
            ssize_t w = write(vc->fd, vc->out.data, first);
            if (w < 0 && errno != EAGAIN) { vc_finish(vc, 0, 1); return; }
            sbuf_consume(&vc->out, (size_t)(w > 0 ? w : (ssize_t)first));
            vc->state = VC_SLOW_DRIP;
            vc->slow_drips_left = (int)sbuf_buffered(&vc->out);
            vc->timer = el_timer_add(el, r->slow_drip_interval_ms,
                                      vc_slow_tick, vc);
            return;
        }
    }
    if (vc->state == VC_SEND) {
        ssize_t w = sbuf_write_fd(&vc->out, vc->fd);
        if (w < 0 && errno != EAGAIN) { vc_finish(vc, 0, 1); return; }
        if (sbuf_buffered(&vc->out) == 0) {
            vc->state = VC_READ_HEAD;
            vc_arm(vc, EL_READ);
        }
    }
}

static void vc_slow_tick(event_loop_t *el, void *arg) {
    vclient_t *vc = arg;
    runner_t *r = g_runner;
    vc->timer = 0;
    if (el_now(el) > vc->deadline_ms) {
        /* Held long enough: abort the request and count it. The proxy
         * should have closed the socket via head_timeout first. */
        vc_finish(vc, 0, 1);
        return;
    }
    if (sbuf_buffered(&vc->out) == 0) {
        vc->state = VC_READ_HEAD;
        vc_arm(vc, EL_READ);
        return;
    }
    ssize_t w = write(vc->fd, vc->out.data + vc->out.rd, 1);
    if (w == 1) {
        sbuf_consume(&vc->out, 1);
        vc->slow_drips_left--;
    } else if (w < 0 && errno != EAGAIN) {
        vc_finish(vc, 0, 1);
        return;
    }
    vc->timer = el_timer_add(el, r->slow_drip_interval_ms,
                              vc_slow_tick, vc);
}

static void vc_readable(event_loop_t *el, int fd, int events, void *arg) {
    (void)el; (void)fd; (void)events;
    vclient_t *vc = arg;

    for (;;) {
        ssize_t n = sbuf_read_fd(&vc->in, vc->fd, 4 * 1024 * 1024);
        if (n == 0) {
            if (vc->head_done) vc_finish(vc, vc->resp.status, 0);
            else vc_finish(vc, 0, 1);
            return;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            vc_finish(vc, 0, 1);
            return;
        }
        if (!vc->head_done) {
            hp_status_t st = http_parse_response(
                vc->in.data + vc->in.rd, sbuf_buffered(&vc->in), &vc->resp);
            if (st == HP_NEED_MORE) continue;
            if (st != HP_OK) { vc_finish(vc, 0, 1); return; }
            vc->head_done = 1;
            vc->remain = vc->resp.content_length;
            sbuf_consume(&vc->in, vc->resp.head_len);
            if (vc->resp.status == 429 || vc->remain == 0) {
                vc_finish(vc, vc->resp.status, 0);
                return;
            }
        }
        if (vc->remain > 0) {
            vc->remain -= (long long)sbuf_buffered(&vc->in);
            sbuf_reset(&vc->in);
            if (vc->remain <= 0) { vc_finish(vc, vc->resp.status, 0); return; }
        }
    }
}

static vclient_t *vc_new(runner_t *r, int attack) {
    vclient_t *vc = calloc(1, sizeof(*vc));
    if (!vc) return NULL;
    /* Identity numbering: benign callers in 1..N, attackers in a
     * separate high range so the two populations never share an IP key.
     * The id is unique for the whole run. */
    vc->id = attack ? (1000000 + ++r->next_attack_id)
                    : (++r->next_benign_id);
    vc->is_attack = attack;
    vc->fd = -1;
    sbuf_init(&vc->out);
    sbuf_init(&vc->in);
    vc->deadline_ms = el_now(r->el) + r->slow_hold_ms;
    return vc;
}

static void vc_destroy(vclient_t *vc) {
    if (vc->fd >= 0) close(vc->fd);
    sbuf_free(&vc->out);
    sbuf_free(&vc->in);
    free(vc);
}

/* ---------------- pacing ---------------- */

static void runner_tick(event_loop_t *el, void *arg);

/* Deterministic shutdown: once the test window closes, stop spawning and
 * force-finish anything still alive after the grace period. Never depends
 * on every vclient reaching DONE on its own. */
static void hard_stop_cb(event_loop_t *el, void *arg) {
    runner_t *r = arg;
    for (int i = 0; i < r->active_n; i++) {
        vclient_t *vc = r->active[i];
        if (vc->state != VC_DONE) vc_finish(vc, 0, 1);
    }
    el_stop(el);
}

static void spawn_batch(runner_t *r, int n, int attack) {
    for (int i = 0; i < n; i++) {
        if (r->active_n >= r->concurrency) break;
        vclient_t *vc = vc_new(r, attack);
        if (!vc) break;
        r->active = realloc(r->active,
                            (size_t)(r->active_n + 1) * sizeof(*r->active));
        r->active[r->active_n++] = vc;
        vc_start(vc);
    }
}

static void runner_tick(event_loop_t *el, void *arg) {
    runner_t *r = arg;
    r->tick_timer = 0;
    int64_t now = el_now(el);
    if (now >= r->end_at_ms) {
        if (!r->stopping) {
            r->stopping = 1;
            el_timer_add(el, r->hard_stop_ms - now, hard_stop_cb, r);
        }
        return;
    }

    /* Reap finished vclients and keep the pool at target concurrency. */
    int alive = 0;
    for (int i = 0; i < r->active_n; i++) {
        vclient_t *vc = r->active[i];
        if (vc->state == VC_DONE) {
            vc_destroy(vc);
            r->active[i] = r->active[--r->active_n];
            i--;
        } else {
            alive++;
        }
    }

    if (r->mode == 3) {
        /* Fixed-rps replay: budget tokens per tick (100ms granularity). */
        int64_t elapsed = now - r->last_tick_ms;
        r->benign_budget += (int64_t)r->rps * elapsed / 1000;
        r->last_tick_ms = now;
        int want = (int)(r->benign_budget < 64 ? r->benign_budget : 64);
        if (want > 0) {
            spawn_batch(r, want, 0);
            r->benign_budget -= want;
        }
    } else {
        int target_attack = r->n_attack;
        int alive_attack = 0, alive_benign = 0;
        for (int i = 0; i < r->active_n; i++) {
            if (r->active[i]->is_attack) alive_attack++;
            else alive_benign++;
        }
        /* Throttle new connections per tick so a ramp-up cannot flood
         * the listener's half-open queue; the pool fills over a few
         * ticks and then stays at target concurrency. */
        const int spawn_cap = 200;
        if (alive_attack < target_attack) {
            int need = target_attack - alive_attack;
            if (need > spawn_cap) need = spawn_cap;
            spawn_batch(r, need, 1);
        }
        if (r->mode == 2 && alive_benign < r->n_benign) {
            int need = r->n_benign - alive_benign;
            if (need > spawn_cap) need = spawn_cap;
            spawn_batch(r, need, 0);
        }
    }
    (void)alive;
    r->tick_timer = el_timer_add(el, 100, runner_tick, r);
}

/* ---------------- reporting ---------------- */

static void print_stats(const char *name, const stats_t *s, int json) {
    double pass = s->sent ? 100.0 * (double)s->allowed / (double)s->sent : 0;
    if (!json) {
        fprintf(stderr, "\n=== %s ===\n", name);
        fprintf(stderr, "sent=%llu allowed=%llu (%.2f%%) 429=%llu errors=%llu\n",
                (unsigned long long)s->sent,
                (unsigned long long)s->allowed, pass,
                (unsigned long long)s->limited,
                (unsigned long long)s->errors);
        if (s->lat_n) {
            fprintf(stderr, "latency ms  p50=%lld p90=%lld p95=%lld "
                    "p99=%lld max=%lld\n",
                    (long long)percentile((stats_t *)s, 0.50),
                    (long long)percentile((stats_t *)s, 0.90),
                    (long long)percentile((stats_t *)s, 0.95),
                    (long long)percentile((stats_t *)s, 0.99),
                    (long long)percentile((stats_t *)s, 1.00));
        }
        fprintf(stderr, "status codes:");
        for (int i = 100; i < 600; i++)
            if (s->status[i]) fprintf(stderr, " %d:%llu", i,
                                      (unsigned long long)s->status[i]);
        fputc('\n', stderr);
    }
}

static void print_json(const runner_t *r) {
    const stats_t *s[2] = {&r->benign, &r->attack};
    const char *nm[2] = {"benign", "attack"};
    printf("{\n  \"duration_ms\": %lld,\n  \"groups\": [\n",
           (long long)r->duration_ms);
    for (int g = 0; g < 2; g++) {
        double pass = s[g]->sent
            ? 100.0 * (double)s[g]->allowed / (double)s[g]->sent : 0;
        printf("    {\"group\":\"%s\",\"sent\":%llu,\"allowed\":%llu,"
               "\"pass_rate_pct\":%.3f,\"limited_429\":%llu,\"errors\":%llu,"
               "\"p50_ms\":%lld,\"p90_ms\":%lld,\"p95_ms\":%lld,"
               "\"p99_ms\":%lld,\"max_ms\":%lld}%s\n",
               nm[g],
               (unsigned long long)s[g]->sent,
               (unsigned long long)s[g]->allowed, pass,
               (unsigned long long)s[g]->limited,
               (unsigned long long)s[g]->errors,
               (long long)percentile((stats_t *)s[g], 0.50),
               (long long)percentile((stats_t *)s[g], 0.90),
               (long long)percentile((stats_t *)s[g], 0.95),
               (long long)percentile((stats_t *)s[g], 0.99),
               (long long)percentile((stats_t *)s[g], 1.00),
               g == 0 ? "," : "");
    }
    printf("  ]\n}\n");
}

static void usage(const char *prog) {
    fprintf(stderr,
      "usage: %s -t host:port -m model.conf -M burst|slow|mix|replay \\\n"
      "          [-d seconds] [-c concurrency] [-r rps] [-j]\n"
      "          [--attack N] [--benign N] [--drip-ms N] [--hold-ms N]\n",
      prog);
}

int main(int argc, char **argv) {
    runner_t r;
    memset(&r, 0, sizeof(r));
    snprintf(r.host, sizeof(r.host), "127.0.0.1");
    r.port = 8080;
    const char *model_path = NULL;
    const char *mode_s = "burst";
    int duration_s = 15;
    r.concurrency = 2000;
    r.rps = 100;
    r.n_attack = 500;
    r.n_benign = 50;
    r.slow_drip_interval_ms = 1000;
    r.slow_hold_ms = 12000;
    int json = 0;

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        #define NEED() (i + 1 < argc ? argv[++i] : NULL)
        if (!strcmp(a, "-t")) {
            const char *v = NEED(); if (!v) goto bad;
            char *c = strrchr(v, ':');
            if (!c) goto bad;
            snprintf(r.host, sizeof(r.host), "%.*s", (int)(c - v), v);
            r.port = atoi(c + 1);
        } else if (!strcmp(a, "-m")) { model_path = NEED(); }
        else if (!strcmp(a, "-M")) { mode_s = NEED(); }
        else if (!strcmp(a, "-d")) { duration_s = atoi(NEED()); }
        else if (!strcmp(a, "-c")) { r.concurrency = atoi(NEED()); }
        else if (!strcmp(a, "-r")) { r.rps = atoi(NEED()); }
        else if (!strcmp(a, "--attack")) { r.n_attack = atoi(NEED()); }
        else if (!strcmp(a, "--benign")) { r.n_benign = atoi(NEED()); }
        else if (!strcmp(a, "--drip-ms")) { r.slow_drip_interval_ms = atoi(NEED()); }
        else if (!strcmp(a, "--hold-ms")) { r.slow_hold_ms = atoi(NEED()); }
        else if (!strcmp(a, "-j")) { json = 1; }
        else if (!strcmp(a, "-h")) { usage(argv[0]); return 0; }
        else goto bad;
        #undef NEED
    }
    if (!model_path) goto bad;
    if (!strcmp(mode_s, "burst")) r.mode = 0;
    else if (!strcmp(mode_s, "slow")) r.mode = 1;
    else if (!strcmp(mode_s, "mix")) r.mode = 2;
    else if (!strcmp(mode_s, "replay")) r.mode = 3;
    else goto bad;

    char err[256];
    if (model_load(model_path, &r.model, err, sizeof(err)) < 0) {
        fprintf(stderr, "%s\n", err);
        return 1;
    }
    signal(SIGPIPE, SIG_IGN);
    r.el = el_create();
    if (!r.el) { perror("el_create"); return 1; }
    g_runner = &r;
    r.duration_ms = (int64_t)duration_s * 1000;
    r.end_at_ms = el_now(r.el) + r.duration_ms;
    r.hard_stop_ms = r.end_at_ms + 3000;
    r.request_timeout_ms = r.mode == 1 ? r.slow_hold_ms + 2000 : 10000;
    r.last_tick_ms = el_now(r.el);
    r.tick_timer = el_timer_add(r.el, 50, runner_tick, &r);
    el_run(r.el);

    if (json) print_json(&r);
    else {
        print_stats("benign / baseline", &r.benign, 0);
        print_stats("attack", &r.attack, 0);
    }
    for (int i = 0; i < r.active_n; i++) vc_destroy(r.active[i]);
    free(r.active);
    free(r.benign.lat_ms);
    free(r.attack.lat_ms);
    el_destroy(r.el);
    return 0;
bad:
    usage(argv[0]);
    return 2;
}
