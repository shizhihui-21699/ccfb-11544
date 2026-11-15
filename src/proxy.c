#include "proxy.h"

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
#include "config.h"
#include "evloop.h"
#include "http.h"
#include "limiter.h"

#define HIGH_WATER (256 * 1024)  /* per-connection write-buffer backpressure */
#define MAX_HDR    (64 * 1024)   /* max header block we will parse */
#define READ_CHUNK 65536

/* client states */
enum { CS_HDR, CS_BODY, CS_DISCARD, CS_WAIT };
/* upstream states */
enum { RS_IDLE, RS_HDR, RS_BODY_LEN, RS_BODY_CHUNK, RS_BODY_EOF };

typedef struct conn conn_t;
struct conn {
    int       fd;
    int       is_upstream;
    conn_t   *peer;
    buf_t     in, out;
    uint32_t  mask;
    uint64_t  last_active;
    uint64_t  hdr_deadline;
    int       cstate;
    int       connecting;
    int       close_after_drain;
    int       close_me;         /* upstream: close once response fully relayed */
    http_req_t req;
    long      body_left;
    long      resp_left;
    int       resp_close;
    chunk_parser_t chunk;
    char      ip[64];
    conn_t   *next;
};

typedef struct {
    char    prefix[256];
    layer_t layer;
} rlayer_t;

typedef struct {
    evloop_t *loop;
    config_t  cfg;
    char      conf_path[512];
    int       listen_fd;
    layer_t   ip_layer, token_layer;
    rlayer_t  routes[MAX_ROUTES];
    int       nroutes;
    conn_t   *conns;
    size_t    nconns;
    struct sockaddr_storage up_addr;
    socklen_t up_addrlen;
    uint64_t  n_allowed, n_denied;
    uint64_t  last_stat_ms, stat_allowed, stat_denied;
    uint64_t  last_sweep_ms;
    volatile sig_atomic_t reload_flag, quit_flag;
} server_t;

static server_t G;

static void on_client(void *ud, uint32_t ev);
static void on_upstream(void *ud, uint32_t ev);
static void on_listen(void *ud, uint32_t ev);

/* ------------------------------------------------------------------ */

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0) return -1;
    return fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void conn_free(conn_t *c)
{
    ev_del(G.loop, c->fd);
    close(c->fd);
    /* unlink */
    conn_t **pp = &G.conns;
    while (*pp && *pp != c) pp = &(*pp)->next;
    if (*pp) *pp = c->next;
    G.nconns--;
    buf_free(&c->in);
    buf_free(&c->out);
    free(c);
}

static void close_pair(conn_t *c)
{
    conn_t *p = c->peer;
    if (p) p->peer = NULL;
    conn_free(c);
    if (p) conn_free(p);
}

static void maybe_close(conn_t *c)
{
    if (c->close_after_drain && c->out.len == 0) close_pair(c);
}

static void update_events(conn_t *c)
{
    uint32_t want = 0;
    if (c->is_upstream) {
        if (c->connecting) {
            want = EV_WRITE;
        } else {
            if (c->out.len) want |= EV_WRITE;
            if (c->cstate != RS_IDLE && c->peer && c->peer->out.len < HIGH_WATER)
                want |= EV_READ;
        }
    } else {
        if (c->out.len) want |= EV_WRITE;
        int can_read = 0;
        switch (c->cstate) {
        case CS_HDR:
        case CS_BODY:
            can_read = !c->peer || c->peer->out.len < HIGH_WATER;
            break;
        case CS_DISCARD:
            can_read = 1;
            break;
        default:
            break;
        }
        if (can_read) want |= EV_READ;
    }
    if (want != c->mask) {
        ev_mod(G.loop, c->fd, want);
        c->mask = want;
    }
}

static int do_write(conn_t *c)
{
    while (c->out.len > 0) {
        ssize_t n = write(c->fd, c->out.p, c->out.len);
        if (n > 0) {
            buf_consume(&c->out, (size_t)n);
            c->last_active = now_ms();
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        if (n < 0 && errno == EINTR) continue;
        return -1;
    }
    return 0;
}

static conn_t *conn_new(int fd, int is_upstream)
{
    conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd;
    c->is_upstream = is_upstream;
    c->last_active = now_ms();
    c->cstate = is_upstream ? RS_IDLE : CS_HDR;
    c->next = G.conns;
    G.conns = c;
    G.nconns++;
    return c;
}

/* ------------------------------------------------------------------ */
/* responses generated locally                                          */

static void send_simple(conn_t *c, int code, const char *reason, const char *msg)
{
    char body[256];
    int blen = snprintf(body, sizeof(body), "{\"error\":\"%s\"}\n", msg);
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: %s\r\n\r\n",
        code, reason, blen, c->close_after_drain ? "close" : "keep-alive");
    buf_put(&c->out, hdr, (size_t)n);
    buf_put(&c->out, body, (size_t)blen);
}

static void send_429(conn_t *c, const char *layer, uint64_t retry_ms)
{
    unsigned ra = (unsigned)((retry_ms + 999) / 1000);
    if (ra == 0) ra = 1;
    char body[192];
    int blen = snprintf(body, sizeof(body),
        "{\"error\":\"rate_limited\",\"layer\":\"%s\",\"retry_after\":%u}\n",
        layer, ra);
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 429 Too Many Requests\r\n"
        "Content-Type: application/json\r\n"
        "Retry-After: %u\r\n"
        "X-RateLimit-Layer: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: %s\r\n\r\n",
        ra, layer, blen, c->close_after_drain ? "close" : "keep-alive");
    buf_put(&c->out, hdr, (size_t)n);
    buf_put(&c->out, body, (size_t)blen);
}

/* ------------------------------------------------------------------ */
/* upstream connection management                                       */

static int ensure_upstream(conn_t *c)
{
    int fd = socket(G.up_addr.ss_family, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    set_nonblock(fd);
    int r = connect(fd, (struct sockaddr *)&G.up_addr, G.up_addrlen);
    if (r < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    conn_t *u = conn_new(fd, 1);
    if (!u) { close(fd); return -1; }
    u->peer = c;
    c->peer = u;
    u->connecting = 1;
    u->cstate = RS_IDLE;
    ev_add(G.loop, fd, EV_WRITE, on_upstream, u);
    u->mask = EV_WRITE;
    return 0;
}

static void drop_upstream(conn_t *u)
{
    conn_t *c = u->peer;
    if (c) c->peer = NULL;
    conn_free(u);
    if (c) {
        update_events(c);
        maybe_close(c);
    }
}

/* ------------------------------------------------------------------ */
/* request handling / rate limiting                                     */

static int match_route(const char *path)
{
    int best = -1;
    size_t bestlen = 0;
    for (int i = 0; i < G.nroutes; i++) {
        size_t pl = strlen(G.routes[i].prefix);
        if (pl > bestlen && strncmp(path, G.routes[i].prefix, pl) == 0) {
            best = i;
            bestlen = pl;
        }
    }
    return best;
}

static void handle_request(conn_t *c)
{
    http_req_t *q = &c->req;
    uint64_t now = now_ms();
    uint64_t ra = 0;
    const char *lname = NULL;
    char key[320];

    if (G.cfg.ip_on) {
        snprintf(key, sizeof(key), "i:%s", c->ip);
        if (!layer_check(&G.ip_layer, key, now, &ra)) { lname = "ip"; goto denied; }
    }
    if (G.cfg.token_on && q->token[0]) {
        snprintf(key, sizeof(key), "t:%s", q->token);
        if (!layer_check(&G.token_layer, key, now, &ra)) { lname = "token"; goto denied; }
    }
    {
        int ri = match_route(q->path);
        if (ri >= 0) {
            snprintf(key, sizeof(key), "r:%s", G.routes[ri].prefix);
            if (!layer_check(&G.routes[ri].layer, key, now, &ra)) {
                lname = "route";
                goto denied;
            }
        }
    }

    G.n_allowed++;
    G.stat_allowed++;

    if (q->chunked) {
        buf_consume(&c->in, q->header_len);
        c->close_after_drain = 1;
        send_simple(c, 501, "Not Implemented", "chunked_request_unsupported");
        c->cstate = CS_WAIT;
        return;
    }

    if (!c->peer) {
        if (ensure_upstream(c) < 0) {
            buf_consume(&c->in, q->header_len);
            send_simple(c, 502, "Bad Gateway", "upstream_unavailable");
            c->body_left = q->content_length > 0 ? q->content_length : 0;
            c->cstate = c->body_left ? CS_DISCARD : CS_HDR;
            return;
        }
    }

    conn_t *u = c->peer;
    buf_put(&u->out, c->in.p, q->header_len);
    buf_consume(&c->in, q->header_len);
    u->cstate = RS_HDR;
    u->resp_close = 0;
    u->close_me = 0;
    chunk_init(&u->chunk);
    c->body_left = q->content_length > 0 ? q->content_length : 0;
    c->cstate = c->body_left ? CS_BODY : CS_WAIT;
    if (!q->keep_alive) c->close_after_drain = 1;
    return;

denied:
    G.n_denied++;
    G.stat_denied++;
    buf_consume(&c->in, q->header_len);
    if (q->chunked || !q->keep_alive) c->close_after_drain = 1;
    send_429(c, lname, ra);
    if (c->close_after_drain) {
        c->cstate = CS_WAIT;
    } else {
        c->body_left = q->content_length > 0 ? q->content_length : 0;
        c->cstate = c->body_left ? CS_DISCARD : CS_HDR;
    }
}

/* Consume buffered client input according to the client state machine. */
static void client_process(conn_t *c)
{
    for (;;) {
        if (c->cstate == CS_HDR) {
            if (c->in.len == 0) return;
            if (c->in.len > MAX_HDR) {
                c->close_after_drain = 1;
                send_simple(c, 431, "Request Header Fields Too Large", "headers_too_large");
                c->cstate = CS_WAIT;
                return;
            }
            int r = http_parse_request(c->in.p, c->in.len, &c->req);
            if (r == 0) return; /* need more */
            if (r < 0) {
                c->close_after_drain = 1;
                send_simple(c, 400, "Bad Request", "bad_request");
                c->cstate = CS_WAIT;
                return;
            }
            handle_request(c);
            if (c->cstate == CS_HDR) continue; /* local response, try pipelined next */
            return;
        } else if (c->cstate == CS_BODY) {
            if (!c->peer) { c->cstate = CS_WAIT; return; }
            size_t avail = c->in.len;
            size_t take = avail < (size_t)c->body_left ? avail : (size_t)c->body_left;
            if (take) {
                buf_put(&c->peer->out, c->in.p, take);
                buf_consume(&c->in, take);
                c->body_left -= (long)take;
            }
            if (c->body_left == 0) {
                c->cstate = CS_WAIT;
                return;
            }
            if (c->in.len == 0) return; /* need more body */
            /* else loop and keep draining */
        } else if (c->cstate == CS_DISCARD) {
            size_t avail = c->in.len;
            size_t take = avail < (size_t)c->body_left ? avail : (size_t)c->body_left;
            buf_consume(&c->in, take);
            c->body_left -= (long)take;
            if (c->body_left <= 0) {
                c->cstate = CS_HDR;
                continue;
            }
            return;
        } else {
            return; /* CS_WAIT */
        }
    }
}

/* ------------------------------------------------------------------ */
/* event handlers                                                       */

static void on_listen(void *ud, uint32_t ev)
{
    (void)ud; (void)ev;
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        int fd = accept(G.listen_fd, (struct sockaddr *)&ss, &sl);
        if (fd < 0) {
            if (errno == EINTR) continue;
            break; /* EAGAIN: no more pending */
        }
        set_nonblock(fd);
        if (G.nconns >= (size_t)G.cfg.max_conns) {
            static const char r503[] =
                "HTTP/1.1 503 Service Unavailable\r\n"
                "Content-Length: 13\r\nConnection: close\r\n\r\noverloaded\n";
            (void)write(fd, r503, sizeof(r503) - 1);
            close(fd);
            continue;
        }
        conn_t *c = conn_new(fd, 0);
        if (!c) { close(fd); continue; }
        if (ss.ss_family == AF_INET) {
            struct sockaddr_in *a = (struct sockaddr_in *)&ss;
            inet_ntop(AF_INET, &a->sin_addr, c->ip, sizeof(c->ip));
        } else if (ss.ss_family == AF_INET6) {
            struct sockaddr_in6 *a = (struct sockaddr_in6 *)&ss;
            inet_ntop(AF_INET6, &a->sin6_addr, c->ip, sizeof(c->ip));
        } else {
            snprintf(c->ip, sizeof(c->ip), "?");
        }
        ev_add(G.loop, fd, EV_READ, on_client, c);
        c->mask = EV_READ;
    }
}

static void on_client(void *ud, uint32_t ev)
{
    conn_t *c = ud;
    if ((ev & EV_WRITE) && do_write(c) < 0) { close_pair(c); return; }
    if (ev & EV_READ) {
        char tmp[READ_CHUNK];
        ssize_t n = read(c->fd, tmp, sizeof(tmp));
        if (n <= 0) { close_pair(c); return; }
        c->last_active = now_ms();
        if (c->cstate == CS_HDR && c->in.len == 0)
            c->hdr_deadline = c->last_active + (uint64_t)G.cfg.header_timeout_ms;
        if (buf_put(&c->in, tmp, (size_t)n) < 0) { close_pair(c); return; }
        client_process(c);
    }
    update_events(c);
    if (c->peer) update_events(c->peer);
    maybe_close(c);
}

static void finish_response(conn_t *u)
{
    conn_t *c = u->peer;
    u->cstate = RS_IDLE;
    u->in.len = 0;
    if (u->resp_close) u->close_me = 1;
    if (c) {
        if (c->close_after_drain || u->resp_close) {
            c->close_after_drain = 1;
            c->cstate = CS_WAIT;
        } else {
            c->cstate = CS_HDR;
            client_process(c); /* pipelined request may already be buffered */
        }
    }
}

/* Returns u if the connection is still open, NULL if it was closed. */
static conn_t *process_upstream(conn_t *u)
{
    conn_t *c = u->peer;
    if (!c) return u;
    while (u->in.len > 0) {
        if (u->cstate == RS_HDR) {
            if (u->in.len > MAX_HDR) { close_pair(u); return NULL; }
            http_resp_t resp;
            int r = http_parse_response(u->in.p, u->in.len, &resp);
            if (r == 0) return u;
            if (r < 0) { close_pair(u); return NULL; }
            buf_put(&c->out, u->in.p, resp.header_len);
            buf_consume(&u->in, resp.header_len);
            u->resp_close = !resp.keep_alive;
            if (resp.chunked) {
                u->cstate = RS_BODY_CHUNK;
                chunk_init(&u->chunk);
            } else if (resp.content_length > 0) {
                u->cstate = RS_BODY_LEN;
                u->resp_left = resp.content_length;
            } else if (resp.content_length == 0) {
                finish_response(u);
                return u;
            } else {
                u->cstate = RS_BODY_EOF;
            }
        } else if (u->cstate == RS_BODY_LEN) {
            size_t take = u->in.len < (size_t)u->resp_left ? u->in.len : (size_t)u->resp_left;
            buf_put(&c->out, u->in.p, take);
            buf_consume(&u->in, take);
            u->resp_left -= (long)take;
            if (u->resp_left == 0) {
                finish_response(u);
                return u;
            }
            if (u->in.len == 0) return u;
        } else if (u->cstate == RS_BODY_CHUNK) {
            int done = 0;
            size_t used = chunk_consume(&u->chunk, u->in.p, u->in.len, &done);
            if (used == (size_t)-1) { close_pair(u); return NULL; }
            buf_put(&c->out, u->in.p, used);
            buf_consume(&u->in, used);
            if (done) {
                finish_response(u);
                return u;
            }
            if (used == 0) return u;
        } else if (u->cstate == RS_BODY_EOF) {
            buf_put(&c->out, u->in.p, u->in.len);
            buf_consume(&u->in, u->in.len);
            return u;
        } else {
            return u; /* RS_IDLE: stray bytes, ignore */
        }
    }
    return u;
}

static void upstream_eof(conn_t *u)
{
    conn_t *c = u->peer;
    if (u->cstate == RS_BODY_EOF && c) {
        /* response was delimited by connection close */
        c->close_after_drain = 1;
        c->cstate = CS_WAIT;
        drop_upstream(u);
        return;
    }
    if (u->cstate == RS_IDLE && c) {
        /* upstream closed an idle keep-alive connection */
        drop_upstream(u);
        return;
    }
    close_pair(u); /* truncated response, or client already gone */
}

static void upstream_failed(conn_t *u)
{
    conn_t *c = u->peer;
    if (c && c->cstate == CS_WAIT) {
        send_simple(c, 502, "Bad Gateway", "upstream_connect_failed");
        c->cstate = CS_HDR;
    }
    drop_upstream(u);
    if (c) client_process(c);
}

static void on_upstream(void *ud, uint32_t ev)
{
    conn_t *u = ud;
    if (u->connecting) {
        int err = 0;
        socklen_t l = sizeof(err);
        if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &err, &l) < 0 || err) {
            upstream_failed(u);
            return;
        }
        u->connecting = 0;
    }
    if ((ev & EV_WRITE) && do_write(u) < 0) { close_pair(u); return; }
    if (ev & EV_READ) {
        char tmp[READ_CHUNK];
        ssize_t n = read(u->fd, tmp, sizeof(tmp));
        if (n <= 0) { upstream_eof(u); return; }
        u->last_active = now_ms();
        if (buf_put(&u->in, tmp, (size_t)n) < 0) { close_pair(u); return; }
        if (!process_upstream(u)) return; /* pair was closed */
    }
    update_events(u);
    if (u->close_me) { drop_upstream(u); return; }
    if (u->peer) {
        update_events(u->peer);
        maybe_close(u->peer);
    }
}

/* ------------------------------------------------------------------ */
/* config / listener                                                    */

static int parse_hostport(const char *spec, char *host, size_t hcap,
                          char *port, size_t pcap)
{
    const char *colon = strrchr(spec, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - spec);
    if (hl >= hcap) hl = hcap - 1;
    memcpy(host, spec, hl);
    host[hl] = '\0';
    snprintf(port, pcap, "%s", colon + 1);
    return 0;
}

static int resolve_upstream(const char *spec)
{
    char host[256], port[32];
    if (parse_hostport(spec, host, sizeof(host), port, sizeof(port)) < 0) return -1;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host[0] ? host : "127.0.0.1", port, &hints, &res) != 0 || !res)
        return -1;
    memcpy(&G.up_addr, res->ai_addr, res->ai_addrlen);
    G.up_addrlen = (socklen_t)res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

static int open_listener(const char *spec)
{
    char host[256], port[32];
    if (parse_hostport(spec, host, sizeof(host), port, sizeof(port)) < 0) return -1;
    struct addrinfo hints, *res = NULL, *ai;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    const char *h = (host[0] && strcmp(host, "*") != 0) ? host : NULL;
    if (getaddrinfo(h, port, &hints, &res) != 0) return -1;
    int fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 && listen(fd, 1024) == 0)
            break;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd >= 0) set_nonblock(fd);
    return fd;
}

static void apply_limits(config_t *nc)
{
    layer_set_params(&G.ip_layer, &nc->ip);
    layer_set_params(&G.token_layer, &nc->token);

    /* sync route layers, preserving state for prefixes that survive */
    rlayer_t nr[MAX_ROUTES];
    int nn = 0;
    for (int i = 0; i < nc->nroutes && nn < MAX_ROUTES; i++) {
        int found = -1;
        for (int j = 0; j < G.nroutes; j++)
            if (strcmp(G.routes[j].prefix, nc->routes[i].prefix) == 0) { found = j; break; }
        if (found >= 0) {
            nr[nn] = G.routes[found];
            layer_set_params(&nr[nn].layer, &nc->routes[i].p);
        } else {
            snprintf(nr[nn].prefix, sizeof(nr[nn].prefix), "%s", nc->routes[i].prefix);
            layer_init(&nr[nn].layer, nc->routes[i].prefix, &nc->routes[i].p);
        }
        nn++;
    }
    for (int j = 0; j < G.nroutes; j++) {
        int used = 0;
        for (int k = 0; k < nn; k++)
            if (strcmp(nr[k].prefix, G.routes[j].prefix) == 0) { used = 1; break; }
        if (!used) layer_free(&G.routes[j].layer);
    }
    memcpy(G.routes, nr, sizeof(nr));
    G.nroutes = nn;
}

static void do_reload(void)
{
    config_t nc;
    char err[256];
    if (config_load(G.conf_path, &nc, err, sizeof(err)) < 0) {
        fprintf(stderr, "[rlproxy] reload failed: %s (keeping old config)\n", err);
        return;
    }
    if (strcmp(nc.listen, G.cfg.listen) != 0) {
        int fd = open_listener(nc.listen);
        if (fd < 0) {
            fprintf(stderr, "[rlproxy] reload: cannot bind %s, keeping old listener\n",
                    nc.listen);
            memcpy(nc.listen, G.cfg.listen, sizeof(nc.listen));
        } else {
            ev_del(G.loop, G.listen_fd);
            close(G.listen_fd);
            G.listen_fd = fd;
            ev_add(G.loop, fd, EV_READ, on_listen, NULL);
            fprintf(stderr, "[rlproxy] listener moved to %s\n", nc.listen);
        }
    }
    if (strcmp(nc.upstream, G.cfg.upstream) != 0) {
        if (resolve_upstream(nc.upstream) < 0) {
            fprintf(stderr, "[rlproxy] reload: cannot resolve upstream %s, keeping old\n",
                    nc.upstream);
            memcpy(nc.upstream, G.cfg.upstream, sizeof(nc.upstream));
        } else {
            fprintf(stderr, "[rlproxy] upstream -> %s (new connections)\n", nc.upstream);
        }
    }
    apply_limits(&nc);
    G.cfg = nc;
    fprintf(stderr, "[rlproxy] config reloaded (ip:%s token:%s routes:%d)\n",
            nc.ip_on ? "on" : "off", nc.token_on ? "on" : "off", nc.nroutes);
}

/* ------------------------------------------------------------------ */
/* housekeeping                                                         */

static void housekeeping(void)
{
    uint64_t now = now_ms();

    if (G.reload_flag) {
        G.reload_flag = 0;
        do_reload();
    }

    conn_t *c = G.conns;
    while (c) {
        conn_t *next = c->next;
        if (!c->is_upstream) {
            if (c->cstate == CS_HDR && c->in.len > 0 && now > c->hdr_deadline) {
                /* slow-header (slowloris-style) connection: kill it */
                close_pair(c);
            } else if (now - c->last_active > (uint64_t)G.cfg.idle_timeout_ms) {
                close_pair(c);
            }
        } else {
            if (c->connecting && now - c->last_active > 10000) {
                close_pair(c);
            } else if (c->cstate == RS_IDLE &&
                       now - c->last_active > (uint64_t)G.cfg.idle_timeout_ms) {
                drop_upstream(c);
            }
        }
        c = next;
    }

    if (now - G.last_sweep_ms >= 30000) {
        G.last_sweep_ms = now;
        layer_sweep(&G.ip_layer, now);
        layer_sweep(&G.token_layer, now);
        for (int i = 0; i < G.nroutes; i++) layer_sweep(&G.routes[i].layer, now);
    }

    if (now - G.last_stat_ms >= 5000) {
        fprintf(stderr,
            "[rlproxy] conns=%zu allowed=%llu (+%llu/5s) denied=%llu (+%llu/5s) "
            "ip_keys=%zu token_keys=%zu\n",
            G.nconns,
            (unsigned long long)G.n_allowed, (unsigned long long)G.stat_allowed,
            (unsigned long long)G.n_denied, (unsigned long long)G.stat_denied,
            G.ip_layer.count, G.token_layer.count);
        G.stat_allowed = 0;
        G.stat_denied = 0;
        G.last_stat_ms = now;
    }
}

/* ------------------------------------------------------------------ */

static void on_sighup(int s)  { (void)s; G.reload_flag = 1; }
static void on_sigterm(int s) { (void)s; G.quit_flag = 1; }

int server_run(const char *conf_path)
{
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, on_sighup);
    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);

    snprintf(G.conf_path, sizeof(G.conf_path), "%s", conf_path);

    char err[256];
    if (config_load(conf_path, &G.cfg, err, sizeof(err)) < 0) {
        fprintf(stderr, "[rlproxy] config error: %s\n", err);
        return 1;
    }
    if (resolve_upstream(G.cfg.upstream) < 0) {
        fprintf(stderr, "[rlproxy] cannot resolve upstream %s\n", G.cfg.upstream);
        return 1;
    }

    G.loop = evloop_new();
    if (!G.loop) {
        fprintf(stderr, "[rlproxy] cannot create event loop\n");
        return 1;
    }

    layer_init(&G.ip_layer, "ip", &G.cfg.ip);
    layer_init(&G.token_layer, "token", &G.cfg.token);
    apply_limits(&G.cfg);

    G.listen_fd = open_listener(G.cfg.listen);
    if (G.listen_fd < 0) {
        fprintf(stderr, "[rlproxy] cannot bind %s\n", G.cfg.listen);
        return 1;
    }
    ev_add(G.loop, G.listen_fd, EV_READ, on_listen, NULL);

    G.last_stat_ms = now_ms();
    G.last_sweep_ms = now_ms();

    fprintf(stderr, "[rlproxy] listening on %s -> upstream %s (max_conns=%d)\n",
            G.cfg.listen, G.cfg.upstream, G.cfg.max_conns);
    fprintf(stderr, "[rlproxy] limits: ip=%s token=%s routes=%d  "
            "(SIGHUP to reload)\n",
            G.cfg.ip_on ? "on" : "off", G.cfg.token_on ? "on" : "off", G.cfg.nroutes);

    while (!G.quit_flag) {
        ev_wait(G.loop, 500);
        housekeeping();
    }

    fprintf(stderr, "[rlproxy] shutting down: allowed=%llu denied=%llu\n",
            (unsigned long long)G.n_allowed, (unsigned long long)G.n_denied);
    return 0;
}
