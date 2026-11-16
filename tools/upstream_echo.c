/* upstream_echo — event-driven test origin for rlproxy.
 *
 * One process, non-blocking, same event-loop abstraction as the proxy.
 * Handles thousands of concurrent connections so load tests measure the
 * proxy rather than fork() overhead. Delays are timer-driven.
 *
 * usage: upstream_echo [host:port] [delay_ms] [body_bytes]
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
#include <signal.h>
#include <sys/socket.h>

static int g_delay_ms = 0;
static int g_body_bytes = 128;

typedef struct {
    int      fd;
    sbuf_t   in;
    sbuf_t   out;
    http_req_t req;
    int      parsed;
    uint64_t timer;
} uconn_t;

static event_loop_t *g_el;

static void uc_close(uconn_t *c) {
    if (c->timer) el_timer_cancel(g_el, c->timer);
    el_unwatch(g_el, c->fd);
    close(c->fd);
    sbuf_free(&c->in);
    sbuf_free(&c->out);
    free(c);
}

static void uc_writable(event_loop_t *el, int fd, int events, void *arg);

static void build_response(uconn_t *c) {
    /* Dynamically sized so large-body tests exercise response relay. */
    int want = g_body_bytes > 64 ? g_body_bytes : 64;
    char *payload = malloc((size_t)want + 1);
    if (!payload) { uc_close(c); return; }
    int plen = snprintf(payload, (size_t)want,
        "{\"upstream\":\"ok\",\"method\":\"%.*s\",\"path\":\"%.*s\"",
        (int)c->req.mlen, c->req.method,
        (int)c->req.plen, c->req.path);
    const http_header_t *tok = http_find_header(&c->req, "x-user-token");
    if (tok && plen < want)
        plen += snprintf(payload + plen, (size_t)want + 1 - (size_t)plen,
                         ",\"token\":\"%.*s\"", (int)tok->vlen, tok->val);
    if (plen < want)
        plen += snprintf(payload + plen, (size_t)want + 1 - (size_t)plen, "}");
    while (plen < want)
        payload[plen++] = ' ';

    char head[512];
    int hn = snprintf(head, sizeof(head),
        "HTTP/1.1 200 OK\r\n"
        "Server: upstream_echo\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n\r\n", plen);
    if (sbuf_reserve(&c->out, (size_t)hn + (size_t)plen) < 0) {
        free(payload);
        uc_close(c);
        return;
    }
    memcpy(c->out.data + c->out.len, head, (size_t)hn);
    c->out.len += (size_t)hn;
    memcpy(c->out.data + c->out.len, payload, (size_t)plen);
    c->out.len += (size_t)plen;
    free(payload);
}

static void respond_now(uconn_t *c) {
    build_response(c);
    el_watch(g_el, c->fd, EL_WRITE, uc_writable, c);
}

static void delay_timer(event_loop_t *el, void *arg) {
    (void)el;
    uconn_t *c = arg;
    c->timer = 0;
    respond_now(c);
}

static void uc_readable(event_loop_t *el, int fd, int events, void *arg) {
    (void)el; (void)fd; (void)events;
    uconn_t *c = arg;
    for (;;) {
        ssize_t n = sbuf_read_fd(&c->in, c->fd, 1024 * 1024);
        if (n == 0) { uc_close(c); return; }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            uc_close(c);
            return;
        }
        if (!c->parsed) {
            hp_status_t st = http_parse_request(
                c->in.data + c->in.rd, sbuf_buffered(&c->in), &c->req);
            if (st == HP_NEED_MORE) continue;
            if (st != HP_OK) {
                static const char bad[] =
                    "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n"
                    "Connection: close\r\n\r\n";
                sbuf_reset(&c->out);
                if (sbuf_reserve(&c->out, sizeof(bad) - 1) == 0) {
                    memcpy(c->out.data, bad, sizeof(bad) - 1);
                    c->out.len = sizeof(bad) - 1;
                }
                el_watch(g_el, c->fd, EL_WRITE, uc_writable, c);
                return;
            }
            c->parsed = 1;
            if (g_delay_ms > 0)
                c->timer = el_timer_add(el, g_delay_ms, delay_timer, c);
            else
                respond_now(c);
            return;
        }
    }
}

static void uc_writable(event_loop_t *el, int fd, int events, void *arg) {
    (void)el; (void)fd; (void)events;
    uconn_t *c = arg;
    while (sbuf_buffered(&c->out) > 0) {
        ssize_t w = sbuf_write_fd(&c->out, c->fd);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            uc_close(c);
            return;
        }
        if (w == 0) break;
    }
    if (sbuf_buffered(&c->out) == 0) uc_close(c);
}

static void listen_cb(event_loop_t *el, int lfd, int ev, void *arg) {
    (void)el; (void)ev; (void)arg;
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cfd = accept(lfd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            if (errno == EMFILE || errno == ENFILE) return;
            log_err("accept: %s", strerror(errno));
            return;
        }
        if (set_nonblock(cfd) < 0 || set_cloexec(cfd) < 0) { close(cfd); continue; }
        uconn_t *c = calloc(1, sizeof(*c));
        if (!c) { close(cfd); continue; }
        c->fd = cfd;
        sbuf_init(&c->in);
        sbuf_init(&c->out);
        if (el_watch(el, cfd, EL_READ, uc_readable, c) < 0) {
            close(cfd);
            free(c);
            continue;
        }
    }
}

int main(int argc, char **argv) {
    const char *addr = argc > 1 ? argv[1] : "127.0.0.1:9000";
    g_delay_ms = argc > 2 ? atoi(argv[2]) : 0;
    g_body_bytes = argc > 3 ? atoi(argv[3]) : 128;

    char hostbuf[128];
    snprintf(hostbuf, sizeof(hostbuf), "%s", addr);
    char *colon = strrchr(hostbuf, ':');
    if (!colon) { fprintf(stderr, "bad address %s\n", addr); return 2; }
    *colon = '\0';
    int port = atoi(colon + 1);

    signal(SIGPIPE, SIG_IGN);
    g_el = el_create();
    if (!g_el) { perror("el_create"); return 1; }
    int lfd = listen_tcp(hostbuf, port, 16384);
    if (lfd < 0) { perror("listen"); return 1; }
    if (el_watch(g_el, lfd, EL_READ, listen_cb, NULL) < 0) {
        perror("watch");
        return 1;
    }
    fprintf(stderr, "upstream_echo (event loop) on %s:%d delay=%dms body=%d\n",
            hostbuf, port, g_delay_ms, g_body_bytes);
    el_run(g_el);
    el_destroy(g_el);
    return 0;
}
