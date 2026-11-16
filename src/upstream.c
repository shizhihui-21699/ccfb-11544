#include "proxy_internal.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

/* ===================================================================
 * Data flow
 *   client --read--> cbuf --copy--> reqbuf --write--> upstream
 *   upstream --read--> respbuf --write--> client
 *
 * Every request uses one fresh upstream connection (Connection: close
 * to the upstream). The client leg is also closed after the response,
 * which keeps the state machine exact under pipelining; keep-alive
 * reuse lives behind the same states and can be enabled later without
 * touching the rate-limit or event-loop layers.
 * =================================================================== */

struct up_state {
    enum { RESP_WAIT_HEAD, RESP_BODY, RESP_DONE } phase;
    http_resp_t resp;
    long long   remaining;
    int         chunked;
};

/* ---------------- request head rewriting ---------------- */

static int hop_by_hop(const http_header_t *h) {
    static const char *hops[] = {
        "connection", "proxy-connection", "keep-alive",
        "transfer-encoding", "te", "upgrade", NULL
    };
    for (int i = 0; hops[i]; i++)
        if (ci_equals(h->name, h->nlen, hops[i])) return 1;
    return 0;
}

static int build_upstream_head(conn_t *c) {
    sbuf_t *out = &c->reqbuf;
    http_req_t *r = &c->req;
    if (buf_printf(&out->data, &out->len, &out->cap,
                   "%.*s %.*s HTTP/1.1\r\n",
                   (int)r->mlen, r->method,
                   (int)r->tlen, r->target) < 0)
        return -1;

    int saw_host = 0;
    for (int i = 0; i < r->nheaders; i++) {
        http_header_t *h = &r->headers[i];
        if (hop_by_hop(h)) continue;
        if (ci_equals(h->name, h->nlen, "host")) saw_host = 1;
        if (buf_printf(&out->data, &out->len, &out->cap,
                       "%.*s: %.*s\r\n",
                       (int)h->nlen, h->name,
                       (int)h->vlen, h->val) < 0)
            return -1;
    }
    if (!saw_host &&
        buf_printf(&out->data, &out->len, &out->cap,
                   "Host: %s:%d\r\n",
                   c->px->cfg.upstream_host,
                   c->px->cfg.upstream_port) < 0)
        return -1;
    if (buf_printf(&out->data, &out->len, &out->cap,
                   "X-Forwarded-For: %s\r\n"
                   "Connection: close\r\n\r\n",
                   c->peer_ip) < 0)
        return -1;
    return 0;
}

/* ---------------- connect ---------------- */

int up_connect(conn_t *c) {
    int fd = connect_tcp_nb(c->px->cfg.upstream_host,
                            c->px->cfg.upstream_port);
    if (fd < 0) return -1;
    c->ufd = fd;
    if (build_upstream_head(c) < 0) goto fail;
    if (el_watch(c->px->el, fd, EL_WRITE, up_writable_cb, c) < 0)
        goto fail;
    conn_kick_timer(c, UP_CONNECT_TIMEOUT_MS);
    return 0;
fail:
    close(fd);
    c->ufd = -1;
    return -1;
}

static int socket_connected(int fd) {
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) return -1;
    if (err != 0) { errno = err; return -1; }
    return 0;
}

/* ---------------- pumping ---------------- */

/* Move newly arrived client body bytes into the upstream staging
 * buffer. Returns 0 on success, -1 on hard error. */
static int stage_request_body(conn_t *c) {
    sbuf_t *in = &c->cbuf;
    sbuf_t *out = &c->reqbuf;
    size_t avail = sbuf_buffered(in);
    if (avail == 0) return 0;
    if (sbuf_reserve(out, avail) < 0) return -1;
    memcpy(out->data + out->len, in->data + in->rd, avail);
    out->len += avail;
    in->rd += avail; /* cbuf fully drained; rd==len collapses to 0 */
    if (c->body_remaining > 0) {
        c->body_remaining -= (long long)avail;
        if (c->body_remaining < 0) c->body_remaining = 0;
    }
    return 0;
}

static int flush_reqbuf(conn_t *c) {
    sbuf_t *b = &c->reqbuf;
    while (sbuf_buffered(b) > 0) {
        ssize_t w = sbuf_write_fd(b, c->ufd);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
            return -1;
        }
        if (w == 0) break;
    }
    return 0;
}

static int flush_respbuf(conn_t *c) {
    sbuf_t *b = &c->respbuf;
    while (sbuf_buffered(b) > 0) {
        ssize_t w = sbuf_write_fd(b, c->cfd);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return 1;
            return -1;
        }
        if (w == 0) break;
    }
    return 0;
}

/* Recompute interest masks from actual buffer pressure. Called after
 * every IO batch so neither leg spins on a level-triggered fd. */
static void update_interests(conn_t *c) {
    if (c->ufd >= 0) {
        int up_ev = 0;
        if (sbuf_buffered(&c->reqbuf) > 0) up_ev |= EL_WRITE;
        if (sbuf_buffered(&c->respbuf) < BODY_HARD_CAP) up_ev |= EL_READ;
        if (up_ev == 0) up_ev = EL_READ;
        el_watch(c->px->el, c->ufd, up_ev,
                 (up_ev & EL_WRITE) ? up_writable_cb : up_readable_cb, c);
    }

    int cl_ev = EL_READ; /* always interested in more client data */
    if (sbuf_buffered(&c->respbuf) > 0) cl_ev |= EL_WRITE;
    if (c->up_eof) cl_ev = EL_WRITE; /* half-closed upstream: drain only */
    el_watch(c->px->el, c->cfd, cl_ev,
             (cl_ev & EL_WRITE) ? client_writable : client_readable, c);
}

/* ---------------- callbacks ---------------- */

void up_writable_cb(event_loop_t *el, int fd, int events, void *arg) {
    (void)el; (void)fd; (void)events;
    conn_t *c = arg;

    if (c->state == CS_UP_PENDING) {
        if (socket_connected(fd) < 0) {
            log_dbg("upstream connect failed: %s", strerror(errno));
            send_simple_error(c, 502, 0);
            return;
        }
        c->state = CS_RELAY;
    }
    conn_kick_timer(c, c->px->cfg.idle_timeout_ms);

    if (stage_request_body(c) < 0) { send_simple_error(c, 502, 0); return; }
    int rc = flush_reqbuf(c);
    if (rc < 0) { send_simple_error(c, 502, 0); return; }
    update_interests(c);
}

void up_readable_cb(event_loop_t *el, int fd, int events, void *arg) {
    (void)el; (void)fd; (void)events;
    conn_t *c = arg;
    conn_kick_timer(c, c->px->cfg.idle_timeout_ms);

    for (;;) {
        ssize_t n = sbuf_read_fd(&c->respbuf, c->ufd, BODY_HARD_CAP);
        if (n == 0) {
            /* Upstream finished. Stop reading it, keep flushing whatever
             * remains toward the client; close only once the response
             * buffer is fully drained (client may be backpressured). */
            c->up_eof = 1;
            el_unwatch(c->px->el, c->ufd);
            close(c->ufd);
            c->ufd = -1;
            if (flush_respbuf(c) < 0) { conn_close(c); return; }
            if (sbuf_buffered(&c->respbuf) == 0) { conn_close(c); return; }
            el_watch(c->px->el, c->cfd, EL_WRITE, client_writable, c);
            return;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (n == -2) { send_simple_error(c, 502, 0); return; }
            send_simple_error(c, 502, 0);
            return;
        }
        if (!c->up_state) {
            c->up_state = calloc(1, sizeof(up_state_t));
            if (!c->up_state) { send_simple_error(c, 502, 0); return; }
            c->up_state->phase = RESP_WAIT_HEAD;
        }
        up_state_t *us = c->up_state;
        if (us->phase == RESP_WAIT_HEAD) {
            hp_status_t st = http_parse_response(
                c->respbuf.data + c->respbuf.rd,
                sbuf_buffered(&c->respbuf), &us->resp);
            if (st == HP_NEED_MORE) continue;
            if (st != HP_OK) { send_simple_error(c, 502, 0); return; }
            us->remaining = us->resp.content_length;
            us->chunked = us->resp.chunked;
            us->phase = (us->remaining == 0 && !us->chunked)
                        ? RESP_DONE : RESP_BODY;
        }
    }

    if (flush_respbuf(c) < 0) { conn_close(c); return; }
    update_interests(c);
}

/* Called from the client-side callbacks to drive the relay directly,
 * avoiding an extra event-loop round trip for body bytes. */
void up_relay(conn_t *c, int events) {
    if (c->ufd < 0) return;
    if (stage_request_body(c) < 0) {
        send_simple_error(c, 502, 0);
        return;
    }
    if (events & EL_WRITE) {
        if (flush_reqbuf(c) < 0) { send_simple_error(c, 502, 0); return; }
    }
    update_interests(c);
}
