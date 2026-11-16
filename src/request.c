#include "proxy_internal.h"
#include "hashmap_internal.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* ---------------- timers ---------------- */

static void conn_idle_timer(event_loop_t *el, void *arg) {
    (void)el;
    conn_t *c = arg;
    c->idle_timer = 0;
    log_dbg("idle/head timeout fd=%d state=%d", c->cfd, c->state);
    if (c->state == CS_READ_HEAD)
        send_simple_error(c, 408, 0);
    else
        conn_close(c);
}

void conn_kick_timer(conn_t *c, int timeout_ms) {
    if (c->idle_timer) el_timer_cancel(c->px->el, c->idle_timer);
    c->idle_timer = el_timer_add(c->px->el, timeout_ms,
                                 conn_idle_timer, c);
}

/* ---------------- helpers ---------------- */

static void get_peer_ip(conn_t *c) {
    struct sockaddr_storage ss;
    socklen_t slen = sizeof(ss);
    if (getpeername(c->cfd, (struct sockaddr *)&ss, &slen) < 0) {
        snprintf(c->peer_ip, sizeof(c->peer_ip), "unknown");
        return;
    }
    if (ss.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&ss;
        inet_ntop(AF_INET, &s->sin_addr, c->peer_ip, sizeof(c->peer_ip));
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
        inet_ntop(AF_INET6, &s->sin6_addr, c->peer_ip, sizeof(c->peer_ip));
    }
}

static void extract_client_ip(conn_t *c, const http_req_t *r,
                              char *out, size_t outlen) {
    snprintf(out, outlen, "%s", c->peer_ip);
    if (!c->px->cfg.trust_xff) return;
    const http_header_t *h = http_find_header(r, "x-forwarded-for");
    if (!h || h->vlen == 0) return;
    size_t end = 0;
    while (end < h->vlen && h->val[end] != ',') end++;
    size_t start = 0;
    while (start < end && (h->val[start] == ' ' || h->val[start] == '\t'))
        start++;
    size_t n = end - start;
    if (n >= outlen) n = outlen - 1;
    memcpy(out, h->val + start, n);
    out[n] = '\0';
}

void send_simple_error(conn_t *c, int status, long long retry_after) {
    if (c->state == CS_CLOSING) return;
    sbuf_reset(&c->errbuf);
    const char *body;
    switch (status) {
        case 429: body = "{\"error\":\"rate_limited\"}"; break;
        case 503: body = "{\"error\":\"overloaded\"}"; break;
        case 408: body = "{\"error\":\"timeout\"}"; break;
        case 413: body = "{\"error\":\"payload_too_large\"}"; break;
        default:  body = "{\"error\":\"bad_gateway\"}"; break;
    }
    size_t bodylen = strlen(body);
    char ra[64] = "";
    if (retry_after > 0)
        snprintf(ra, sizeof(ra), "Retry-After: %lld\r\n", retry_after);

    char head[640];
    int hn = snprintf(head, sizeof(head),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %zu\r\n"
        "%s"
        "Connection: close\r\n"
        "\r\n",
        status, http_reason(status), bodylen, ra);
    if (hn < 0 || sbuf_reserve(&c->errbuf, (size_t)hn + bodylen) < 0) {
        conn_close(c);
        return;
    }
    memcpy(c->errbuf.data, head, (size_t)hn);
    c->errbuf.len = (size_t)hn;
    memcpy(c->errbuf.data + c->errbuf.len, body, bodylen);
    c->errbuf.len += bodylen;

    c->state = CS_SEND_ERROR;
    if (c->ufd >= 0) {
        el_unwatch(c->px->el, c->ufd);
        close(c->ufd);
        c->ufd = -1;
    }
    el_watch(c->px->el, c->cfd, EL_WRITE, client_writable, c);
}

/* ---------------- layered rate limiting ---------------- */

static int evaluate_limits(conn_t *c, const http_req_t *r,
                           long long *retry_after_out) {
    char ipkey[128], tokenkey[256], routekey[320];
    proxy_t *p = c->px;

    for (int i = 0; i < p->cfg.nzones; i++) {
        zone_cfg_t *zc = &p->cfg.zones[i];
        rl_zone_t *z = hm_get(p->zones, zc->name);
        if (!z) continue;

        const char *key = NULL;
        if (zc->type == ZT_IP) {
            extract_client_ip(c, r, ipkey, sizeof(ipkey));
            key = ipkey;
        } else if (zc->type == ZT_TOKEN) {
            const http_header_t *h =
                http_find_header(r, p->cfg.token_header);
            if (h && h->vlen > 0 && h->vlen < 200)
                snprintf(tokenkey, sizeof(tokenkey), "%.*s",
                         (int)h->vlen, h->val);
            else
                snprintf(tokenkey, sizeof(tokenkey), "anon");
            key = tokenkey;
        } else {
            size_t mlen = strlen(zc->match);
            if (mlen == 0 ||
                (r->plen >= mlen && strncmp(r->path, zc->match, mlen) == 0)) {
                snprintf(routekey, sizeof(routekey), "%.*s",
                         (int)r->plen, r->path);
                key = routekey;
            }
        }
        if (!key || key[0] == '\0') continue;

        rl_decision_t d = rl_zone_check(z, key, el_now(p->el));
        if (!d.allowed) {
            *retry_after_out = d.retry_after_s;
            log_dbg("deny zone=%s key=%s ra=%lld", zc->name, key,
                    d.retry_after_s);
            return -1;
        }
    }
    return 0;
}

/* ---------------- request head ---------------- */

static void begin_upstream(conn_t *c) {
    c->state = CS_UP_PENDING;
    if (up_connect(c) < 0) send_simple_error(c, 502, 0);
}

static void on_request_head(conn_t *c) {
    hp_status_t st = http_parse_request(c->cbuf.data + c->cbuf.rd,
                                        sbuf_buffered(&c->cbuf), &c->req);
    if (st == HP_NEED_MORE) return;
    if (st != HP_OK) {
        log_dbg("bad request fd=%d status=%d", c->cfd, st);
        send_simple_error(c, 400, 0);
        return;
    }
    c->req_valid = 1;
    c->keep_alive = c->req.keep_alive;
    c->chunked_req = c->req.chunked;
    c->body_remaining = c->req.content_length > 0 ? c->req.content_length : 0;

    c->px->total_requests++;
    long long retry_after = 0;
    if (evaluate_limits(c, &c->req, &retry_after) < 0) {
        c->px->total_denied++;
        /* A denied request with a body: stop reading further from the
         * client and answer 429; the connection is closed afterwards. */
        send_simple_error(c, 429, retry_after);
        return;
    }

    sbuf_consume(&c->cbuf, c->req.head_len);
    begin_upstream(c);
}

/* ---------------- client IO callbacks ---------------- */

void client_readable(event_loop_t *el, int fd, int events, void *arg) {
    (void)el; (void)fd; (void)events;
    conn_t *c = arg;
    conn_kick_timer(c, c->state == CS_READ_HEAD
                      ? c->px->cfg.head_timeout_ms
                      : c->px->cfg.idle_timeout_ms);

    for (;;) {
        ssize_t n = sbuf_read_fd(&c->cbuf, c->cfd, BODY_HARD_CAP);
        if (n == 0) {
            if (c->state == CS_READ_HEAD) { conn_close(c); return; }
            /* Half-close: stop reading; relay/response logic decides
             * when the upstream leg ends. */
            el_watch(c->px->el, c->cfd, EL_WRITE, client_writable, c);
            return;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            if (n == -2) { send_simple_error(c, 413, 0); return; }
            conn_close(c);
            return;
        }

        switch (c->state) {
        case CS_READ_HEAD:
            on_request_head(c);
            break;
        case CS_UP_PENDING:
        case CS_RELAY:
            up_relay(c, EL_READ);
            if (c->state == CS_CLOSING) return;
            break;
        case CS_DRAIN_CLOSE:
        case CS_SEND_ERROR:
            /* Ignore further client input while an error response is
             * being flushed; the socket closes right after. */
            break;
        default:
            break;
        }
        if (c->state == CS_CLOSING) return;
    }
}

void client_writable(event_loop_t *el, int fd, int events, void *arg) {
    (void)el; (void)fd; (void)events;
    conn_t *c = arg;

    if (c->state == CS_SEND_ERROR) {
        sbuf_t *b = &c->errbuf;
        while (sbuf_buffered(b) > 0) {
            ssize_t w = sbuf_write_fd(b, c->cfd);
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                conn_close(c);
                return;
            }
            if (w == 0) break;
        }
        if (sbuf_buffered(b) == 0) { conn_close(c); return; }
    } else if (c->up_eof) {
        /* Upstream already closed: finish draining the buffered response
         * under client backpressure, then tear down. */
        sbuf_t *b = &c->respbuf;
        while (sbuf_buffered(b) > 0) {
            ssize_t w = sbuf_write_fd(b, c->cfd);
            if (w < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                conn_close(c);
                return;
            }
            if (w == 0) break;
        }
        if (sbuf_buffered(b) == 0) conn_close(c);
    } else if (c->state == CS_RELAY || c->state == CS_UP_PENDING) {
        up_relay(c, EL_WRITE);
    }
}

/* ---------------- accept / close ---------------- */

conn_t *conn_accept(proxy_t *p, int cfd) {
    conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->px = p;
    c->cfd = cfd;
    c->ufd = -1;
    c->state = CS_READ_HEAD;
    sbuf_init(&c->cbuf);
    sbuf_init(&c->reqbuf);
    sbuf_init(&c->respbuf);
    sbuf_init(&c->errbuf);
    c->start_ms = el_now(p->el);
    get_peer_ip(c);

    p->nconns++;
    p->total_conns++;
    if (el_watch(p->el, cfd, EL_READ, client_readable, c) < 0) {
        conn_close(c);
        return NULL;
    }
    conn_kick_timer(c, p->cfg.head_timeout_ms);
    return c;
}

void conn_close(conn_t *c) {
    if (!c || c->state == CS_CLOSING) return;
    proxy_t *p = c->px;
    c->state = CS_CLOSING;
    if (c->idle_timer) el_timer_cancel(p->el, c->idle_timer);
    if (c->cfd >= 0) { el_unwatch(p->el, c->cfd); close(c->cfd); c->cfd = -1; }
    if (c->ufd >= 0) { el_unwatch(p->el, c->ufd); close(c->ufd); c->ufd = -1; }
    sbuf_free(&c->cbuf);
    sbuf_free(&c->reqbuf);
    sbuf_free(&c->respbuf);
    sbuf_free(&c->errbuf);
    free(c->up_state);
    p->nconns--;
    free(c);
}
