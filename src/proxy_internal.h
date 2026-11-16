#ifndef RL_PROXY_INTERNAL_H
#define RL_PROXY_INTERNAL_H

#include "proxy.h"
#include "sbuf.h"
#include "http.h"
#include "event_loop.h"

#define BODY_HARD_CAP     (16 * 1024 * 1024)
#define UP_CONNECT_TIMEOUT_MS 5000
#define UPSTREAM_RESP_TIMEOUT_MS 30000

typedef enum {
    CS_READ_HEAD = 0,   /* accumulating request head */
    CS_READ_BODY,       /* forwarding request body (upstream open) */
    CS_UP_PENDING,      /* non-blocking connect() in flight */
    CS_RELAY,           /* bidirectional relay established */
    CS_DRAIN_CLOSE,     /* drain request body, then close (429 path) */
    CS_SEND_ERROR,      /* writing a locally generated response */
    CS_CLOSING
} conn_state_t;

typedef struct up_state up_state_t;

typedef struct conn {
    proxy_t      *px;
    int           cfd;       /* client socket */
    int           ufd;       /* upstream socket, -1 when closed */
    conn_state_t  state;
    sbuf_t        cbuf;      /* client -> proxy raw bytes */
    sbuf_t        reqbuf;    /* proxy -> upstream: head + body staging */
    sbuf_t        respbuf;   /* upstream -> proxy -> client */
    sbuf_t        errbuf;    /* generated 4xx/5xx response */
    http_req_t    req;
    int           req_valid;
    long long     body_remaining; /* content-length bytes left from client */
    int           chunked_req;
    int           keep_alive;
    int           head_sent;
    int           up_eof;       /* upstream closed; drain respbuf then close */
    uint64_t      idle_timer;
    int64_t       start_ms;
    char          peer_ip[64];
    up_state_t   *up_state;
} conn_t;

conn_t *conn_accept(proxy_t *px, int listen_fd);
void    conn_close(conn_t *c);
void    conn_kick_timer(conn_t *c, int timeout_ms);

/* Upstream manager (upstream.c) */
int  up_connect(conn_t *c);
void up_relay(conn_t *c, int events);
void up_writable_cb(event_loop_t *el, int fd, int events, void *arg);
void up_readable_cb(event_loop_t *el, int fd, int events, void *arg);

/* Request pipeline (request.c) */
void client_readable(event_loop_t *el, int fd, int events, void *arg);
void client_writable(event_loop_t *el, int fd, int events, void *arg);

/* Local error responses (request.c) */
void send_simple_error(conn_t *c, int status, long long retry_after);

#endif
