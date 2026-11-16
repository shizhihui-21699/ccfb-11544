#ifndef RL_HTTP_H
#define RL_HTTP_H

#include <stddef.h>
#include <stdint.h>

/* Incremental, zero-copy-ish HTTP/1.x request parser.
 * All pieces point into the caller's buffer; none are NUL-terminated.
 * The parser tolerates folded/duplicate headers and just exposes them. */

typedef struct {
    const char *name;
    size_t      nlen;
    const char *val;
    size_t      vlen;
} http_header_t;

#define HTTP_MAX_HEADERS 64

typedef enum {
    HP_NEED_MORE = 0,
    HP_OK,
    HP_BAD_REQUEST,
    HP_URI_TOO_LONG,
    HP_HEADER_TOO_LARGE,
    HP_TOO_MANY_HEADERS,
    HP_BAD_VERSION          /* only HTTP/1.0 and 1.1 accepted */
} hp_status_t;

typedef struct {
    const char    *method;
    size_t         mlen;
    const char    *target;   /* raw request-target (path?query) */
    size_t         tlen;
    const char    *path;     /* target without query */
    size_t         plen;
    int            minor;    /* 0 or 1 */
    http_header_t  headers[HTTP_MAX_HEADERS];
    int            nheaders;
    size_t         head_len; /* total bytes consumed by the head incl CRLFCRLF */
    long long      content_length;  /* -1 if absent */
    int            chunked;
    int            keep_alive;      /* resolved per version + Connection */
    const char    *err_reason;
} http_req_t;

hp_status_t http_parse_request(const char *buf, size_t len, http_req_t *r);
const http_header_t *http_find_header(const http_req_t *r, const char *name);

/* Minimal response head parser, used by the replay tool only. */
typedef struct {
    int      status;
    int      minor;
    size_t   head_len;
    long long content_length;
    int      chunked;
    int      keep_alive;
} http_resp_t;

hp_status_t http_parse_response(const char *buf, size_t len, http_resp_t *r);

/* Case-insensitive token search inside a comma-separated header value,
 * e.g. Connection: "keep-alive, x". */
int http_value_has_token(const char *v, size_t vlen, const char *token);

/* Lookup table for known reason phrases. */
const char *http_reason(int status);

#endif
