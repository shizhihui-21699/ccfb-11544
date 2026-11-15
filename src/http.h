#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>

/* Minimal incremental HTTP/1.x parsing helpers (headers only) plus a
 * chunked-body tracker used to find response boundaries while streaming. */

typedef struct {
    char   method[16];
    char   path[1024];      /* path without query string */
    int    minor;           /* HTTP minor version */
    long   content_length;  /* -1 if absent */
    int    chunked;
    int    keep_alive;      /* resolved per RFC 7230 defaults */
    char   token[256];      /* Authorization: Bearer <t> or X-Api-Key */
    char   host[256];
    size_t header_len;      /* raw header bytes incl. final CRLFCRLF */
} http_req_t;

typedef struct {
    int    status;
    long   content_length;  /* -1 if absent */
    int    chunked;
    int    keep_alive;
    size_t header_len;
} http_resp_t;

/* Returns 1 complete, 0 need more data, -1 malformed. */
int http_parse_request(const char *buf, size_t len, http_req_t *out);
int http_parse_response(const char *buf, size_t len, http_resp_t *out);

/* Chunked transfer-coding tracker. Feed stream bytes; it reports how many
 * were consumed (forward them verbatim) and sets *done on the terminal
 * chunk + trailers. Returns (size_t)-1 on malformed input. */
typedef struct {
    int  state;      /* 0=size line 1=data 2=CRLF after data 3=trailers */
    long remaining;
} chunk_parser_t;

void   chunk_init(chunk_parser_t *c);
size_t chunk_consume(chunk_parser_t *c, const char *buf, size_t len, int *done);

#endif
