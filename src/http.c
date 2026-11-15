#include "http.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *find_seq(const char *p, size_t n, const char *seq, size_t m)
{
    if (n < m) return NULL;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(p + i, seq, m) == 0) return p + i;
    return NULL;
}

static void copy_str(char *dst, size_t cap, const char *src, size_t n)
{
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* Scan one header line [line, le) and fill what we care about. */
static void scan_header(const char *line, const char *le,
                        long *content_length, int *chunked, int *keep_alive,
                        char *token, size_t tokcap, char *host, size_t hostcap)
{
    const char *colon = memchr(line, ':', (size_t)(le - line));
    if (!colon) return;
    size_t nlen = (size_t)(colon - line);
    const char *v = colon + 1;
    while (v < le && (*v == ' ' || *v == '\t')) v++;
    size_t vlen = (size_t)(le - v);

    if (nlen == 14 && strncasecmp(line, "content-length", 14) == 0) {
        *content_length = strtol(v, NULL, 10);
        if (*content_length < 0) *content_length = -1;
    } else if (nlen == 17 && strncasecmp(line, "transfer-encoding", 17) == 0) {
        if (vlen >= 7 && strncasecmp(v + vlen - 7, "chunked", 7) == 0) *chunked = 1;
    } else if (nlen == 10 && strncasecmp(line, "connection", 10) == 0) {
        if (vlen >= 5 && strncasecmp(v, "close", 5) == 0) *keep_alive = 0;
        else if (vlen >= 10 && strncasecmp(v, "keep-alive", 10) == 0) *keep_alive = 1;
    } else if (token && nlen == 13 && strncasecmp(line, "authorization", 13) == 0) {
        if (vlen > 7 && strncasecmp(v, "bearer ", 7) == 0) { v += 7; vlen -= 7; }
        copy_str(token, tokcap, v, vlen);
    } else if (token && nlen == 9 && strncasecmp(line, "x-api-key", 9) == 0) {
        if (!token[0]) copy_str(token, tokcap, v, vlen);
    } else if (host && nlen == 4 && strncasecmp(line, "host", 4) == 0) {
        copy_str(host, hostcap, v, vlen);
    }
}

int http_parse_request(const char *b, size_t n, http_req_t *r)
{
    const char *end = find_seq(b, n, "\r\n\r\n", 4);
    if (!end) return 0;
    memset(r, 0, sizeof(*r));
    r->content_length = -1;
    r->header_len = (size_t)(end - b) + 4;

    const char *eol = find_seq(b, (size_t)(end - b) + 2, "\r\n", 2);
    if (!eol) return -1;
    const char *sp1 = memchr(b, ' ', (size_t)(eol - b));
    if (!sp1) return -1;
    size_t mlen = (size_t)(sp1 - b);
    if (mlen == 0 || mlen >= sizeof(r->method)) return -1;
    memcpy(r->method, b, mlen);

    const char *sp2 = memchr(sp1 + 1, ' ', (size_t)(eol - sp1 - 1));
    if (!sp2) return -1;
    const char *p = sp1 + 1;
    const char *q = memchr(p, '?', (size_t)(sp2 - p));
    const char *pend = q ? q : sp2;
    copy_str(r->path, sizeof(r->path), p, (size_t)(pend - p));

    if ((size_t)(eol - sp2) < 9 || memcmp(sp2 + 1, "HTTP/1.", 7) != 0) return -1;
    r->minor = sp2[8] - '0';
    if (r->minor < 0 || r->minor > 9) return -1;
    r->keep_alive = (r->minor >= 1);

    const char *line = eol + 2;
    while (line < end) {
        const char *le = find_seq(line, (size_t)(end - line) + 2, "\r\n", 2);
        if (!le) return -1;
        scan_header(line, le, &r->content_length, &r->chunked, &r->keep_alive,
                    r->token, sizeof(r->token), r->host, sizeof(r->host));
        line = le + 2;
    }
    return 1;
}

int http_parse_response(const char *b, size_t n, http_resp_t *r)
{
    const char *end = find_seq(b, n, "\r\n\r\n", 4);
    if (!end) return 0;
    memset(r, 0, sizeof(*r));
    r->content_length = -1;
    r->header_len = (size_t)(end - b) + 4;

    const char *eol = find_seq(b, (size_t)(end - b) + 2, "\r\n", 2);
    if (!eol) return -1;
    if ((size_t)(eol - b) < 12 || memcmp(b, "HTTP/1.", 7) != 0) return -1;
    int minor = b[7] - '0';
    r->status = atoi(b + 9);
    if (r->status < 100 || r->status > 999) return -1;
    r->keep_alive = (minor >= 1);

    const char *line = eol + 2;
    while (line < end) {
        const char *le = find_seq(line, (size_t)(end - line) + 2, "\r\n", 2);
        if (!le) return -1;
        scan_header(line, le, &r->content_length, &r->chunked, &r->keep_alive,
                    NULL, 0, NULL, 0);
        line = le + 2;
    }
    /* 1xx/204/304 carry no body */
    if ((r->status >= 100 && r->status < 200) || r->status == 204 || r->status == 304) {
        r->content_length = 0;
        r->chunked = 0;
    }
    return 1;
}

void chunk_init(chunk_parser_t *c)
{
    c->state = 0;
    c->remaining = 0;
}

size_t chunk_consume(chunk_parser_t *c, const char *b, size_t n, int *done)
{
    size_t used = 0;
    *done = 0;
    while (used < n) {
        switch (c->state) {
        case 0: { /* chunk-size line */
            const char *eol = find_seq(b + used, n - used, "\r\n", 2);
            if (!eol) {
                if (n - used > 64) return (size_t)-1; /* absurd size line */
                return used;
            }
            long sz = 0;
            int digits = 0;
            for (const char *p = b + used; p < eol; p++) {
                char ch = *p;
                int d;
                if (ch >= '0' && ch <= '9') d = ch - '0';
                else if (ch >= 'a' && ch <= 'f') d = ch - 'a' + 10;
                else if (ch >= 'A' && ch <= 'F') d = ch - 'A' + 10;
                else break; /* chunk extensions: ignore rest of line */
                sz = sz * 16 + d;
                digits++;
                if (sz > (1L << 40)) return (size_t)-1;
            }
            if (!digits) return (size_t)-1;
            used = (size_t)(eol - b) + 2;
            if (sz == 0) c->state = 3;
            else { c->remaining = sz; c->state = 1; }
            break;
        }
        case 1: { /* chunk data */
            size_t avail = n - used;
            size_t take = avail < (size_t)c->remaining ? avail : (size_t)c->remaining;
            used += take;
            c->remaining -= (long)take;
            if (c->remaining == 0) c->state = 2;
            break;
        }
        case 2: /* CRLF after chunk data */
            if (n - used < 2) return used;
            if (b[used] != '\r' || b[used + 1] != '\n') return (size_t)-1;
            used += 2;
            c->state = 0;
            break;
        case 3: /* trailers until empty line */
            if (n - used >= 2 && b[used] == '\r' && b[used + 1] == '\n') {
                used += 2;
                *done = 1;
                return used;
            }
            {
                const char *eol = find_seq(b + used, n - used, "\r\n", 2);
                if (!eol) return used;
                used = (size_t)(eol - b) + 2;
            }
            break;
        }
    }
    return used;
}
