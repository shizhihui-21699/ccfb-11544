#include "http.h"
#include "util.h"

#include <string.h>
#include <strings.h>
#include <stdio.h>

#define MAX_REQUEST_LINE  16384
#define MAX_HEADER_BLOCK  65536

static const char *find_crlf(const char *buf, size_t len, size_t *off) {
    for (size_t i = 0; i + 1 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n') {
            *off = i;
            return buf + i;
        }
    }
    return NULL;
}

static int is_space(char c) { return c == ' ' || c == '\t'; }

static int token_end(const char *s, size_t len, size_t i) {
    while (i < len && !is_space(s[i])) i++;
    return (int)i;
}

int http_value_has_token(const char *v, size_t vlen, const char *token) {
    size_t tlen = strlen(token);
    size_t i = 0;
    while (i < vlen) {
        while (i < vlen && (v[i] == ',' || is_space(v[i]))) i++;
        size_t start = i;
        while (i < vlen && v[i] != ',') i++;
        size_t end = i;
        while (end > start && is_space(v[end - 1])) end--;
        if (end - start == tlen) {
            int eq = 1;
            for (size_t k = 0; k < tlen; k++) {
                char a = v[start + k], b = token[k];
                if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
                if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
                if (a != b) { eq = 0; break; }
            }
            if (eq) return 1;
        }
    }
    return 0;
}

static hp_status_t parse_request_line(const char *line, size_t len,
                                      http_req_t *r) {
    if (len > MAX_REQUEST_LINE) return HP_URI_TOO_LONG;
    size_t i = 0;
    int end = token_end(line, len, i);
    if (end == (int)i) return HP_BAD_REQUEST;
    r->method = line;
    r->mlen = (size_t)end;
    i = (size_t)end;
    while (i < len && is_space(line[i])) i++;
    end = token_end(line, len, i);
    if (end == (int)i) return HP_BAD_REQUEST;
    r->target = line + i;
    r->tlen = (size_t)end - i;
    i = (size_t)end;
    while (i < len && is_space(line[i])) i++;
    if (len - i < 5 || line[i] != 'H' || line[i + 1] != 'T' ||
        line[i + 2] != 'T' || line[i + 3] != 'P' || line[i + 4] != '/')
        return HP_BAD_VERSION;
    i += 5;
    if (line[i] != '1' || line[i + 1] != '.' ||
        (line[i + 2] != '0' && line[i + 2] != '1'))
        return HP_BAD_VERSION;
    r->minor = line[i + 2] == '1' ? 1 : 0;
    i += 3;
    while (i < len && is_space(line[i])) i++;
    if (i != len) return HP_BAD_REQUEST;

    r->path = r->target;
    r->plen = r->tlen;
    for (size_t k = 0; k < r->tlen; k++) {
        if (r->target[k] == '?') { r->plen = k; break; }
    }
    return HP_OK;
}

hp_status_t http_parse_request(const char *buf, size_t len, http_req_t *r) {
    memset(r, 0, sizeof(*r));
    r->content_length = -1;
    r->keep_alive = -1;

    size_t off;
    const char *crlf = find_crlf(buf, len, &off);
    if (!crlf) return len >= MAX_HEADER_BLOCK ? HP_HEADER_TOO_LARGE : HP_NEED_MORE;

    hp_status_t st = parse_request_line(buf, off, r);
    if (st != HP_OK) return st;

    size_t pos = off + 2;
    int saw_conn = 0, conn_keep = 0, conn_close = 0;

    while (1) {
        size_t hoff;
        const char *h = find_crlf(buf + pos, len - pos, &hoff);
        if (!h) return HP_NEED_MORE;
        size_t line_len = hoff;
        if (line_len == 0) { pos += 2; break; } /* empty line: end of head */
        if (pos + line_len > MAX_HEADER_BLOCK) return HP_HEADER_TOO_LARGE;

        const char *line = buf + pos;
        size_t colon = 0;
        while (colon < line_len && line[colon] != ':') colon++;
        if (colon == line_len) { r->err_reason = "malformed header"; return HP_BAD_REQUEST; }
        size_t nlen = colon;
        while (nlen && is_space(line[nlen - 1])) nlen--;
        size_t vstart = colon + 1;
        while (vstart < line_len && is_space(line[vstart])) vstart++;
        size_t vend = line_len;
        while (vend > vstart && is_space(line[vend - 1])) vend--;

        if (r->nheaders >= HTTP_MAX_HEADERS) return HP_TOO_MANY_HEADERS;
        http_header_t *hh = &r->headers[r->nheaders++];
        hh->name = line;
        hh->nlen = nlen;
        hh->val = line + vstart;
        hh->vlen = vend - vstart;

        if (ci_equals(hh->name, hh->nlen, "content-length")) {
            long long cl = parse_u64(hh->val, hh->vlen);
            if (cl < 0) { r->err_reason = "bad content-length"; return HP_BAD_REQUEST; }
            r->content_length = cl;
        } else if (ci_equals(hh->name, hh->nlen, "transfer-encoding")) {
            if (http_value_has_token(hh->val, hh->vlen, "chunked"))
                r->chunked = 1;
        } else if (ci_equals(hh->name, hh->nlen, "connection")) {
            saw_conn = 1;
            if (http_value_has_token(hh->val, hh->vlen, "close")) conn_close = 1;
            if (http_value_has_token(hh->val, hh->vlen, "keep-alive")) conn_keep = 1;
        }
        pos += line_len + 2;
    }

    if (r->chunked && r->content_length >= 0) {
        r->err_reason = "chunked + content-length";
        return HP_BAD_REQUEST;
    }
    r->keep_alive = saw_conn
        ? (conn_close ? 0 : (conn_keep || r->minor == 1))
        : (r->minor == 1);
    r->head_len = pos;
    return HP_OK;
}

const http_header_t *http_find_header(const http_req_t *r, const char *name) {
    for (int i = 0; i < r->nheaders; i++) {
        if (ci_equals(r->headers[i].name, r->headers[i].nlen, name))
            return &r->headers[i];
    }
    return NULL;
}

hp_status_t http_parse_response(const char *buf, size_t len, http_resp_t *r) {
    memset(r, 0, sizeof(*r));
    r->content_length = -1;
    size_t off;
    const char *crlf = find_crlf(buf, len, &off);
    if (!crlf) return HP_NEED_MORE;
    const char *line = buf;
    size_t i = 0;
    while (i < off && line[i] != ' ') i++;
    if (i >= off) return HP_BAD_REQUEST;
    i++;
    int status = 0, digits = 0;
    while (i < off && line[i] >= '0' && line[i] <= '9') {
        status = status * 10 + (line[i] - '0');
        digits++;
        i++;
    }
    if (digits != 3) return HP_BAD_REQUEST;
    r->status = status;
    r->minor = (off >= 9 && line[5] == '1' && line[7] == '1') ? 1 : 0;

    size_t pos = off + 2;
    int saw_conn = 0, conn_close = 0;
    while (1) {
        size_t hoff;
        const char *h = find_crlf(buf + pos, len - pos, &hoff);
        if (!h) return HP_NEED_MORE;
        size_t line_len = hoff;
        if (line_len == 0) { pos += 2; break; }
        const char *hl = buf + pos;
        size_t colon = 0;
        while (colon < line_len && hl[colon] != ':') colon++;
        if (colon < line_len) {
            size_t vstart = colon + 1;
            while (vstart < line_len && is_space(hl[vstart])) vstart++;
            size_t vend = line_len;
            while (vend > vstart && is_space(hl[vend - 1])) vend--;
            if (ci_equals(hl, colon, "content-length")) {
                long long cl = parse_u64(hl + vstart, vend - vstart);
                if (cl >= 0) r->content_length = cl;
            } else if (ci_equals(hl, colon, "transfer-encoding")) {
                if (http_value_has_token(hl + vstart, vend - vstart, "chunked"))
                    r->chunked = 1;
            } else if (ci_equals(hl, colon, "connection")) {
                saw_conn = 1;
                if (http_value_has_token(hl + vstart, vend - vstart, "close"))
                    conn_close = 1;
            }
        }
        pos += line_len + 2;
    }
    r->keep_alive = saw_conn ? !conn_close : (r->minor == 1);
    r->head_len = pos;
    return HP_OK;
}

const char *http_reason(int status) {
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:  return "Error";
    }
}
