#include "sbuf.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define SBUF_MIN_CAP 4096

void sbuf_init(sbuf_t *b) {
    b->data = NULL;
    b->len = b->rd = b->cap = 0;
}

void sbuf_free(sbuf_t *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->rd = b->cap = 0;
}

int sbuf_reserve(sbuf_t *b, size_t extra) {
    if (b->len + extra <= b->cap) return 0;
    /* Compact first to reclaim consumed front space. */
    if (b->rd > 0 && b->rd >= b->len / 2) sbuf_compact(b);
    size_t ncap = b->cap ? b->cap : SBUF_MIN_CAP;
    while (ncap < b->len + extra) {
        if (ncap > (size_t)-1 / 2) { errno = ENOMEM; return -1; }
        ncap *= 2;
    }
    char *p = realloc(b->data, ncap);
    if (!p) return -1;
    b->data = p;
    b->cap = ncap;
    return 0;
}

void sbuf_consume(sbuf_t *b, size_t n) {
    if (n >= b->len - b->rd) { b->rd = b->len = 0; return; }
    b->rd += n;
}

void sbuf_compact(sbuf_t *b) {
    if (b->rd == 0) return;
    size_t n = b->len - b->rd;
    if (n) memmove(b->data, b->data + b->rd, n);
    b->len = n;
    b->rd = 0;
}

void sbuf_reset(sbuf_t *b) { b->rd = b->len = 0; }

size_t sbuf_buffered(const sbuf_t *b) { return b->len - b->rd; }

ssize_t sbuf_read_fd(sbuf_t *b, int fd, size_t hard_cap) {
    if (sbuf_reserve(b, 8192) < 0) return -1;
    if (hard_cap && b->len >= hard_cap) return -2;
    size_t room = b->cap - b->len;
    if (hard_cap && room > hard_cap - b->len) room = hard_cap - b->len;
    ssize_t n = read(fd, b->data + b->len, room);
    if (n > 0) b->len += (size_t)n;
    return n;
}

ssize_t sbuf_write_fd(sbuf_t *b, int fd) {
    size_t n = b->len - b->rd;
    if (n == 0) return 0;
    ssize_t w = write(fd, b->data + b->rd, n);
    if (w > 0) {
        b->rd += (size_t)w;
        if (b->rd == b->len) b->rd = b->len = 0;
    }
    return w; /* -1 with errno=EAGAIN is the normal backpressure case */
}
