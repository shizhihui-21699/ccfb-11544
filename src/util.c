#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int ci_equals(const char *a, size_t alen, const char *b) {
    size_t blen = strlen(b);
    if (alen != blen) return 0;
    for (size_t i = 0; i < alen; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return 1;
}

int ci_starts(const char *a, size_t alen, const char *b) {
    size_t blen = strlen(b);
    if (blen > alen) return 0;
    for (size_t i = 0; i < blen; i++) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return 0;
    }
    return 1;
}

long long parse_u64(const char *s, size_t len) {
    if (len == 0) return -1;
    long long v = 0;
    for (size_t i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        long long d = s[i] - '0';
        if (v > (9223372036854775807LL - d) / 10) return -1;
        v = v * 10 + d;
    }
    return v;
}

long long parse_rate(const char *s, size_t len, long long *window_ms) {
    size_t i = 0;
    while (i < len && s[i] != '/') i++;
    if (i == 0 || i + 2 != len || s[i] != '/') return 0;
    long long n = parse_u64(s, i);
    if (n <= 0) return 0;
    char unit = s[i + 1];
    if (unit == 's')      *window_ms = 1000;
    else if (unit == 'm') *window_ms = 60000;
    else return 0;
    return n;
}

int buf_printf(char **buf, size_t *len, size_t *cap, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    va_list ap2;
    va_copy(ap2, ap);
    int need = vsnprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (need < 0) { va_end(ap2); return -1; }
    if (*len + (size_t)need + 1 > *cap) {
        size_t ncap = *cap ? *cap : 256;
        while (ncap < *len + (size_t)need + 1) ncap *= 2;
        char *nb = realloc(*buf, ncap);
        if (!nb) { va_end(ap2); return -1; }
        *buf = nb;
        *cap = ncap;
    }
    int w = vsnprintf(*buf + *len, *cap - *len, fmt, ap2);
    va_end(ap2);
    if (w < 0) return -1;
    *len += (size_t)w;
    return 0;
}

static int g_log_level = 1;

void log_set_level(int level) { g_log_level = level; }

void log_emit(int level, const char *fmt, ...) {
    if (level > g_log_level) return;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    const char *tag = level == 0 ? "ERR" : level == 1 ? "INFO" : "DBG";
    fprintf(stderr, "[%5lld.%03ld %s] ",
            (long long)ts.tv_sec, ts.tv_nsec / 1000000, tag);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

int set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int set_cloexec(int fd) {
    int flags = fcntl(fd, F_GETFD, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFD, flags | FD_CLOEXEC);
}

int listen_tcp(const char *host, int port, int backlog) {
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) return -1;

    /* On Linux, try to raise the system cap first; macOS clamps silently
     * to kern.ipc.somaxconn so a high backlog is still harmless. */
#ifdef __linux__
    FILE *f = fopen("/proc/sys/net/core/somaxconn", "r");
    if (f) {
        int syscap = 0;
        if (fscanf(f, "%d", &syscap) == 1 && syscap > backlog)
            backlog = syscap;
        fclose(f);
    }
#endif
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (set_nonblock(fd) < 0 || set_cloexec(fd) < 0) { close(fd); fd = -1; continue; }
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) < 0) { close(fd); fd = -1; continue; }
        if (listen(fd, backlog) < 0) { close(fd); fd = -1; continue; }
        break;
    }
    freeaddrinfo(res);
    return fd;
}

int connect_tcp_nb(const char *host, int port) {
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        errno = EHOSTUNREACH;
        return -1;
    }
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        if (set_nonblock(fd) < 0 || set_cloexec(fd) < 0) { close(fd); fd = -1; continue; }
        if (connect(fd, rp->ai_addr, rp->ai_addrlen) < 0 &&
            errno != EINPROGRESS) { close(fd); fd = -1; continue; }
        break;
    }
    freeaddrinfo(res);
    return fd;
}
