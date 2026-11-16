#ifndef RL_UTIL_H
#define RL_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdarg.h>

/* Monotonic clock, milliseconds. Never jumps backwards. */
int64_t now_ms(void);

/* Case-insensitive compare / prefix match, ASCII only (headers are ASCII). */
int ci_equals(const char *a, size_t alen, const char *b);
int ci_starts(const char *a, size_t alen, const char *b);

/* Parse non-negative 64-bit int. Returns -1 on malformed input. */
long long parse_u64(const char *s, size_t len);

/* Parse rate "100/s", "6000/m". Returns 0 on error; writes window ms. */
long long parse_rate(const char *s, size_t len, long long *window_ms);

/* Append printf-style to a heap buffer (buf/cap), grows as needed. */
int buf_printf(char **buf, size_t *len, size_t *cap, const char *fmt, ...);

/* Logging, line buffered to stderr. Levels: 0=err 1=info 2=debug */
void log_set_level(int level);
void log_emit(int level, const char *fmt, ...);
#define log_err(...) log_emit(0, __VA_ARGS__)
#define log_info(...) log_emit(1, __VA_ARGS__)
#define log_dbg(...)  log_emit(2, __VA_ARGS__)

/* Set a fd non-blocking / close-on-exec. */
int set_nonblock(int fd);
int set_cloexec(int fd);

/* Create a non-blocking TCP listener on host:port (backlog up to SOMAXCONN). */
int listen_tcp(const char *host, int port, int backlog);

/* Connect (non-blocking) to host:port. Returns fd, or -1 with errno set
 * (EINPROGRESS case is the normal in-progress path). */
int connect_tcp_nb(const char *host, int port);

#endif
