#ifndef RL_SBUF_H
#define RL_SBUF_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Growable byte buffer with separate read position.
 * Data lives at data[rd .. len). Writes append at data[len .. cap). */
typedef struct {
    char  *data;
    size_t len;   /* write end */
    size_t rd;    /* read end  */
    size_t cap;
} sbuf_t;

void sbuf_init(sbuf_t *b);
void sbuf_free(sbuf_t *b);
int  sbuf_reserve(sbuf_t *b, size_t extra);          /* ensure room for extra */
void sbuf_consume(sbuf_t *b, size_t n);              /* drop n read bytes */
void sbuf_compact(sbuf_t *b);                         /* move tail to front */
void sbuf_reset(sbuf_t *b);                           /* rd = len = 0 */
size_t sbuf_buffered(const sbuf_t *b);                /* len - rd */

/* Read from fd into buffer. Returns bytes read, 0 on EOF, -1 on error
 * (errno == EAGAIN means try again), -2 if a hard cap was hit. */
ssize_t sbuf_read_fd(sbuf_t *b, int fd, size_t hard_cap);

/* Write buffered bytes to fd. Returns:
 *  >=0 bytes written, -1 EAGAIN/error (check errno), 0 when nothing queued. */
ssize_t sbuf_write_fd(sbuf_t *b, int fd);

#endif
