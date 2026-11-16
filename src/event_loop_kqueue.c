#ifdef __APPLE__

#include "event_loop_internal.h"
#include "util.h"

#include <sys/event.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

int el_backend_init(event_loop_t *el) {
    el->backend_fd = kqueue();
    if (el->backend_fd < 0) return -1;
    return set_cloexec(el->backend_fd);
}

static int kevent_ctl(event_loop_t *el, int fd, int filter,
                      int flags, int events) {
    struct kevent ch;
    /* Level-triggered (no EV_CLEAR): mirrors the epoll backend's
     * semantics and avoids losing readiness after EV_DISABLE/ENABLE. */
    EV_SET(&ch, fd, filter, flags, 0, 0, &el->ios[fd]);
    (void)events;
    int rc = kevent(el->backend_fd, &ch, 1, NULL, 0, NULL);
    if (rc < 0 && errno == EINTR) {
        rc = kevent(el->backend_fd, &ch, 1, NULL, 0, NULL);
    }
    return rc;
}

int el_backend_add(event_loop_t *el, int fd, int events) {
    int rc = 0;
    if (events & EL_READ)
        rc |= kevent_ctl(el, fd, EVFILT_READ, EV_ADD, events);
    if (events & EL_WRITE)
        rc |= kevent_ctl(el, fd, EVFILT_WRITE, EV_ADD, events);
    return rc;
}

int el_backend_mod(event_loop_t *el, int fd, int events) {
    /* With both filters registered independently, "mod" means disable a
     * filter via EV_DISABLE and re-enable via EV_ENABLE. Clear-event
     * mode means we always drain until EAGAIN anyway. */
    struct kevent ch[2];
    int n = 0;
    int want_read  = events & EL_READ;
    int want_write = events & EL_WRITE;
    EV_SET(&ch[n++], fd, EVFILT_READ,
           EV_ADD | (want_read ? EV_ENABLE : EV_DISABLE), 0, 0,
           &el->ios[fd]);
    EV_SET(&ch[n++], fd, EVFILT_WRITE,
           EV_ADD | (want_write ? EV_ENABLE : EV_DISABLE), 0, 0,
           &el->ios[fd]);
    return kevent(el->backend_fd, ch, n, NULL, 0, NULL);
}

int el_backend_del(event_loop_t *el, int fd) {
    struct kevent ch[2];
    EV_SET(&ch[0], fd, EVFILT_READ,  EV_DELETE, 0, 0, NULL);
    EV_SET(&ch[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    /* One filter may never have been added; ignore ENOENT. */
    int rc = kevent(el->backend_fd, ch, 2, NULL, 0, NULL);
    if (rc < 0 && errno == ENOENT) errno = 0, rc = 0;
    return rc;
}

void el_backend_wait(event_loop_t *el, int timeout_ms) {
    struct kevent evlist[256];
    struct timespec ts;
    struct timespec *tsp = NULL;
    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (timeout_ms % 1000) * 1000000L;
        tsp = &ts;
    }
    int n;
    do {
        n = kevent(el->backend_fd, NULL, 0, evlist, 256, tsp);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return;

    for (int i = 0; i < n; i++) {
        struct kevent *ev = &evlist[i];
        int fd = (int)ev->ident;
        if (ev->flags & EV_ERROR) {
            /* Treat errors as readiness; the IO callback sees the
             * failure on read/write and closes the connection. */
            if (fd == el->sigpipe[0]) continue;
        }
        if (fd < 0 || fd >= EL_MAX_FDS || !el->ios[fd].active) continue;
        io_entry_t *e = &el->ios[fd];
        int events = 0;
        if (ev->filter == EVFILT_READ)  events = EL_READ;
        if (ev->filter == EVFILT_WRITE) events = EL_WRITE;
        if (ev->flags & EV_EOF) events |= EL_READ | EL_WRITE;
        if (events && e->cb) e->cb(el, fd, events, e->arg);
        if (el->stop) return;
    }
}

#endif /* __APPLE__ */
