#ifdef __linux__

#include "event_loop_internal.h"
#include "util.h"

#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

int el_backend_init(event_loop_t *el) {
    el->backend_fd = epoll_create1(EPOLL_CLOEXEC);
    return el->backend_fd < 0 ? -1 : 0;
}

static uint32_t to_epoll(int events) {
    uint32_t e = 0;
    if (events & EL_READ)  e |= EPOLLIN;
    if (events & EL_WRITE) e |= EPOLLOUT;
    /* Level-triggered, matching the kqueue backend. */
    return e | EPOLLRDHUP;
}

int el_backend_add(event_loop_t *el, int fd, int events) {
    struct epoll_event ev;
    ev.events = to_epoll(events);
    ev.data.ptr = &el->ios[fd];
    return epoll_ctl(el->backend_fd, EPOLL_CTL_ADD, fd, &ev);
}

int el_backend_mod(event_loop_t *el, int fd, int events) {
    struct epoll_event ev;
    ev.events = to_epoll(events);
    ev.data.ptr = &el->ios[fd];
    return epoll_ctl(el->backend_fd, EPOLL_CTL_MOD, fd, &ev);
}

int el_backend_del(event_loop_t *el, int fd) {
    return epoll_ctl(el->backend_fd, EPOLL_CTL_DEL, fd, NULL);
}

void el_backend_wait(event_loop_t *el, int timeout_ms) {
    struct epoll_event evlist[256];
    int n;
    do {
        n = epoll_wait(el->backend_fd, evlist, 256, timeout_ms);
    } while (n < 0 && errno == EINTR);
    if (n < 0) return;

    for (int i = 0; i < n; i++) {
        io_entry_t *e = evlist[i].data.ptr;
        if (!e || !e->active) continue;
        /* Recover the fd: entries are embedded contiguously. */
        int fd = (int)(e - el->ios);
        uint32_t fl = evlist[i].events;
        int events = 0;
        if (fl & (EPOLLIN | EPOLLHUP | EPOLLRDHUP))  events |= EL_READ;
        if (fl & (EPOLLOUT | EPOLLERR | EPOLLHUP))    events |= EL_WRITE;
        if (e->cb) e->cb(el, fd, events, e->arg);
        if (el->stop) return;
    }
}

#endif /* __linux__ */
