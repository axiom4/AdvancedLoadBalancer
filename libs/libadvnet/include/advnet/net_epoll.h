#ifndef ADVNET_EPOLL_H
#define ADVNET_EPOLL_H

#if defined(__linux__)
#include <sys/epoll.h>
#else
#include <sys/types.h>
#include <sys/event.h>
#include <sys/time.h>
#include <stdint.h>
#include <unistd.h>

#define EPOLLIN  0x001
#define EPOLLOUT 0x004
#define EPOLLERR 0x008
#define EPOLLHUP 0x010
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

typedef union epoll_data {
    void    *ptr;
    int      fd;
    uint32_t u32;
    uint64_t u64;
} epoll_data_t;

struct epoll_event {
    uint32_t     events;
    epoll_data_t data;
};

static inline int epoll_create1(int flags) {
    (void)flags;
    return kqueue();
}

static inline int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    struct kevent kev[2];
    int n = 0;
    if (op == EPOLL_CTL_ADD) {
        if (event->events & EPOLLIN) {
            EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)event->data.fd);
        }
        if (event->events & EPOLLOUT) {
            EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)event->data.fd);
        }
    } else if (op == EPOLL_CTL_MOD) {
        struct kevent del_kev[2];
        EV_SET(&del_kev[0], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&del_kev[1], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        kevent(epfd, del_kev, 2, NULL, 0, NULL);

        if (event->events & EPOLLIN) {
            EV_SET(&kev[n++], fd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)event->data.fd);
        }
        if (event->events & EPOLLOUT) {
            EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ENABLE, 0, 0, (void *)(intptr_t)event->data.fd);
        }
    } else if (op == EPOLL_CTL_DEL) {
        EV_SET(&kev[n++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&kev[n++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
    }
    return kevent(epfd, kev, n, NULL, 0, NULL);
}

static inline int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout_ms) {
    struct timespec ts;
    struct timespec *pts = NULL;
    if (timeout_ms >= 0) {
        ts.tv_sec = timeout_ms / 1000;
        ts.tv_nsec = (long)(timeout_ms % 1000) * 1000000L;
        pts = &ts;
    }
    struct kevent out_kev[64];
    int to_fetch = (maxevents < 64) ? maxevents : 64;
    int n = kevent(epfd, NULL, 0, out_kev, to_fetch, pts);
    if (n <= 0) return n;

    for (int i = 0; i < n; i++) {
        events[i].events = 0;
        if (out_kev[i].filter == EVFILT_READ) events[i].events |= EPOLLIN;
        if (out_kev[i].filter == EVFILT_WRITE) events[i].events |= EPOLLOUT;
        if (out_kev[i].flags & EV_ERROR) events[i].events |= EPOLLERR;
        if (out_kev[i].flags & EV_EOF) events[i].events |= EPOLLHUP;
        events[i].data.fd = (int)(intptr_t)out_kev[i].udata;
    }
    return n;
}
#endif

#ifndef SOL_IP
#define SOL_IP 0
#endif

#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif

#endif /* ADVNET_EPOLL_H */

