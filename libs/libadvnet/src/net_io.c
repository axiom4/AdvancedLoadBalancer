#define _GNU_SOURCE
#include "advnet/net_io.h"

#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>

ssize_t net_write_all(int fd, const char *buf, size_t len, int timeout_ms) {
    size_t total = 0;
    int to_wait = (timeout_ms > 0) ? timeout_ms : 5000;

    while (total < len) {
        ssize_t written = write(fd, buf + total, len - total);
        if (written < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
                int pr = poll(&pfd, 1, to_wait);
                if (pr > 0 && (pfd.revents & POLLOUT)) continue;
                return -1; // Socket timeout or error
            }
            return -1;
        }
        if (written == 0) return (ssize_t)total;
        total += (size_t)written;
    }
    return (ssize_t)total;
}

ssize_t net_read_retry(int fd, char *buf, size_t len) {
    while (1) {
        ssize_t bytes = read(fd, buf, len);
        if (bytes < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        return bytes;
    }
}

ssize_t net_write_nonblocking(int fd, const char *buf, size_t len, bool *out_want_io) {
    *out_want_io = false;
    if (len == 0) return 0;

    while (1) {
        ssize_t w = send(fd, buf, len, 0);
        if (w >= 0) return w;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *out_want_io = true;
            return 0;
        }
        return -1;
    }
}

ssize_t net_read_nonblocking(int fd, char *buf, size_t max_len, bool *out_want_io) {
    *out_want_io = false;
    if (max_len == 0) return 0;

    while (1) {
        ssize_t r = recv(fd, buf, max_len, 0);
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *out_want_io = true;
            return 0;
        }
        return -1;
    }
}

