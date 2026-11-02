#define _GNU_SOURCE
#include "advnet/net_core.h"
#include "advnet/net_epoll.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/socket.h>

int net_set_nonblocking(int fd) {
    int flags;
    while ((flags = fcntl(fd, F_GETFL, 0)) == -1) {
        if (errno == EINTR) continue;
        return -1;
    }
    while (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        if (errno == EINTR) continue;
        return -1;
    }
    return 0;
}

int net_set_nodelay(int fd, int enable) {
    int val = enable ? 1 : 0;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *)&val, sizeof(int));
}

int net_set_timeouts(int fd, int timeout_sec) {
    struct timeval tv = { .tv_sec = timeout_sec, .tv_usec = 0 };
    int r1 = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    int r2 = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return (r1 == 0 && r2 == 0) ? 0 : -1;
}

int net_set_reuse(int fd, int reuse_addr, int reuse_port) {
    int opt = reuse_addr ? 1 : 0;
    int r = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    if (reuse_port) {
        int opt_p = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt_p, sizeof(opt_p));
    }
#else
    (void)reuse_port;
#endif
    return r;
}

int net_set_keepalive(int fd, int enable) {
    int opt = enable ? 1 : 0;
    return setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
}

bool net_validate_ipv4(const char *ip) {
    if (!ip || strlen(ip) == 0) return false;
    struct in_addr addr;
    return inet_pton(AF_INET, ip, &addr) == 1;
}

int net_create_tcp_server(int port, int backlog) {
    int server_fd;
    while ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        if (errno == EINTR) continue;
        perror("TCP server socket error");
        return -1;
    }

    net_set_reuse(server_fd, 1, 1);

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons((uint16_t)port);

    while (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        if (errno == EINTR) continue;
        perror("TCP bind error");
        close(server_fd);
        return -1;
    }

    int bl = (backlog > 0) ? backlog : SOMAXCONN;
    while (listen(server_fd, bl) < 0) {
        if (errno == EINTR) continue;
        perror("TCP listen error");
        close(server_fd);
        return -1;
    }

    return server_fd;
}

int net_create_udp_server(int port) {
    int udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_fd < 0) {
        perror("UDP server socket error");
        return -1;
    }

    net_set_reuse(udp_fd, 1, 1);
    net_set_nonblocking(udp_fd);

    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons((uint16_t)port);

    if (bind(udp_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("UDP bind error");
        close(udp_fd);
        return -1;
    }

    return udp_fd;
}

int net_connect_tcp_timeout(const char *ip, int port, int timeout_ms,
                            const struct sockaddr_in *bind_client_addr,
                            bool enable_transparent) {
    int fd;
    while ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        if (errno == EINTR) continue;
        return -1;
    }

    net_set_nodelay(fd, 1);
#ifdef SO_NOSIGPIPE
    int flag = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flag, sizeof(int));
#endif

    // IP transparency support (Linux TPROXY)
    if (enable_transparent && bind_client_addr != NULL) {
        int opt = 1;
        if (setsockopt(fd, SOL_IP, IP_TRANSPARENT, &opt, sizeof(opt)) == 0) {
            struct sockaddr_in bind_addr;
            memset(&bind_addr, 0, sizeof(bind_addr));
            bind_addr.sin_family = AF_INET;
            bind_addr.sin_addr = bind_client_addr->sin_addr;
            bind_addr.sin_port = htons(0);

            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            while (bind(fd, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
                if (errno == EINTR) continue;
                break;
            }
        }
    }

    if (net_set_nonblocking(fd) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        close(fd);
        return -1;
    }

    int res;
    while ((res = connect(fd, (struct sockaddr *)&addr, sizeof(addr))) < 0) {
        if (errno == EINTR || errno == EINPROGRESS) {
            break;
        }
        close(fd);
        return -1;
    }

    if (res == 0) {
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
        return fd;
    }

    int epfd = epoll_create1(0);
    if (epfd < 0) {
        close(fd);
        return -1;
    }

    struct epoll_event ev;
    ev.events = EPOLLOUT;
    ev.data.fd = fd;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        close(epfd);
        close(fd);
        return -1;
    }

    while (1) {
        struct epoll_event event;
        int ep_res = epoll_wait(epfd, &event, 1, timeout_ms);
        if (ep_res < 0) {
            if (errno == EINTR) continue;
            close(epfd);
            close(fd);
            return -1;
        }
        if (ep_res == 0) {
            close(epfd);
            close(fd);
            return -1; // Connection timeout
        }
        break;
    }
    close(epfd);

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    return fd;
}

