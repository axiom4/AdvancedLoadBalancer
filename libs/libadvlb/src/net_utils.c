#define _GNU_SOURCE
#include "advlb/net_utils.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advnet/advnet.h"
#include <sys/resource.h>

void increase_fd_limit(void) {
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
        rlim_t target = 65536;
        if (target > rl.rlim_max) {
            target = rl.rlim_max;
        }
        if (rl.rlim_cur < target) {
            rl.rlim_cur = target;
            if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
                rl.rlim_cur = rl.rlim_max;
                setrlimit(RLIMIT_NOFILE, &rl);
            }
        }
    }
}

int set_nonblocking(int fd) {
    return net_set_nonblocking(fd);
}

ssize_t write_all(int fd, const char *buf, size_t len) {
    return net_write_all(fd, buf, len, 5000);
}

ssize_t read_retry(int fd, char *buf, size_t len) {
    return net_read_retry(fd, buf, len);
}

int connect_with_timeout_transparent(const char *ip, int port, int timeout_ms, const struct sockaddr_storage *client_addr) {
    return net_connect_tcp_timeout(ip, port, timeout_ms, client_addr, g_config.enable_transparent_mode);
}

int connect_nonblocking_transparent(const char *ip, int port, const struct sockaddr_storage *client_addr, bool *in_progress) {
    return net_connect_tcp_nonblocking(ip, port, client_addr, g_config.enable_transparent_mode, in_progress);
}

int create_tcp_server_socket(int port) {
    return net_create_tcp_server(port, SOMAXCONN);
}

int create_udp_server_socket(int port) {
    return net_create_udp_server(port);
}
