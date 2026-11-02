#define _GNU_SOURCE
#include "advlb/net_utils.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advnet/advnet.h"

int set_nonblocking(int fd) {
    return net_set_nonblocking(fd);
}

ssize_t write_all(int fd, const char *buf, size_t len) {
    return net_write_all(fd, buf, len, 5000);
}

ssize_t read_retry(int fd, char *buf, size_t len) {
    return net_read_retry(fd, buf, len);
}

int connect_with_timeout_transparent(const char *ip, int port, int timeout_ms, const struct sockaddr_in *client_addr) {
    return net_connect_tcp_timeout(ip, port, timeout_ms, client_addr, g_config.enable_transparent_mode);
}

int create_tcp_server_socket(int port) {
    return net_create_tcp_server(port, SOMAXCONN);
}

int create_udp_server_socket(int port) {
    return net_create_udp_server(port);
}
