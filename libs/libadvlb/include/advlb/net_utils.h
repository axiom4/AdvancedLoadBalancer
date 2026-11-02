#ifndef ADVLB_NET_UTILS_H
#define ADVLB_NET_UTILS_H

#include <sys/types.h>
#include <stdbool.h>
#include <netinet/in.h>

int set_nonblocking(int fd);
ssize_t write_all(int fd, const char *buf, size_t len);
ssize_t read_retry(int fd, char *buf, size_t len);
int connect_with_timeout_transparent(const char *ip, int port, int timeout_ms, const struct sockaddr_in *client_addr);
int connect_nonblocking_transparent(const char *ip, int port, const struct sockaddr_in *client_addr, bool *in_progress);
int create_tcp_server_socket(int port);
int create_udp_server_socket(int port);
void increase_fd_limit(void);

#endif /* ADVLB_NET_UTILS_H */

