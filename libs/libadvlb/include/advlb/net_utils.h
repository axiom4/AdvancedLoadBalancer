#ifndef ADVLB_NET_UTILS_H
#define ADVLB_NET_UTILS_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <netinet/in.h>

#if !defined(SOMAXCONN) || (SOMAXCONN < 4096)
#undef SOMAXCONN
#define SOMAXCONN 4096
#endif

int set_nonblocking(int fd);
ssize_t write_all(int fd, const char *buf, size_t len);
ssize_t read_retry(int fd, char *buf, size_t len);
int connect_with_timeout_transparent(const char *ip, int port, int timeout_ms, const struct sockaddr_storage *client_addr);
int connect_nonblocking_transparent(const char *ip, int port, const struct sockaddr_storage *client_addr, bool *in_progress);
int create_tcp_server_socket(int port);
int create_udp_server_socket(int port);
void increase_fd_limit(void);
void get_client_ip_port(const struct sockaddr_storage *ss, char *ip_buf, size_t ip_len, int *port);

#endif /* ADVLB_NET_UTILS_H */

