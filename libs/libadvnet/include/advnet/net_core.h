#ifndef ADVNET_CORE_H
#define ADVNET_CORE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#if !defined(SOMAXCONN) || (SOMAXCONN < 4096)
#undef SOMAXCONN
#define SOMAXCONN 4096
#endif

// Server socket creation
int net_create_tcp_server(int port, int backlog);
int net_create_udp_server(int port);

// Client connection with timeout and IP transparency support
int net_connect_tcp_timeout(const char *ip, int port, int timeout_ms,
                            const struct sockaddr_storage *bind_client_addr,
                            bool enable_transparent);
int net_connect_tcp_nonblocking(const char *ip, int port,
                                const struct sockaddr_storage *bind_client_addr,
                                bool enable_transparent,
                                bool *in_progress);

// Socket options tuning
int net_set_nonblocking(int fd);
int net_set_nodelay(int fd, int enable);
int net_set_timeouts(int fd, int timeout_sec);
int net_set_reuse(int fd, int reuse_addr, int reuse_port);
int net_set_keepalive(int fd, int enable);

// IP address validation (IPv4 and IPv6)
bool net_validate_ipv4(const char *ip);
bool net_validate_ip(const char *ip);

#ifdef __cplusplus
}
#endif

#endif /* ADVNET_CORE_H */

