#ifndef ADVLB_PROXY_H
#define ADVLB_PROXY_H

#include <stdbool.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "advlb/compat_ssl.h"

bool worker_pool_init(int num_workers);
void worker_pool_dispatch(int client_fd, const struct sockaddr_storage *client_addr);
void worker_pool_shutdown(void);

void forward_traffic_dual_epoll(int client_fd, SSL *client_ssl, int backend_fd);
void *client_handler_thread(void *arg);

#endif /* ADVLB_PROXY_H */

