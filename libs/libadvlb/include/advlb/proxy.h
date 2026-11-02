#ifndef ADVLB_PROXY_H
#define ADVLB_PROXY_H

#include "advlb/compat_ssl.h"

void forward_traffic_dual_epoll(int client_fd, SSL *client_ssl, int backend_fd);
void *client_handler_thread(void *arg);

#endif /* ADVLB_PROXY_H */

