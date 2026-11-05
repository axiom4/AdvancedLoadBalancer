#ifndef ADVLB_PROXY_H
#define ADVLB_PROXY_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "advlb/compat_ssl.h"
#include "advlb/tcp_repair.h"

bool worker_pool_init(int num_workers);
void worker_pool_dispatch(int client_fd, const struct sockaddr_storage *client_addr);
void worker_pool_adopt_migrated_conn(int client_fd,
                                     int backend_fd,
                                     int backend_idx,
                                     const struct sockaddr_storage *client_addr,
                                     const char *initial_req,
                                     uint16_t req_len,
                                     uint64_t bytes_to_client,
                                     MigratedStreamState *migrated /* owned; NULL = client socket only */);
void worker_pool_handover_active_conns(void);
void worker_pool_resync_live_conns(void);
void worker_pool_shutdown(void);

void forward_traffic_dual_epoll(int client_fd, SSL *client_ssl, int backend_fd);
void *client_handler_thread(void *arg);

#endif /* ADVLB_PROXY_H */

