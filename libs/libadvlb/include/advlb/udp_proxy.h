#ifndef ADVLB_UDP_PROXY_H
#define ADVLB_UDP_PROXY_H

#include <stdbool.h>

bool udp_worker_pool_start(int num_workers, int port);
void udp_worker_pool_stop(void);
void run_udp_proxy_loop(int master_udp_fd);

#endif /* ADVLB_UDP_PROXY_H */
