#ifndef ADVLB_BALANCER_H
#define ADVLB_BALANCER_H

#include <stdbool.h>
#include <netinet/in.h>
#include <pthread.h>
#include "advlb/types.h"

extern BackendServer g_backends[MAX_BACKENDS];
extern int g_num_backends;
extern pthread_mutex_t g_backend_mutex;

const char *algorithm_name(BalancerAlgorithm alg);
bool add_backend(const char *ip, int port, int weight);
int get_healthy_backend(const struct sockaddr_storage *client_addr);
void release_backend(int index);
void record_backend_success(int index);
void record_backend_failure(int index);
void reset_backend_stats(void);

#endif /* ADVLB_BALANCER_H */

