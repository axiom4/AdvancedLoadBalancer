#ifndef ADVLB_CONN_POOL_H
#define ADVLB_CONN_POOL_H

#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include "advlb/types.h"

#define MAX_POOLED_CONNS_PER_BACKEND 32
#define DEFAULT_POOL_MAX_IDLE_SEC 30

typedef struct {
    int fd;
    time_t idle_since;
} PooledSocket;

typedef struct {
    PooledSocket items[MAX_POOLED_CONNS_PER_BACKEND];
    int count;
    pthread_mutex_t lock;
} BackendPool;

void conn_pool_init(void);
int conn_pool_acquire(int backend_idx);
bool conn_pool_release(int backend_idx, int fd);
void conn_pool_purge_backend(int backend_idx);
void conn_pool_cleanup_expired(int max_idle_sec);
void conn_pool_destroy(void);
int conn_pool_get_total_idle(void);
int conn_pool_get_backend_idle(int backend_idx);

#endif /* ADVLB_CONN_POOL_H */

