#define _GNU_SOURCE
#include "advlb/conn_pool.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/balancer.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

static BackendPool s_backend_pools[MAX_BACKENDS];
static bool s_pool_initialized = false;
static pthread_mutex_t s_pool_init_lock = PTHREAD_MUTEX_INITIALIZER;

void conn_pool_init(void) {
    pthread_mutex_lock(&s_pool_init_lock);
    if (!s_pool_initialized) {
        for (int i = 0; i < MAX_BACKENDS; i++) {
            s_backend_pools[i].count = 0;
            pthread_mutex_init(&s_backend_pools[i].lock, NULL);
        }
        s_pool_initialized = true;
    }
    pthread_mutex_unlock(&s_pool_init_lock);
}

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

// Checks if a socket is still alive, open, and has no stale pending data
static bool is_socket_healthy(int fd) {
    if (fd < 0) return false;

    int so_error = 0;
    socklen_t len = sizeof(so_error);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &len) < 0 || so_error != 0) {
        return false;
    }

    // Verify socket is not half-closed for writing (EPIPE guard)
    if (send(fd, "", 0, MSG_DONTWAIT | MSG_NOSIGNAL) < 0) {
        if (errno == EPIPE || errno == ENOTCONN || errno == ECONNRESET) {
            return false;
        }
    }

    char peek_buf[1];
    ssize_t ret = recv(fd, peek_buf, 1, MSG_PEEK | MSG_DONTWAIT);
    if (ret == 0) {
        // Remote closed connection (FIN / EOF)
        return false;
    }
    if (ret > 0) {
        // Stale unread data remaining from prior session
        return false;
    }
    // ret < 0
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Socket is ready, connected, with no pending bytes: healthy!
        return true;
    }
    return false;
}

int conn_pool_acquire(int backend_idx) {
    if (!g_config.enable_upstream_pooling) return -1;
    if (backend_idx < 0 || backend_idx >= MAX_BACKENDS) return -1;

    conn_pool_init();
    BackendPool *bp = &s_backend_pools[backend_idx];
    time_t now = time(NULL);
    int max_idle = (g_config.upstream_pool_idle_sec > 0) ? g_config.upstream_pool_idle_sec : DEFAULT_POOL_MAX_IDLE_SEC;

    pthread_mutex_lock(&bp->lock);
    while (bp->count > 0) {
        // Pop the most recently used connection (LIFO for cache warmth and lower probability of timeout)
        bp->count--;
        int fd = bp->items[bp->count].fd;
        time_t idle_since = bp->items[bp->count].idle_since;

        // 1. Check idle timeout
        if (now - idle_since > max_idle) {
            close(fd);
            continue;
        }

        // 2. Check backend is still marked alive
        if (!atomic_load_explicit(&g_backends[backend_idx].is_alive, memory_order_relaxed)) {
            close(fd);
            continue;
        }

        // 3. Check socket health
        if (!is_socket_healthy(fd)) {
            close(fd);
            continue;
        }

        // Found valid pooled connection!
        pthread_mutex_unlock(&bp->lock);
        add_log("\033[1;32m[POOL HIT]\033[0m Reused pooled upstream socket fd=%d for backend [%d]",
                fd, backend_idx);
        return fd;
    }
    pthread_mutex_unlock(&bp->lock);
    return -1;
}

bool conn_pool_release(int backend_idx, int fd) {
    if (!g_config.enable_upstream_pooling || fd < 0) {
        if (fd >= 0) close(fd);
        return false;
    }
    if (backend_idx < 0 || backend_idx >= MAX_BACKENDS) {
        close(fd);
        return false;
    }

    // Verify backend is alive and socket is still valid
    if (!atomic_load_explicit(&g_backends[backend_idx].is_alive, memory_order_relaxed) ||
        !is_socket_healthy(fd)) {
        close(fd);
        return false;
    }

    conn_pool_init();
    BackendPool *bp = &s_backend_pools[backend_idx];
    int max_cap = (g_config.upstream_pool_size > 0 && g_config.upstream_pool_size <= MAX_POOLED_CONNS_PER_BACKEND)
                      ? g_config.upstream_pool_size
                      : MAX_POOLED_CONNS_PER_BACKEND;

    pthread_mutex_lock(&bp->lock);
    if (bp->count >= max_cap) {
        // Pool is full, close socket
        pthread_mutex_unlock(&bp->lock);
        close(fd);
        return false;
    }

    bp->items[bp->count].fd = fd;
    bp->items[bp->count].idle_since = time(NULL);
    bp->count++;
    pthread_mutex_unlock(&bp->lock);

    add_log("\033[1;34m[POOL STORE]\033[0m Socket fd=%d stored in upstream pool for backend [%d] (pool count: %d)",
            fd, backend_idx, bp->count);
    return true;
}

void conn_pool_purge_backend(int backend_idx) {
    if (backend_idx < 0 || backend_idx >= MAX_BACKENDS) return;
    conn_pool_init();
    BackendPool *bp = &s_backend_pools[backend_idx];

    pthread_mutex_lock(&bp->lock);
    for (int i = 0; i < bp->count; i++) {
        if (bp->items[i].fd >= 0) {
            close(bp->items[i].fd);
            bp->items[i].fd = -1;
        }
    }
    bp->count = 0;
    pthread_mutex_unlock(&bp->lock);
}

void conn_pool_cleanup_expired(int max_idle_sec) {
    if (max_idle_sec <= 0) max_idle_sec = DEFAULT_POOL_MAX_IDLE_SEC;
    conn_pool_init();
    time_t now = time(NULL);

    for (int b = 0; b < MAX_BACKENDS; b++) {
        BackendPool *bp = &s_backend_pools[b];
        pthread_mutex_lock(&bp->lock);
        int write_idx = 0;
        for (int i = 0; i < bp->count; i++) {
            if ((now - bp->items[i].idle_since) > max_idle_sec || !is_socket_healthy(bp->items[i].fd)) {
                close(bp->items[i].fd);
            } else {
                if (write_idx != i) {
                    bp->items[write_idx] = bp->items[i];
                }
                write_idx++;
            }
        }
        bp->count = write_idx;
        pthread_mutex_unlock(&bp->lock);
    }
}

void conn_pool_destroy(void) {
    for (int b = 0; b < MAX_BACKENDS; b++) {
        conn_pool_purge_backend(b);
    }
}

int conn_pool_get_total_idle(void) {
    int total = 0;
    for (int b = 0; b < MAX_BACKENDS; b++) {
        BackendPool *bp = &s_backend_pools[b];
        pthread_mutex_lock(&bp->lock);
        total += bp->count;
        pthread_mutex_unlock(&bp->lock);
    }
    return total;
}

int conn_pool_get_backend_idle(int backend_idx) {
    if (backend_idx < 0 || backend_idx >= MAX_BACKENDS) return 0;
    BackendPool *bp = &s_backend_pools[backend_idx];
    pthread_mutex_lock(&bp->lock);
    int c = bp->count;
    pthread_mutex_unlock(&bp->lock);
    return c;
}

