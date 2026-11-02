#define _GNU_SOURCE
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

BackendServer g_backends[MAX_BACKENDS];
int g_num_backends = 0;
pthread_mutex_t g_backend_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_round_robin_index = 0;

const char *algorithm_name(BalancerAlgorithm alg) {
    switch (alg) {
        case ALG_ROUND_ROBIN:       return "Round-Robin";
        case ALG_LEAST_CONNECTIONS: return "Least-Connections";
        case ALG_IP_HASH:           return "IP-Hash (Sticky)";
        case ALG_LEAST_LATENCY:     return "Least-Latency (Fastest)";
        case ALG_WEIGHTED_RR:       return "Weighted Round-Robin";
        case ALG_RANDOM_2:          return "Random (Power-of-2)";
        default:                    return "Unknown";
    }
}

bool add_backend(const char *ip, int port, int weight) {
    pthread_mutex_lock(&g_backend_mutex);
    if (g_num_backends >= MAX_BACKENDS) {
        pthread_mutex_unlock(&g_backend_mutex);
        fprintf(stderr, "[WARN] Maximum backends limit reached (%d). '%s:%d' ignored.\n", MAX_BACKENDS, ip, port);
        return false;
    }
    int idx = g_num_backends;
    strncpy(g_backends[idx].ip, ip, sizeof(g_backends[idx].ip) - 1);
    g_backends[idx].ip[sizeof(g_backends[idx].ip) - 1] = '\0';
    g_backends[idx].port = port;
    g_backends[idx].weight = (weight > 0) ? weight : 1;
    g_backends[idx].current_weight = 0;
    g_backends[idx].is_alive = false;
    g_backends[idx].consecutive_failures = 0;
    g_backends[idx].consecutive_successes = 0;
    g_backends[idx].latency_ms = 0.0;
    atomic_init(&g_backends[idx].active_connections, 0);
    atomic_init(&g_backends[idx].total_requests_handled, 0);
    g_num_backends++;
    pthread_mutex_unlock(&g_backend_mutex);
    return true;
}

// 1. Round-Robin: sequential cyclic selection
static int select_backend_round_robin_locked(void) {
    for (int attempts = 0; attempts < g_num_backends; attempts++) {
        int idx = s_round_robin_index;
        s_round_robin_index = (s_round_robin_index + 1) % g_num_backends;
        if (g_backends[idx].is_alive) {
            return idx;
        }
    }
    return -1;
}

// 2. Least-Connections: select server with lowest active connection count
static int select_backend_least_connections_locked(void) {
    int best_index = -1;
    int min_connections = 1e9;

    for (int i = 0; i < g_num_backends; i++) {
        if (g_backends[i].is_alive) {
            int conns = atomic_load_explicit(&g_backends[i].active_connections, memory_order_relaxed);
            if (conns < min_connections) {
                min_connections = conns;
                best_index = i;
            }
        }
    }
    return best_index;
}

// 3. IP Hash: client IP sticky sessions with active backend fallback
static int select_backend_ip_hash_locked(const struct sockaddr_in *client_addr) {
    int healthy_list[MAX_BACKENDS];
    int healthy_count = 0;

    for (int i = 0; i < g_num_backends; i++) {
        if (g_backends[i].is_alive) {
            healthy_list[healthy_count++] = i;
        }
    }
    if (healthy_count == 0) return -1;

    // 32-bit FNV-1a hash algorithm on client IPv4 address
    uint32_t hash = 2166136261u;
    if (client_addr != NULL) {
        const unsigned char *p = (const unsigned char *)&(client_addr->sin_addr.s_addr);
        for (int i = 0; i < 4; i++) {
            hash ^= p[i];
            hash *= 16777619u;
        }
    }
    return healthy_list[hash % (uint32_t)healthy_count];
}

// 4. Least-Latency: route to server with lowest measured real-time RTT latency
static int select_backend_least_latency_locked(void) {
    int best_index = -1;
    double min_lat = 1e9;
    int min_conns = 1e9;

    for (int i = 0; i < g_num_backends; i++) {
        if (g_backends[i].is_alive) {
            int conns = atomic_load_explicit(&g_backends[i].active_connections, memory_order_relaxed);
            if (g_backends[i].latency_ms < min_lat - 0.1 ||
                (g_backends[i].latency_ms <= min_lat + 0.1 && conns < min_conns)) {
                min_lat = g_backends[i].latency_ms;
                min_conns = conns;
                best_index = i;
            }
        }
    }
    return best_index;
}

// 5. Smooth Weighted Round-Robin: weighted balancing algorithm
static int select_backend_weighted_rr_locked(void) {
    int best_index = -1;
    int total_weight = 0;

    for (int i = 0; i < g_num_backends; i++) {
        if (g_backends[i].is_alive) {
            g_backends[i].current_weight += g_backends[i].weight;
            total_weight += g_backends[i].weight;
            if (best_index == -1 || g_backends[i].current_weight > g_backends[best_index].current_weight) {
                best_index = i;
            }
        }
    }
    if (best_index != -1) {
        g_backends[best_index].current_weight -= total_weight;
    }
    return best_index;
}

// 6. Random (Power of Two Choices: pick 2 random nodes and route to the less loaded one)
static int select_backend_random_2_locked(void) {
    int healthy_list[MAX_BACKENDS];
    int healthy_count = 0;

    for (int i = 0; i < g_num_backends; i++) {
        if (g_backends[i].is_alive) {
            healthy_list[healthy_count++] = i;
        }
    }
    if (healthy_count == 0) return -1;
    if (healthy_count == 1) return healthy_list[0];

    int r1 = rand() % healthy_count;
    int r2 = rand() % healthy_count;
    if (r2 == r1) {
        r2 = (r1 + 1) % healthy_count;
    }

    int idx1 = healthy_list[r1];
    int idx2 = healthy_list[r2];
    int c1 = atomic_load_explicit(&g_backends[idx1].active_connections, memory_order_relaxed);
    int c2 = atomic_load_explicit(&g_backends[idx2].active_connections, memory_order_relaxed);
    return (c1 <= c2) ? idx1 : idx2;
}

int get_healthy_backend(const struct sockaddr_in *client_addr) {
    pthread_mutex_lock(&g_backend_mutex);
    int selected = -1;

    switch (g_config.current_algorithm) {
        case ALG_ROUND_ROBIN:
            selected = select_backend_round_robin_locked();
            break;
        case ALG_LEAST_CONNECTIONS:
            selected = select_backend_least_connections_locked();
            break;
        case ALG_IP_HASH:
            selected = select_backend_ip_hash_locked(client_addr);
            break;
        case ALG_LEAST_LATENCY:
            selected = select_backend_least_latency_locked();
            break;
        case ALG_WEIGHTED_RR:
            selected = select_backend_weighted_rr_locked();
            break;
        case ALG_RANDOM_2:
            selected = select_backend_random_2_locked();
            break;
    }

    if (selected >= 0) {
        atomic_fetch_add_explicit(&g_backends[selected].active_connections, 1, memory_order_relaxed);
        atomic_fetch_add_explicit(&g_backends[selected].total_requests_handled, 1, memory_order_relaxed);
    }
    pthread_mutex_unlock(&g_backend_mutex);
    return selected;
}

void release_backend(int index) {
    if (index >= 0 && index < g_num_backends) {
        int val = atomic_fetch_sub_explicit(&g_backends[index].active_connections, 1, memory_order_relaxed);
        if (val <= 0) {
            atomic_store_explicit(&g_backends[index].active_connections, 0, memory_order_relaxed);
        }
    }
}

void record_backend_failure(int index) {
    if (index >= 0 && index < g_num_backends) {
        pthread_mutex_lock(&g_backend_mutex);
        int val = atomic_fetch_sub_explicit(&g_backends[index].active_connections, 1, memory_order_relaxed);
        if (val <= 0) {
            atomic_store_explicit(&g_backends[index].active_connections, 0, memory_order_relaxed);
        }
        g_backends[index].consecutive_failures++;
        g_backends[index].consecutive_successes = 0;
        int fails = g_backends[index].consecutive_failures;
        if (fails >= FALL_THRESHOLD) {
            g_backends[index].is_alive = false;
        }
        char b_ip[INET_ADDRSTRLEN];
        int b_port = g_backends[index].port;
        strncpy(b_ip, g_backends[index].ip, sizeof(b_ip));
        pthread_mutex_unlock(&g_backend_mutex);

        add_log("\033[1;33m[CIRCUIT BREAKER]\033[0m Backend [%d] %s:%d conn error (fail %d/%d)",
                index, b_ip, b_port, fails, FALL_THRESHOLD);
    }
}

void reset_backend_stats(void) {
    pthread_mutex_lock(&g_backend_mutex);
    for (int i = 0; i < g_num_backends; i++) {
        atomic_store_explicit(&g_backends[i].total_requests_handled, 0, memory_order_relaxed);
    }
    pthread_mutex_unlock(&g_backend_mutex);
    add_log("\033[1;32m[STATS]\033[0m Request statistics reset.");
}

