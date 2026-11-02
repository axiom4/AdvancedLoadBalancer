#define _GNU_SOURCE
#include "advlb/udp_proxy.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/net_utils.h"
#include "advlb/compat_epoll.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX_UDP_SESSIONS 2048
#define UDP_HASH_BUCKETS 1024
#define MAX_UDP_SESSIONS_PER_IP 64

typedef struct UdpSession {
    bool in_use;
    struct sockaddr_in client_addr;
    int backend_idx;
    int backend_fd;
    time_t last_activity;
    int slot_id;
    struct UdpSession *hash_next;
} UdpSession;

static UdpSession s_udp_sessions[MAX_UDP_SESSIONS] = {{0}};
static UdpSession *s_hash_table[UDP_HASH_BUCKETS] = {NULL};
static pthread_mutex_t s_udp_session_mutex = PTHREAD_MUTEX_INITIALIZER;

static inline uint32_t udp_session_hash(const struct sockaddr_in *addr) {
    uint32_t h = (uint32_t)addr->sin_addr.s_addr ^ ((uint32_t)addr->sin_port * 2654435761u);
    return h % UDP_HASH_BUCKETS;
}

static void hash_insert(UdpSession *session) {
    uint32_t h = udp_session_hash(&session->client_addr);
    session->hash_next = s_hash_table[h];
    s_hash_table[h] = session;
}

static void hash_remove(UdpSession *session) {
    uint32_t h = udp_session_hash(&session->client_addr);
    UdpSession **curr = &s_hash_table[h];
    while (*curr) {
        if (*curr == session) {
            *curr = session->hash_next;
            session->hash_next = NULL;
            return;
        }
        curr = &((*curr)->hash_next);
    }
}

static UdpSession *hash_find(const struct sockaddr_in *client_addr) {
    uint32_t h = udp_session_hash(client_addr);
    UdpSession *curr = s_hash_table[h];
    while (curr) {
        if (curr->in_use &&
            curr->client_addr.sin_addr.s_addr == client_addr->sin_addr.s_addr &&
            curr->client_addr.sin_port == client_addr->sin_port) {
            return curr;
        }
        curr = curr->hash_next;
    }
    return NULL;
}

static UdpSession *find_or_create_udp_session(int epfd, const struct sockaddr_in *client_addr) {
    pthread_mutex_lock(&s_udp_session_mutex);
    time_t now = time(NULL);

    // Fast O(1) hash table lookup
    UdpSession *existing = hash_find(client_addr);
    if (existing) {
        if (atomic_load_explicit(&g_backends[existing->backend_idx].is_alive, memory_order_relaxed)) {
            existing->last_activity = now;
            pthread_mutex_unlock(&s_udp_session_mutex);
            return existing;
        }
        // Backend went DOWN: remove socket and reassign
        epoll_ctl(epfd, EPOLL_CTL_DEL, existing->backend_fd, NULL);
        close(existing->backend_fd);
        release_backend(existing->backend_idx);
        hash_remove(existing);
        existing->in_use = false;
    }

    int free_slot = -1;
    int oldest_slot = -1;
    time_t oldest_time = now + 1;
    int expired_slot = -1;
    time_t oldest_expired_time = now + 1;
    int ip_sessions = 0;

    // Single-pass scan: find free slot, count per-IP sessions, and identify LRU candidates
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        if (!s_udp_sessions[i].in_use) {
            if (free_slot == -1) free_slot = i;
        } else {
            if (s_udp_sessions[i].client_addr.sin_addr.s_addr == client_addr->sin_addr.s_addr) {
                ip_sessions++;
            }
            // Track absolute oldest for emergency LRU eviction under heavy flood
            if (s_udp_sessions[i].last_activity < oldest_time) {
                oldest_time = s_udp_sessions[i].last_activity;
                oldest_slot = i;
            }
            // Track oldest expired session (idle > timeout)
            if ((now - s_udp_sessions[i].last_activity) >= g_config.udp_session_timeout_sec) {
                if (s_udp_sessions[i].last_activity < oldest_expired_time) {
                    oldest_expired_time = s_udp_sessions[i].last_activity;
                    expired_slot = i;
                }
            }
        }
    }

    // 1. Enforce per-IP concurrent session limit (mitigates IP-spoofing / state exhaustion DoS)
    if (ip_sessions >= MAX_UDP_SESSIONS_PER_IP) {
        static time_t last_ip_drop = 0;
        if (now - last_ip_drop >= 2) {
            char c_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_addr->sin_addr), c_ip, sizeof(c_ip));
            add_log("\033[1;31m[UDP DROP]\033[0m Client %s exceeded per-IP session limit (%d)",
                    c_ip, MAX_UDP_SESSIONS_PER_IP);
            last_ip_drop = now;
        }
        pthread_mutex_unlock(&s_udp_session_mutex);
        return NULL;
    }

    // 2. Select slot to use: free slot, oldest expired slot, or emergency LRU eviction
    int slot_to_use = free_slot;
    if (slot_to_use == -1 && expired_slot != -1) {
        slot_to_use = expired_slot;
    } else if (slot_to_use == -1 && oldest_slot != -1) {
        slot_to_use = oldest_slot;
        static time_t last_evict = 0;
        if (now - last_evict >= 2) {
            add_log("\033[1;33m[UDP EVICT]\033[0m Table saturated (%d sessions): evicting LRU idle session",
                    MAX_UDP_SESSIONS);
            last_evict = now;
        }
    }

    if (slot_to_use == -1) {
        static time_t last_drop = 0;
        if (now - last_drop >= 2) {
            add_log("\033[1;31m[UDP DROP]\033[0m UDP session table full (max %d)", MAX_UDP_SESSIONS);
            last_drop = now;
        }
        pthread_mutex_unlock(&s_udp_session_mutex);
        return NULL;
    }

    // If recycling an in-use slot (expired or LRU evicted), cleanly close prior resources
    if (s_udp_sessions[slot_to_use].in_use) {
        epoll_ctl(epfd, EPOLL_CTL_DEL, s_udp_sessions[slot_to_use].backend_fd, NULL);
        close(s_udp_sessions[slot_to_use].backend_fd);
        release_backend(s_udp_sessions[slot_to_use].backend_idx);
        hash_remove(&s_udp_sessions[slot_to_use]);
        s_udp_sessions[slot_to_use].in_use = false;
    }

    free_slot = slot_to_use;

    int backend_idx = get_healthy_backend(client_addr);
    if (backend_idx < 0) {
        pthread_mutex_unlock(&s_udp_session_mutex);
        add_log("\033[1;31m[UDP DROP]\033[0m No healthy UDP backend available");
        return NULL;
    }

    char b_ip[INET_ADDRSTRLEN];
    int b_port;
    pthread_mutex_lock(&g_backend_mutex);
    strncpy(b_ip, g_backends[backend_idx].ip, sizeof(b_ip));
    b_port = g_backends[backend_idx].port;
    pthread_mutex_unlock(&g_backend_mutex);

    int bfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (bfd < 0) {
        release_backend(backend_idx);
        pthread_mutex_unlock(&s_udp_session_mutex);
        return NULL;
    }
    set_nonblocking(bfd);

    struct sockaddr_in b_addr;
    memset(&b_addr, 0, sizeof(b_addr));
    b_addr.sin_family = AF_INET;
    b_addr.sin_port = htons((uint16_t)b_port);
    inet_pton(AF_INET, b_ip, &b_addr.sin_addr);

    if (connect(bfd, (struct sockaddr *)&b_addr, sizeof(b_addr)) < 0) {
        close(bfd);
        release_backend(backend_idx);
        pthread_mutex_unlock(&s_udp_session_mutex);
        return NULL;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.fd = free_slot;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, bfd, &ev) < 0) {
        close(bfd);
        release_backend(backend_idx);
        pthread_mutex_unlock(&s_udp_session_mutex);
        return NULL;
    }

    s_udp_sessions[free_slot].in_use = true;
    s_udp_sessions[free_slot].slot_id = free_slot;
    s_udp_sessions[free_slot].client_addr = *client_addr;
    s_udp_sessions[free_slot].backend_idx = backend_idx;
    s_udp_sessions[free_slot].backend_fd = bfd;
    s_udp_sessions[free_slot].last_activity = now;
    hash_insert(&s_udp_sessions[free_slot]);

    char c_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), c_ip, sizeof(c_ip));
    add_log("\033[1;36m[UDP FLOW]\033[0m Client %s:%d -> Backend [%d] %s:%d",
            c_ip, ntohs(client_addr->sin_port), backend_idx, b_ip, b_port);

    UdpSession *ret = &s_udp_sessions[free_slot];
    pthread_mutex_unlock(&s_udp_session_mutex);
    return ret;
}

static void cleanup_expired_udp_sessions(int epfd) {
    pthread_mutex_lock(&s_udp_session_mutex);
    time_t now = time(NULL);
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        if (s_udp_sessions[i].in_use && (now - s_udp_sessions[i].last_activity) >= g_config.udp_session_timeout_sec) {
            epoll_ctl(epfd, EPOLL_CTL_DEL, s_udp_sessions[i].backend_fd, NULL);
            close(s_udp_sessions[i].backend_fd);
            release_backend(s_udp_sessions[i].backend_idx);
            hash_remove(&s_udp_sessions[i]);
            s_udp_sessions[i].in_use = false;

            char c_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(s_udp_sessions[i].client_addr.sin_addr), c_ip, sizeof(c_ip));
            add_log("\033[1;30m[UDP DISC]\033[0m UDP session expired for %s:%d (idle for %ds)",
                    c_ip, ntohs(s_udp_sessions[i].client_addr.sin_port), g_config.udp_session_timeout_sec);
        }
    }
    pthread_mutex_unlock(&s_udp_session_mutex);
}

void run_udp_proxy_loop(int master_udp_fd) {
    int epfd = epoll_create1(0);
    if (epfd < 0) {
        perror("epoll_create1 UDP");
        return;
    }

    struct epoll_event ev_master;
    ev_master.events = EPOLLIN | EPOLLERR;
    ev_master.data.fd = -1;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, master_udp_fd, &ev_master) < 0) {
        perror("epoll_ctl master_udp_fd");
        close(epfd);
        return;
    }

    char buffer[65536];
    struct epoll_event events[64];
    time_t last_cleanup = time(NULL);

    while (g_server_running) {
        int nfds = epoll_wait(epfd, events, 64, 1000);
        time_t now = time(NULL);

        if (now - last_cleanup >= 2) {
            cleanup_expired_udp_sessions(epfd);
            last_cleanup = now;
        }

        if (nfds < 0) {
            if (errno == EINTR) {
                if (!g_server_running) break;
                continue;
            }
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == -1) {
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    ssize_t bytes = recvfrom(master_udp_fd, buffer, sizeof(buffer), 0,
                                             (struct sockaddr *)&client_addr, &client_len);
                    if (bytes < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                        break;
                    }
                    if (bytes == 0) break;

                    UdpSession *session = find_or_create_udp_session(epfd, &client_addr);
                    if (session) {
                        send(session->backend_fd, buffer, (size_t)bytes, 0);
                    }
                }
            } else {
                int slot = events[i].data.fd;
                pthread_mutex_lock(&s_udp_session_mutex);
                if (slot >= 0 && slot < MAX_UDP_SESSIONS && s_udp_sessions[slot].in_use) {
                    UdpSession *session = &s_udp_sessions[slot];
                    while (1) {
                        ssize_t bytes = read(session->backend_fd, buffer, sizeof(buffer));
                        if (bytes < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                            break;
                        }
                        if (bytes == 0) break;

                        session->last_activity = now;
                        sendto(master_udp_fd, buffer, (size_t)bytes, 0,
                               (struct sockaddr *)&(session->client_addr), sizeof(session->client_addr));
                    }
                }
                pthread_mutex_unlock(&s_udp_session_mutex);
            }
        }
    }

    pthread_mutex_lock(&s_udp_session_mutex);
    for (int i = 0; i < MAX_UDP_SESSIONS; i++) {
        if (s_udp_sessions[i].in_use) {
            close(s_udp_sessions[i].backend_fd);
            release_backend(s_udp_sessions[i].backend_idx);
            s_udp_sessions[i].in_use = false;
        }
    }
    memset(s_hash_table, 0, sizeof(s_hash_table));
    pthread_mutex_unlock(&s_udp_session_mutex);

    close(epfd);
}

