#define _GNU_SOURCE
#include "advlb/udp_proxy.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/net_utils.h"
#include "advlb/compat_epoll.h"
#include "advlb/session_table.h"
#include "advlb/cluster.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define MAX_UDP_WORKERS 32
#define MAX_UDP_SESSIONS_PER_WORKER 2048
#define UDP_HASH_BUCKETS_PER_WORKER 1024
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

typedef struct UdpWorker {
    int id;
    int port;
    int server_fd;
    int epfd;
    pthread_t thread;
    volatile bool running;

    UdpSession sessions[MAX_UDP_SESSIONS_PER_WORKER];
    UdpSession *hash_table[UDP_HASH_BUCKETS_PER_WORKER];
    pthread_mutex_t mutex;
} UdpWorker;

static UdpWorker s_udp_workers[MAX_UDP_WORKERS];
static int s_num_udp_workers = 0;
static volatile bool s_udp_pool_active = false;

static inline uint32_t udp_session_hash(const struct sockaddr_in *addr) {
    uint32_t h = (uint32_t)addr->sin_addr.s_addr ^ ((uint32_t)addr->sin_port * 2654435761u);
    return h % UDP_HASH_BUCKETS_PER_WORKER;
}

static void worker_hash_insert(UdpWorker *w, UdpSession *session) {
    uint32_t h = udp_session_hash(&session->client_addr);
    session->hash_next = w->hash_table[h];
    w->hash_table[h] = session;
}

static void worker_hash_remove(UdpWorker *w, UdpSession *session) {
    uint32_t h = udp_session_hash(&session->client_addr);
    UdpSession **curr = &w->hash_table[h];
    while (*curr) {
        if (*curr == session) {
            *curr = session->hash_next;
            session->hash_next = NULL;
            return;
        }
        curr = &((*curr)->hash_next);
    }
}

static UdpSession *worker_hash_find(UdpWorker *w, const struct sockaddr_in *client_addr) {
    uint32_t h = udp_session_hash(client_addr);
    UdpSession *curr = w->hash_table[h];
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

static UdpSession *worker_find_or_create_session(UdpWorker *w, const struct sockaddr_in *client_addr) {
    pthread_mutex_lock(&w->mutex);
    time_t now = time(NULL);

    UdpSession *existing = worker_hash_find(w, client_addr);
    if (existing) {
        if (atomic_load_explicit(&g_backends[existing->backend_idx].is_alive, memory_order_relaxed)) {
            existing->last_activity = now;
            pthread_mutex_unlock(&w->mutex);
            return existing;
        }
        // Backend went DOWN: remove socket and reassign
        epoll_ctl(w->epfd, EPOLL_CTL_DEL, existing->backend_fd, NULL);
        close(existing->backend_fd);
        release_backend(existing->backend_idx);
        worker_hash_remove(w, existing);
        existing->in_use = false;
    }

    int free_slot = -1;
    int oldest_slot = -1;
    time_t oldest_time = now + 1;
    int expired_slot = -1;
    time_t oldest_expired_time = now + 1;
    int ip_sessions = 0;

    for (int i = 0; i < MAX_UDP_SESSIONS_PER_WORKER; i++) {
        if (!w->sessions[i].in_use) {
            if (free_slot == -1) free_slot = i;
        } else {
            if (w->sessions[i].client_addr.sin_addr.s_addr == client_addr->sin_addr.s_addr) {
                ip_sessions++;
            }
            if (w->sessions[i].last_activity < oldest_time) {
                oldest_time = w->sessions[i].last_activity;
                oldest_slot = i;
            }
            if ((now - w->sessions[i].last_activity) >= g_config.udp_session_timeout_sec) {
                if (w->sessions[i].last_activity < oldest_expired_time) {
                    oldest_expired_time = w->sessions[i].last_activity;
                    expired_slot = i;
                }
            }
        }
    }

    // 1. Enforce per-IP concurrent session limit
    if (ip_sessions >= MAX_UDP_SESSIONS_PER_IP) {
        static time_t last_ip_drop = 0;
        if (now - last_ip_drop >= 2) {
            char c_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(client_addr->sin_addr), c_ip, sizeof(c_ip));
            add_log("\033[1;31m[UDP DROP]\033[0m Client %s exceeded per-IP session limit (%d)",
                    c_ip, MAX_UDP_SESSIONS_PER_IP);
            last_ip_drop = now;
        }
        pthread_mutex_unlock(&w->mutex);
        return NULL;
    }

    // 2. Select slot to use
    int slot_to_use = free_slot;
    if (slot_to_use == -1 && expired_slot != -1) {
        slot_to_use = expired_slot;
    } else if (slot_to_use == -1 && oldest_slot != -1) {
        slot_to_use = oldest_slot;
    }

    if (slot_to_use == -1) {
        pthread_mutex_unlock(&w->mutex);
        return NULL;
    }

    if (w->sessions[slot_to_use].in_use) {
        epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->sessions[slot_to_use].backend_fd, NULL);
        close(w->sessions[slot_to_use].backend_fd);
        release_backend(w->sessions[slot_to_use].backend_idx);
        worker_hash_remove(w, &w->sessions[slot_to_use]);
        w->sessions[slot_to_use].in_use = false;
    }

    free_slot = slot_to_use;

    struct sockaddr_storage client_ss;
    memset(&client_ss, 0, sizeof(client_ss));
    memcpy(&client_ss, client_addr, sizeof(struct sockaddr_in));

    int backend_idx = -1;
    if (g_config.enable_cluster || g_config.enable_session_stickiness) {
        backend_idx = session_table_lookup(&client_ss, SESSION_PROTO_UDP, true);
        if (backend_idx >= 0 && backend_idx < g_num_backends) {
            atomic_fetch_add_explicit(&g_backends[backend_idx].active_connections, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&g_backends[backend_idx].total_requests_handled, 1, memory_order_relaxed);
        } else {
            backend_idx = -1;
        }
    }
    if (backend_idx < 0) {
        backend_idx = get_healthy_backend(&client_ss);
    }
    if (backend_idx < 0) {
        pthread_mutex_unlock(&w->mutex);
        return NULL;
    }

    char b_ip[INET6_ADDRSTRLEN];
    int b_port;
    pthread_mutex_lock(&g_backend_mutex);
    strncpy(b_ip, g_backends[backend_idx].ip, sizeof(b_ip));
    b_port = g_backends[backend_idx].port;
    pthread_mutex_unlock(&g_backend_mutex);

    struct in6_addr a6;
    bool is_v6 = (inet_pton(AF_INET6, b_ip, &a6) == 1);

    int bfd = socket(is_v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, 0);
    if (bfd < 0) {
        release_backend(backend_idx);
        pthread_mutex_unlock(&w->mutex);
        return NULL;
    }
    set_nonblocking(bfd);

    int cr;
    if (is_v6) {
        struct sockaddr_in6 b_addr6;
        memset(&b_addr6, 0, sizeof(b_addr6));
        b_addr6.sin6_family = AF_INET6;
        b_addr6.sin6_port = htons((uint16_t)b_port);
        b_addr6.sin6_addr = a6;
        cr = connect(bfd, (struct sockaddr *)&b_addr6, sizeof(b_addr6));
    } else {
        struct sockaddr_in b_addr;
        memset(&b_addr, 0, sizeof(b_addr));
        b_addr.sin_family = AF_INET;
        b_addr.sin_port = htons((uint16_t)b_port);
        inet_pton(AF_INET, b_ip, &b_addr.sin_addr);
        cr = connect(bfd, (struct sockaddr *)&b_addr, sizeof(b_addr));
    }

    if (cr < 0) {
        close(bfd);
        release_backend(backend_idx);
        pthread_mutex_unlock(&w->mutex);
        return NULL;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.fd = free_slot;
    if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, bfd, &ev) < 0) {
        close(bfd);
        release_backend(backend_idx);
        pthread_mutex_unlock(&w->mutex);
        return NULL;
    }

    w->sessions[free_slot].in_use = true;
    w->sessions[free_slot].slot_id = free_slot;
    w->sessions[free_slot].client_addr = *client_addr;
    w->sessions[free_slot].backend_idx = backend_idx;
    w->sessions[free_slot].backend_fd = bfd;
    w->sessions[free_slot].last_activity = now;
    worker_hash_insert(w, &w->sessions[free_slot]);

    if (g_config.enable_cluster || g_config.enable_session_stickiness) {
        session_table_upsert_local(&client_ss, SESSION_PROTO_UDP, true, backend_idx,
                                   (uint32_t)g_config.udp_session_timeout_sec, g_config.enable_cluster);
    }

    char c_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr->sin_addr), c_ip, sizeof(c_ip));
    add_log("\033[1;36m[UDP FLOW]\033[0m Client %s:%d -> Backend [%d] %s:%d (Worker %d)",
            c_ip, ntohs(client_addr->sin_port), backend_idx, b_ip, b_port, w->id);

    UdpSession *ret = &w->sessions[free_slot];
    pthread_mutex_unlock(&w->mutex);
    return ret;
}

static void worker_cleanup_expired_sessions(UdpWorker *w) {
    pthread_mutex_lock(&w->mutex);
    time_t now = time(NULL);
    for (int i = 0; i < MAX_UDP_SESSIONS_PER_WORKER; i++) {
        if (w->sessions[i].in_use && (now - w->sessions[i].last_activity) >= g_config.udp_session_timeout_sec) {
            epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->sessions[i].backend_fd, NULL);
            close(w->sessions[i].backend_fd);
            release_backend(w->sessions[i].backend_idx);
            worker_hash_remove(w, &w->sessions[i]);
            w->sessions[i].in_use = false;
        }
    }
    pthread_mutex_unlock(&w->mutex);
}

static void *udp_worker_thread_func(void *arg) {
    UdpWorker *w = (UdpWorker *)arg;

    char buffer[65536];
    struct epoll_event events[64];
    time_t last_cleanup = time(NULL);

    while (w->running && g_server_running) {
        if (g_config.enable_cluster) {
            if (cluster_get_state() == VRRP_STATE_MASTER) {
                if (w->server_fd < 0) {
                    w->server_fd = create_udp_server_socket(w->port);
                    if (w->server_fd >= 0) {
                        struct epoll_event ev_server;
                        ev_server.events = EPOLLIN | EPOLLERR;
                        ev_server.data.fd = -1;
                        epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->server_fd, &ev_server);
                    }
                }
            } else {
                if (w->server_fd >= 0) {
                    epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->server_fd, NULL);
                    close(w->server_fd);
                    w->server_fd = -1;
                }
            }
        }

        int nfds = epoll_wait(w->epfd, events, 64, 100);
        time_t now = time(NULL);

        if (g_reload_requested) {
            g_reload_requested = 0;
            add_log("\033[1;36m[SYSTEM]\033[0m SIGHUP received: reloading configuration...");
            config_reload();
        }

        if (now - last_cleanup >= 2) {
            worker_cleanup_expired_sessions(w);
            last_cleanup = now;
        }

        if (nfds < 0) {
            if (errno == EINTR) {
                if (!g_server_running || !w->running) break;
                continue;
            }
            break;
        }

        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == -1) {
                // Incoming client datagram on worker server_fd
                while (1) {
                    struct sockaddr_in client_addr;
                    socklen_t client_len = sizeof(client_addr);
                    ssize_t bytes = recvfrom(w->server_fd, buffer, sizeof(buffer), 0,
                                             (struct sockaddr *)&client_addr, &client_len);
                    if (bytes < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                        break;
                    }
                    if (bytes == 0) break;

                    UdpSession *session = worker_find_or_create_session(w, &client_addr);
                    if (session) {
                        send(session->backend_fd, buffer, (size_t)bytes, 0);
                    }
                }
            } else {
                // Response datagram from backend
                int slot = events[i].data.fd;
                pthread_mutex_lock(&w->mutex);
                if (slot >= 0 && slot < MAX_UDP_SESSIONS_PER_WORKER && w->sessions[slot].in_use) {
                    UdpSession *session = &w->sessions[slot];
                    while (1) {
                        ssize_t bytes = read(session->backend_fd, buffer, sizeof(buffer));
                        if (bytes < 0) {
                            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
                            break;
                        }
                        if (bytes == 0) break;

                        session->last_activity = now;
                        if (w->server_fd >= 0) {
                            sendto(w->server_fd, buffer, (size_t)bytes, 0,
                                   (struct sockaddr *)&(session->client_addr), sizeof(session->client_addr));
                        }
                    }
                }
                pthread_mutex_unlock(&w->mutex);
            }
        }
    }

    // Cleanup worker sessions on thread exit
    pthread_mutex_lock(&w->mutex);
    for (int i = 0; i < MAX_UDP_SESSIONS_PER_WORKER; i++) {
        if (w->sessions[i].in_use) {
            close(w->sessions[i].backend_fd);
            release_backend(w->sessions[i].backend_idx);
            w->sessions[i].in_use = false;
        }
    }
    memset(w->hash_table, 0, sizeof(w->hash_table));
    pthread_mutex_unlock(&w->mutex);

    return NULL;
}

bool udp_worker_pool_start(int num_workers, int port) {
    if (num_workers <= 0) num_workers = 1;
    if (num_workers > MAX_UDP_WORKERS) num_workers = MAX_UDP_WORKERS;

    s_num_udp_workers = num_workers;

    for (int i = 0; i < num_workers; i++) {
        UdpWorker *w = &s_udp_workers[i];
        memset(w, 0, sizeof(UdpWorker));
        w->id = i;
        w->port = port;
        pthread_mutex_init(&w->mutex, NULL);

        w->epfd = epoll_create1(0);
        if (w->epfd < 0) {
            udp_worker_pool_stop();
            return false;
        }

        w->server_fd = -1;
        if (!g_config.enable_cluster) {
            w->server_fd = create_udp_server_socket(port);
            if (w->server_fd < 0) {
                fprintf(stderr, "\033[1;31m[ERROR]\033[0m Failed to bind SO_REUSEPORT UDP socket for worker %d on port %d\n", i, port);
                close(w->epfd);
                w->epfd = -1;
                udp_worker_pool_stop();
                return false;
            }

            struct epoll_event ev_server;
            ev_server.events = EPOLLIN | EPOLLERR;
            ev_server.data.fd = -1; // -1 represents the listening worker server_fd
            if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->server_fd, &ev_server) < 0) {
                close(w->server_fd);
                close(w->epfd);
                w->server_fd = -1;
                w->epfd = -1;
                udp_worker_pool_stop();
                return false;
            }
        }

        w->running = true;
        if (pthread_create(&w->thread, NULL, udp_worker_thread_func, w) != 0) {
            w->running = false;
            close(w->server_fd);
            close(w->epfd);
            udp_worker_pool_stop();
            return false;
        }
    }

    s_udp_pool_active = true;
    return true;
}

void udp_worker_pool_stop(void) {
    if (!s_udp_pool_active) return;
    s_udp_pool_active = false;

    for (int i = 0; i < s_num_udp_workers; i++) {
        UdpWorker *w = &s_udp_workers[i];
        w->running = false;
        if (w->server_fd >= 0) {
            close(w->server_fd);
            w->server_fd = -1;
        }
        pthread_join(w->thread, NULL);
        if (w->epfd >= 0) {
            close(w->epfd);
            w->epfd = -1;
        }
        pthread_mutex_destroy(&w->mutex);
    }
    s_num_udp_workers = 0;
}

void run_udp_proxy_loop(int master_udp_fd) {
    // Backwards compatible single-thread fallback
    UdpWorker w;
    memset(&w, 0, sizeof(UdpWorker));
    w.id = 0;
    w.server_fd = master_udp_fd;
    pthread_mutex_init(&w.mutex, NULL);
    w.epfd = epoll_create1(0);
    if (w.epfd < 0) return;

    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLERR;
    ev.data.fd = -1;
    epoll_ctl(w.epfd, EPOLL_CTL_ADD, master_udp_fd, &ev);

    w.running = true;
    udp_worker_thread_func(&w);

    close(w.epfd);
    pthread_mutex_destroy(&w.mutex);
}
