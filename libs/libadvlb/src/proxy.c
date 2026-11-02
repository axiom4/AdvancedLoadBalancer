#define _GNU_SOURCE
#include "advlb/proxy.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/net_utils.h"
#include "advlb/proxy_proto.h"
#include "advlb/compat_epoll.h"
#include "advlb/ssl_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <pthread.h>

#define MAX_WORKER_EVENTS 64
#define INITIAL_FD_TABLE_CAP 1024

typedef struct {
    char data[BUFFER_SIZE];
    size_t head; // read index for sending
    size_t tail; // write index for receiving
} StreamBuffer;

static inline size_t buffer_available(const StreamBuffer *sb) {
    return sb->tail - sb->head;
}

static inline size_t buffer_space(const StreamBuffer *sb) {
    return BUFFER_SIZE - sb->tail;
}

static inline void buffer_compact(StreamBuffer *sb) {
    if (sb->head > 0) {
        size_t avail = sb->tail - sb->head;
        if (avail > 0) {
            memmove(sb->data, sb->data + sb->head, avail);
        }
        sb->head = 0;
        sb->tail = avail;
    }
}

// Sends non-blocking data to plain socket or SSL
static ssize_t nonblocking_write(int fd, SSL *ssl, const char *buf, size_t len, bool *out_want_io) {
    *out_want_io = false;
    if (len == 0) return 0;

    if (ssl) {
        int w = SSL_write(ssl, buf, (int)len);
        if (w > 0) return w;
        int err = SSL_get_error(ssl, w);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            *out_want_io = true;
            return 0; // Temporarily busy, wait for event
        }
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
            *out_want_io = true;
            return 0;
        }
        return -1; // Fatal SSL error
    }

    while (1) {
        ssize_t w = send(fd, buf, len, 0);
        if (w >= 0) return w;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *out_want_io = true;
            return 0; // Socket buffer full, wait for EPOLLOUT
        }
        return -1; // Fatal socket error
    }
}

// Reads non-blocking data from plain socket or SSL
static ssize_t nonblocking_read(int fd, SSL *ssl, char *buf, size_t max_len, bool *out_want_io) {
    *out_want_io = false;
    if (max_len == 0) return 0;

    if (ssl) {
        int r = SSL_read(ssl, buf, (int)max_len);
        if (r > 0) return r;
        if (r == 0) return 0; // Connection closed normally
        int err = SSL_get_error(ssl, r);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            *out_want_io = true;
            return 0; // No immediate data, wait for event
        }
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
            *out_want_io = true;
            return 0;
        }
        return -1; // Fatal SSL error
    }

    while (1) {
        ssize_t r = recv(fd, buf, max_len, 0);
        if (r >= 0) return r;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            *out_want_io = true;
            return 0; // No data currently in kernel buffer
        }
        return -1; // Fatal socket error
    }
}

/* ============================================================================
 * WORKER POOL ARCHITECTURE (Epoll Event-Loop per Worker)
 * ============================================================================ */

typedef enum {
    CONN_STATE_SSL_HANDSHAKE,
    CONN_STATE_FORWARDING
} ConnectionState;

struct WorkerThread;

typedef struct ProxyConnection {
    int client_fd;
    int backend_fd;
    int backend_idx;
    int retry_count;
    ConnectionState state;

    struct sockaddr_in client_addr;
    SSL *client_ssl;

    StreamBuffer c2b; // client to backend
    StreamBuffer b2c; // backend to client

    bool client_closed;
    bool backend_closed;
    bool backend_shut_wr;
    bool client_shut_wr;

    uint32_t last_client_ev;
    uint32_t last_backend_ev;

    time_t last_activity;
    time_t hs_start;

    struct WorkerThread *worker;
    struct ProxyConnection *prev;
    struct ProxyConnection *next;
} ProxyConnection;

typedef struct NewConnNode {
    int client_fd;
    struct sockaddr_in client_addr;
    struct NewConnNode *next;
} NewConnNode;

typedef struct WorkerThread {
    int id;
    pthread_t thread;
    int epfd;
    int notify_pipe[2];

    pthread_mutex_t queue_mutex;
    NewConnNode *queue_head;
    NewConnNode *queue_tail;

    ProxyConnection *conn_list_head;
    int active_conn_count;

    ProxyConnection **fd_table;
    int fd_table_cap;
} WorkerThread;

static WorkerThread *s_workers = NULL;
static int s_num_workers = 0;
static atomic_int s_next_worker = 0;

/* Helper prototypes */
static void worker_set_fd(WorkerThread *worker, int fd, ProxyConnection *conn);
static ProxyConnection *worker_get_fd(WorkerThread *worker, int fd);
static void worker_clear_fd(WorkerThread *worker, int fd);
static void worker_add_conn(WorkerThread *worker, ProxyConnection *conn);
static void worker_remove_conn(WorkerThread *worker, ProxyConnection *conn);
static void worker_close_conn(WorkerThread *worker, ProxyConnection *conn);
static void worker_update_conn_epoll(WorkerThread *worker, ProxyConnection *conn);
static void worker_on_backend_connected(WorkerThread *worker, ProxyConnection *conn);
static void worker_start_backend_connect(WorkerThread *worker, ProxyConnection *conn);
static void worker_step_ssl_handshake(WorkerThread *worker, ProxyConnection *conn);
static void worker_handle_forwarding_io(WorkerThread *worker, ProxyConnection *conn, int fd, uint32_t events);
static void worker_check_timeouts(WorkerThread *worker);
static void worker_process_new_conns(WorkerThread *worker);
static void *worker_event_loop(void *arg);

static void worker_set_fd(WorkerThread *worker, int fd, ProxyConnection *conn) {
    if (fd < 0) return;
    if (fd >= worker->fd_table_cap) {
        int new_cap = (fd + 1) * 2;
        if (new_cap < INITIAL_FD_TABLE_CAP) new_cap = INITIAL_FD_TABLE_CAP;
        ProxyConnection **new_tbl = realloc(worker->fd_table, (size_t)new_cap * sizeof(ProxyConnection *));
        if (!new_tbl) return;
        for (int i = worker->fd_table_cap; i < new_cap; i++) {
            new_tbl[i] = NULL;
        }
        worker->fd_table = new_tbl;
        worker->fd_table_cap = new_cap;
    }
    worker->fd_table[fd] = conn;
}

static inline ProxyConnection *worker_get_fd(WorkerThread *worker, int fd) {
    if (fd < 0 || fd >= worker->fd_table_cap) return NULL;
    return worker->fd_table[fd];
}

static inline void worker_clear_fd(WorkerThread *worker, int fd) {
    if (fd >= 0 && fd < worker->fd_table_cap) {
        worker->fd_table[fd] = NULL;
    }
}

static void worker_add_conn(WorkerThread *worker, ProxyConnection *conn) {
    conn->prev = NULL;
    conn->next = worker->conn_list_head;
    if (worker->conn_list_head) {
        worker->conn_list_head->prev = conn;
    }
    worker->conn_list_head = conn;
    worker->active_conn_count++;
}

static void worker_remove_conn(WorkerThread *worker, ProxyConnection *conn) {
    if (conn->prev) {
        conn->prev->next = conn->next;
    } else {
        worker->conn_list_head = conn->next;
    }
    if (conn->next) {
        conn->next->prev = conn->prev;
    }
    conn->prev = NULL;
    conn->next = NULL;
    worker->active_conn_count--;
}

static void worker_close_conn(WorkerThread *worker, ProxyConnection *conn) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(conn->client_addr.sin_addr), client_ip, sizeof(client_ip));
    int client_port = ntohs(conn->client_addr.sin_port);

    if (conn->backend_fd >= 0) {
        epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->backend_fd, NULL);
        worker_clear_fd(worker, conn->backend_fd);
        close(conn->backend_fd);
        conn->backend_fd = -1;
    }

    if (conn->backend_idx >= 0) {
        release_backend(conn->backend_idx);
        conn->backend_idx = -1;
    }

    if (conn->client_fd >= 0) {
        epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->client_fd, NULL);
        worker_clear_fd(worker, conn->client_fd);
        if (conn->client_ssl) {
            SSL_shutdown(conn->client_ssl);
            SSL_free(conn->client_ssl);
            conn->client_ssl = NULL;
        }
        close(conn->client_fd);
        conn->client_fd = -1;
    }

    add_log("\033[1;30m[DISC]\033[0m Connection closed for client %s:%d", client_ip, client_port);

    worker_remove_conn(worker, conn);
    free(conn);
    atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
}

static void worker_update_conn_epoll(WorkerThread *worker, ProxyConnection *conn) {
    if (conn->state != CONN_STATE_FORWARDING) return;

    // Configure client epoll interest mask (Automatic Backpressure)
    uint32_t client_mask = 0;
    if (!conn->client_closed && buffer_space(&conn->c2b) > 0) client_mask |= EPOLLIN;
    if (buffer_available(&conn->b2c) > 0) client_mask |= EPOLLOUT;
    if (client_mask != 0) client_mask |= (EPOLLERR | EPOLLHUP);

    if (client_mask != conn->last_client_ev) {
        if (client_mask == 0) {
            if (conn->last_client_ev != 0) {
                epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->client_fd, NULL);
                conn->last_client_ev = 0;
            }
        } else {
            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.data.fd = conn->client_fd;
            ev.events = client_mask;
            if (conn->last_client_ev == 0) {
                epoll_ctl(worker->epfd, EPOLL_CTL_ADD, conn->client_fd, &ev);
            } else {
                epoll_ctl(worker->epfd, EPOLL_CTL_MOD, conn->client_fd, &ev);
            }
            conn->last_client_ev = client_mask;
        }
    }

    // Configure backend epoll interest mask (Automatic Backpressure)
    if (conn->backend_fd >= 0) {
        uint32_t backend_mask = 0;
        if (!conn->backend_closed && buffer_space(&conn->b2c) > 0) backend_mask |= EPOLLIN;
        if (buffer_available(&conn->c2b) > 0) backend_mask |= EPOLLOUT;
        if (backend_mask != 0) backend_mask |= (EPOLLERR | EPOLLHUP);

        if (backend_mask != conn->last_backend_ev) {
            if (backend_mask == 0) {
                if (conn->last_backend_ev != 0) {
                    epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->backend_fd, NULL);
                    conn->last_backend_ev = 0;
                }
            } else {
                struct epoll_event ev;
                memset(&ev, 0, sizeof(ev));
                ev.data.fd = conn->backend_fd;
                ev.events = backend_mask;
                if (conn->last_backend_ev == 0) {
                    epoll_ctl(worker->epfd, EPOLL_CTL_ADD, conn->backend_fd, &ev);
                } else {
                    epoll_ctl(worker->epfd, EPOLL_CTL_MOD, conn->backend_fd, &ev);
                }
                conn->last_backend_ev = backend_mask;
            }
        }
    }
}

static void worker_on_backend_connected(WorkerThread *worker, ProxyConnection *conn) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(conn->client_addr.sin_addr), client_ip, sizeof(client_ip));
    int client_port = ntohs(conn->client_addr.sin_port);

    char b_ip[INET_ADDRSTRLEN];
    int b_port;
    pthread_mutex_lock(&g_backend_mutex);
    strncpy(b_ip, g_backends[conn->backend_idx].ip, sizeof(b_ip));
    b_port = g_backends[conn->backend_idx].port;
    pthread_mutex_unlock(&g_backend_mutex);

    add_log("\033[1;36m[CONN]\033[0m Client %s:%d %s -> Backend [%d] %s:%d (Worker %d)",
            client_ip, client_port,
            g_config.enable_ssl_offloading ? "\033[1;35m(TLS)\033[0m" : "",
            conn->backend_idx, b_ip, b_port, worker->id);

    // If PROXY Protocol v1 is enabled towards backend, prepend header to c2b buffer
    if (g_config.enable_proxy_protocol_v1) {
        struct sockaddr_in lb_addr;
        socklen_t lb_len = sizeof(lb_addr);
        if (getsockname(conn->client_fd, (struct sockaddr *)&lb_addr, &lb_len) != 0) {
            memset(&lb_addr, 0, sizeof(lb_addr));
            lb_addr.sin_family = AF_INET;
            lb_addr.sin_port = htons((uint16_t)g_config.listen_port);
        }
        char pp_hdr[128];
        int pp_len = build_proxy_protocol_v1_header(pp_hdr, sizeof(pp_hdr), &conn->client_addr, &lb_addr);
        if (pp_len > 0) {
            size_t space = buffer_space(&conn->c2b);
            if ((size_t)pp_len <= space) {
                memcpy(conn->c2b.data + conn->c2b.tail, pp_hdr, (size_t)pp_len);
                conn->c2b.tail += (size_t)pp_len;
            } else {
                add_log("\033[1;31m[PPv1 ERR]\033[0m Buffer full, failed prepending PROXY v1 header");
            }
        }
    }

    conn->state = CONN_STATE_FORWARDING;
    conn->last_activity = time(NULL);

    // Attempt immediate non-blocking flush of any pending c2b data
    if (buffer_available(&conn->c2b) > 0) {
        bool want_io = false;
        ssize_t w = nonblocking_write(conn->backend_fd, NULL,
                                      conn->c2b.data + conn->c2b.head, buffer_available(&conn->c2b), &want_io);
        if (w > 0) {
            conn->c2b.head += (size_t)w;
        } else if (w < 0) {
            worker_close_conn(worker, conn);
            return;
        }
    }

    worker_update_conn_epoll(worker, conn);
}

static void worker_start_backend_connect(WorkerThread *worker, ProxyConnection *conn) {
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(conn->client_addr.sin_addr), client_ip, sizeof(client_ip));
    int client_port = ntohs(conn->client_addr.sin_port);

    while (conn->retry_count < g_num_backends) {
        conn->retry_count++;
        int b_idx = get_healthy_backend(&conn->client_addr);
        if (b_idx < 0) {
            break;
        }

        char b_ip[INET_ADDRSTRLEN];
        int b_port;
        pthread_mutex_lock(&g_backend_mutex);
        strncpy(b_ip, g_backends[b_idx].ip, sizeof(b_ip));
        b_port = g_backends[b_idx].port;
        pthread_mutex_unlock(&g_backend_mutex);

        int bfd = connect_with_timeout_transparent(b_ip, b_port, 1000, &conn->client_addr);
        if (bfd >= 0) {
            conn->backend_idx = b_idx;
            conn->backend_fd = bfd;
            set_nonblocking(bfd);
            int flag = 1;
            setsockopt(bfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
            worker_set_fd(worker, bfd, conn);
            worker_on_backend_connected(worker, conn);
            return;
        }

        record_backend_failure(b_idx);
    }

    add_log("\033[1;31m[DROP]\033[0m No healthy backend available for %s:%d", client_ip, client_port);
    worker_close_conn(worker, conn);
}

static void worker_step_ssl_handshake(WorkerThread *worker, ProxyConnection *conn) {
    while (g_server_running) {
        int acc_res = SSL_accept(conn->client_ssl);
        if (acc_res > 0) {
            conn->last_activity = time(NULL);
            worker_start_backend_connect(worker, conn);
            return;
        }

        int err = SSL_get_error(conn->client_ssl, acc_res);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            uint32_t needed = (err == SSL_ERROR_WANT_READ) ? (EPOLLIN | EPOLLERR | EPOLLHUP) : (EPOLLOUT | EPOLLERR | EPOLLHUP);
            if (needed != conn->last_client_ev) {
                struct epoll_event ev;
                memset(&ev, 0, sizeof(ev));
                ev.data.fd = conn->client_fd;
                ev.events = needed;
                if (conn->last_client_ev == 0) {
                    epoll_ctl(worker->epfd, EPOLL_CTL_ADD, conn->client_fd, &ev);
                } else {
                    epoll_ctl(worker->epfd, EPOLL_CTL_MOD, conn->client_fd, &ev);
                }
                conn->last_client_ev = needed;
            }
            return;
        }
        if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
            continue;
        }

        worker_close_conn(worker, conn);
        return;
    }
}

static void worker_handle_forwarding_io(WorkerThread *worker, ProxyConnection *conn, int fd, uint32_t events) {
    time_t now = time(NULL);

    if (events & EPOLLERR) {
        worker_close_conn(worker, conn);
        return;
    }

    // Events on CLIENT socket
    if (fd == conn->client_fd) {
        if (events & EPOLLIN) {
            buffer_compact(&conn->c2b);
            size_t space = buffer_space(&conn->c2b);
            if (space > 0) {
                bool want_io = false;
                ssize_t r = nonblocking_read(conn->client_fd, conn->client_ssl,
                                             conn->c2b.data + conn->c2b.tail, space, &want_io);
                if (r > 0) {
                    conn->c2b.tail += (size_t)r;
                    conn->last_activity = now;
                } else if (r == 0 && !want_io) {
                    conn->client_closed = true;
                } else if (r < 0) {
                    worker_close_conn(worker, conn);
                    return;
                }
            }
        }

        if (events & EPOLLOUT) {
            if (buffer_available(&conn->b2c) > 0) {
                bool want_io = false;
                ssize_t w = nonblocking_write(conn->client_fd, conn->client_ssl,
                                              conn->b2c.data + conn->b2c.head, buffer_available(&conn->b2c), &want_io);
                if (w > 0) {
                    conn->b2c.head += (size_t)w;
                    conn->last_activity = now;
                } else if (w < 0) {
                    worker_close_conn(worker, conn);
                    return;
                }
            }
        }

        if ((events & EPOLLHUP) && !(events & EPOLLIN)) {
            conn->client_closed = true;
        }
    }

    // Events on BACKEND socket
    if (fd == conn->backend_fd) {
        if (events & EPOLLIN) {
            buffer_compact(&conn->b2c);
            size_t space = buffer_space(&conn->b2c);
            if (space > 0) {
                bool want_io = false;
                ssize_t r = nonblocking_read(conn->backend_fd, NULL,
                                             conn->b2c.data + conn->b2c.tail, space, &want_io);
                if (r > 0) {
                    conn->b2c.tail += (size_t)r;
                    conn->last_activity = now;
                } else if (r == 0 && !want_io) {
                    conn->backend_closed = true;
                } else if (r < 0) {
                    worker_close_conn(worker, conn);
                    return;
                }
            }
        }

        if (events & EPOLLOUT) {
            if (buffer_available(&conn->c2b) > 0) {
                bool want_io = false;
                ssize_t w = nonblocking_write(conn->backend_fd, NULL,
                                              conn->c2b.data + conn->c2b.head, buffer_available(&conn->c2b), &want_io);
                if (w > 0) {
                    conn->c2b.head += (size_t)w;
                    conn->last_activity = now;
                } else if (w < 0) {
                    worker_close_conn(worker, conn);
                    return;
                }
            }
        }

        if ((events & EPOLLHUP) && !(events & EPOLLIN)) {
            conn->backend_closed = true;
        }
    }

    // Immediate flush attempt for c2b to backend
    if (conn->backend_fd >= 0 && buffer_available(&conn->c2b) > 0) {
        bool want_io = false;
        ssize_t w = nonblocking_write(conn->backend_fd, NULL,
                                      conn->c2b.data + conn->c2b.head, buffer_available(&conn->c2b), &want_io);
        if (w > 0) {
            conn->c2b.head += (size_t)w;
            conn->last_activity = now;
        } else if (w < 0) {
            worker_close_conn(worker, conn);
            return;
        }
    }

    // Immediate flush attempt for b2c to client
    if (conn->client_fd >= 0 && buffer_available(&conn->b2c) > 0) {
        bool want_io = false;
        ssize_t w = nonblocking_write(conn->client_fd, conn->client_ssl,
                                      conn->b2c.data + conn->b2c.head, buffer_available(&conn->b2c), &want_io);
        if (w > 0) {
            conn->b2c.head += (size_t)w;
            conn->last_activity = now;
        } else if (w < 0) {
            worker_close_conn(worker, conn);
            return;
        }
    }

    // Check half-close completion (send FIN exactly once per direction)
    if (conn->client_closed && buffer_available(&conn->c2b) == 0 && !conn->backend_shut_wr) {
        if (conn->backend_fd >= 0) shutdown(conn->backend_fd, SHUT_WR);
        conn->backend_shut_wr = true;
    }
    if (conn->backend_closed && buffer_available(&conn->b2c) == 0 && !conn->client_shut_wr) {
        if (conn->client_ssl) {
            SSL_shutdown(conn->client_ssl);
        } else if (conn->client_fd >= 0) {
            shutdown(conn->client_fd, SHUT_WR);
        }
        conn->client_shut_wr = true;
    }

    // If both closed and buffers drained, terminate connection gracefully
    if (conn->client_closed && conn->backend_closed &&
        buffer_available(&conn->c2b) == 0 && buffer_available(&conn->b2c) == 0) {
        worker_close_conn(worker, conn);
        return;
    }

    worker_update_conn_epoll(worker, conn);
}

static void worker_check_timeouts(WorkerThread *worker) {
    time_t now = time(NULL);
    int timeout_sec = g_config.inactivity_timeout_sec > 0 ? g_config.inactivity_timeout_sec : 30;

    ProxyConnection *curr = worker->conn_list_head;
    while (curr) {
        ProxyConnection *next = curr->next;
        if (now - curr->last_activity >= timeout_sec) {
            add_log("\033[1;33m[TIMEOUT]\033[0m Connection closed due to inactivity (>%ds) Slowloris protection",
                    timeout_sec);
            worker_close_conn(worker, curr);
        } else if (curr->state == CONN_STATE_SSL_HANDSHAKE && (now - curr->hs_start >= 5)) {
            add_log("\033[1;33m[TIMEOUT]\033[0m SSL handshake timeout (>5s)");
            worker_close_conn(worker, curr);
        }
        curr = next;
    }
}

static void worker_accept_connection(WorkerThread *worker, int client_fd, const struct sockaddr_in *client_addr) {
    set_nonblocking(client_fd);
    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    ProxyConnection *conn = calloc(1, sizeof(ProxyConnection));
    if (!conn) {
        close(client_fd);
        atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
        return;
    }

    conn->client_fd = client_fd;
    conn->backend_fd = -1;
    conn->backend_idx = -1;
    conn->client_addr = *client_addr;
    conn->last_activity = time(NULL);
    conn->worker = worker;

    // Check if PROXY Protocol v1 is expected from upstream client
    if (g_config.enable_accept_proxy) {
        struct sockaddr_in real_addr = *client_addr;
        if (parse_proxy_protocol_v1(client_fd, &real_addr)) {
            conn->client_addr = real_addr;
            add_log("\033[1;35m[PPv1 IN]\033[0m Decoded real client IP: %s:%d",
                    inet_ntoa(conn->client_addr.sin_addr), ntohs(conn->client_addr.sin_port));
        } else {
            add_log("\033[1;31m[PPv1 ERR]\033[0m Connection rejected: missing or invalid PROXY v1 header");
            close(client_fd);
            free(conn);
            atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
            return;
        }
    }

    worker_set_fd(worker, client_fd, conn);
    worker_add_conn(worker, conn);

    if (g_config.enable_ssl_offloading) {
        conn->client_ssl = SSL_new(g_global_ssl_ctx);
        if (!conn->client_ssl) {
            worker_close_conn(worker, conn);
            return;
        }
        SSL_set_fd(conn->client_ssl, client_fd);
        conn->state = CONN_STATE_SSL_HANDSHAKE;
        conn->hs_start = time(NULL);

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = client_fd;
        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
        conn->last_client_ev = ev.events;
        epoll_ctl(worker->epfd, EPOLL_CTL_ADD, client_fd, &ev);

        worker_step_ssl_handshake(worker, conn);
    } else {
        worker_start_backend_connect(worker, conn);
    }
}

static void worker_process_new_conns(WorkerThread *worker) {
    char dummy[128];
    while (read(worker->notify_pipe[0], dummy, sizeof(dummy)) > 0);

    pthread_mutex_lock(&worker->queue_mutex);
    NewConnNode *node = worker->queue_head;
    worker->queue_head = NULL;
    worker->queue_tail = NULL;
    pthread_mutex_unlock(&worker->queue_mutex);

    while (node) {
        NewConnNode *next = node->next;
        worker_accept_connection(worker, node->client_fd, &node->client_addr);
        free(node);
        node = next;
    }
}

static void *worker_event_loop(void *arg) {
    WorkerThread *worker = (WorkerThread *)arg;
    struct epoll_event events[MAX_WORKER_EVENTS];
    time_t last_timeout_check = time(NULL);

    while (g_server_running) {
        // Priority drain of pending data in OpenSSL internal buffers
        ProxyConnection *c = worker->conn_list_head;
        while (c) {
            ProxyConnection *next_c = c->next;
            if (c->state == CONN_STATE_FORWARDING && c->client_ssl && !c->client_closed && SSL_pending(c->client_ssl) > 0) {
                buffer_compact(&c->c2b);
                size_t space = buffer_space(&c->c2b);
                if (space > 0) {
                    bool want_io = false;
                    ssize_t r = nonblocking_read(c->client_fd, c->client_ssl,
                                                 c->c2b.data + c->c2b.tail, space, &want_io);
                    if (r > 0) {
                        c->c2b.tail += (size_t)r;
                        c->last_activity = time(NULL);
                        if (c->backend_fd >= 0 && buffer_available(&c->c2b) > 0) {
                            ssize_t w = nonblocking_write(c->backend_fd, NULL,
                                                          c->c2b.data + c->c2b.head, buffer_available(&c->c2b), &want_io);
                            if (w > 0) {
                                c->c2b.head += (size_t)w;
                            } else if (w < 0) {
                                worker_close_conn(worker, c);
                                c = next_c;
                                continue;
                            }
                        }
                    } else if (r < 0) {
                        worker_close_conn(worker, c);
                        c = next_c;
                        continue;
                    }
                }
            }
            c = next_c;
        }

        int nfds = epoll_wait(worker->epfd, events, MAX_WORKER_EVENTS, 1000);
        time_t now = time(NULL);

        if (now - last_timeout_check >= 1) {
            worker_check_timeouts(worker);
            last_timeout_check = now;
        }

        if (nfds < 0) {
            if (errno == EINTR) {
                if (!g_server_running) break;
                continue;
            }
            break;
        }

        for (int i = 0; i < nfds; i++) {
            int curr_fd = events[i].data.fd;
            uint32_t ev_mask = events[i].events;

            if (curr_fd == worker->notify_pipe[0]) {
                worker_process_new_conns(worker);
                continue;
            }

            ProxyConnection *conn = worker_get_fd(worker, curr_fd);
            if (!conn) continue;

            if (conn->state == CONN_STATE_SSL_HANDSHAKE) {
                worker_step_ssl_handshake(worker, conn);
            } else if (conn->state == CONN_STATE_FORWARDING) {
                worker_handle_forwarding_io(worker, conn, curr_fd, ev_mask);
            }
        }
    }

    // Shutdown cleanup of active connections
    while (worker->conn_list_head) {
        worker_close_conn(worker, worker->conn_list_head);
    }

    return NULL;
}

bool worker_pool_init(int num_workers) {
    if (num_workers <= 0) num_workers = 4;
    s_workers = calloc((size_t)num_workers, sizeof(WorkerThread));
    if (!s_workers) return false;
    s_num_workers = num_workers;

    for (int i = 0; i < num_workers; i++) {
        WorkerThread *w = &s_workers[i];
        w->id = i;
        w->epfd = epoll_create1(0);
        if (w->epfd < 0) return false;

        if (pipe(w->notify_pipe) < 0) return false;
        set_nonblocking(w->notify_pipe[0]);
        set_nonblocking(w->notify_pipe[1]);

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = w->notify_pipe[0];
        ev.events = EPOLLIN;
        if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->notify_pipe[0], &ev) < 0) {
            return false;
        }

        pthread_mutex_init(&w->queue_mutex, NULL);

        if (pthread_create(&w->thread, NULL, worker_event_loop, w) != 0) {
            return false;
        }
    }

    add_log("\033[1;32m[SYSTEM]\033[0m Initialized epoll worker pool with %d threads", num_workers);
    return true;
}

void worker_pool_dispatch(int client_fd, const struct sockaddr_in *client_addr) {
    if (s_num_workers <= 0 || !s_workers) {
        close(client_fd);
        atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
        return;
    }

    int idx = (int)((unsigned int)atomic_fetch_add_explicit(&s_next_worker, 1, memory_order_relaxed) % (unsigned int)s_num_workers);
    WorkerThread *worker = &s_workers[idx];

    NewConnNode *node = malloc(sizeof(NewConnNode));
    if (!node) {
        close(client_fd);
        atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
        return;
    }
    node->client_fd = client_fd;
    node->client_addr = *client_addr;
    node->next = NULL;

    pthread_mutex_lock(&worker->queue_mutex);
    if (worker->queue_tail) {
        worker->queue_tail->next = node;
        worker->queue_tail = node;
    } else {
        worker->queue_head = node;
        worker->queue_tail = node;
    }
    pthread_mutex_unlock(&worker->queue_mutex);

    // Notify worker event loop
    char signal_byte = 'c';
    (void)write(worker->notify_pipe[1], &signal_byte, 1);
}

void worker_pool_shutdown(void) {
    if (!s_workers) return;
    for (int i = 0; i < s_num_workers; i++) {
        WorkerThread *w = &s_workers[i];
        char c = 'q';
        (void)write(w->notify_pipe[1], &c, 1);
        pthread_join(w->thread, NULL);

        close(w->notify_pipe[0]);
        close(w->notify_pipe[1]);
        close(w->epfd);

        pthread_mutex_destroy(&w->queue_mutex);
        if (w->fd_table) free(w->fd_table);

        NewConnNode *n = w->queue_head;
        while (n) {
            NewConnNode *tmp = n->next;
            close(n->client_fd);
            free(n);
            n = tmp;
        }
    }
    free(s_workers);
    s_workers = NULL;
    s_num_workers = 0;
}

/* ============================================================================
 * LEGACY / DIRECT COMPATIBILITY FUNCTIONS
 * ============================================================================ */

void forward_traffic_dual_epoll(int client_fd, SSL *client_ssl, int backend_fd) {
    set_nonblocking(client_fd);
    set_nonblocking(backend_fd);

    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    setsockopt(backend_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    int epfd = epoll_create1(0);
    if (epfd < 0) return;

    StreamBuffer c2b = { .head = 0, .tail = 0 };
    StreamBuffer b2c = { .head = 0, .tail = 0 };

    bool client_closed = false;
    bool backend_closed = false;
    bool backend_shut_wr = false;
    bool client_shut_wr = false;

    uint32_t last_client_ev = 0;
    uint32_t last_backend_ev = 0;

    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.data.fd = client_fd;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    last_client_ev = ev.events;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        close(epfd);
        return;
    }

    ev.data.fd = backend_fd;
    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
    last_backend_ev = ev.events;
    if (epoll_ctl(epfd, EPOLL_CTL_ADD, backend_fd, &ev) < 0) {
        close(epfd);
        return;
    }

    struct epoll_event events[4];
    time_t last_activity = time(NULL);
    int timeout_sec = g_config.inactivity_timeout_sec > 0 ? g_config.inactivity_timeout_sec : 30;

    while (g_server_running) {
        if (client_ssl && !client_closed && SSL_pending(client_ssl) > 0) {
            buffer_compact(&c2b);
            size_t space = buffer_space(&c2b);
            if (space > 0) {
                bool want_io = false;
                ssize_t r = nonblocking_read(client_fd, client_ssl, c2b.data + c2b.tail, space, &want_io);
                if (r > 0) {
                    c2b.tail += (size_t)r;
                    last_activity = time(NULL);
                }
            }
        }

        if (buffer_available(&c2b) > 0) {
            bool want_io = false;
            ssize_t w = nonblocking_write(backend_fd, NULL, c2b.data + c2b.head, buffer_available(&c2b), &want_io);
            if (w > 0) {
                c2b.head += (size_t)w;
                last_activity = time(NULL);
            } else if (w < 0) {
                break;
            }
        }

        if (buffer_available(&b2c) > 0) {
            bool want_io = false;
            ssize_t w = nonblocking_write(client_fd, client_ssl, b2c.data + b2c.head, buffer_available(&b2c), &want_io);
            if (w > 0) {
                b2c.head += (size_t)w;
                last_activity = time(NULL);
            } else if (w < 0) {
                break;
            }
        }

        if (client_closed && buffer_available(&c2b) == 0 && !backend_shut_wr) {
            shutdown(backend_fd, SHUT_WR);
            backend_shut_wr = true;
        }
        if (backend_closed && buffer_available(&b2c) == 0 && !client_shut_wr) {
            if (client_ssl) {
                SSL_shutdown(client_ssl);
            } else {
                shutdown(client_fd, SHUT_WR);
            }
            client_shut_wr = true;
        }
        if (client_closed && backend_closed && buffer_available(&c2b) == 0 && buffer_available(&b2c) == 0) {
            break;
        }

        uint32_t client_mask = EPOLLERR | EPOLLHUP;
        if (!client_closed && buffer_space(&c2b) > 0) client_mask |= EPOLLIN;
        if (buffer_available(&b2c) > 0) client_mask |= EPOLLOUT;

        if (client_mask != last_client_ev) {
            ev.data.fd = client_fd;
            ev.events = client_mask;
            epoll_ctl(epfd, EPOLL_CTL_MOD, client_fd, &ev);
            last_client_ev = client_mask;
        }

        uint32_t backend_mask = EPOLLERR | EPOLLHUP;
        if (!backend_closed && buffer_space(&b2c) > 0) backend_mask |= EPOLLIN;
        if (buffer_available(&c2b) > 0) backend_mask |= EPOLLOUT;

        if (backend_mask != last_backend_ev) {
            ev.data.fd = backend_fd;
            ev.events = backend_mask;
            epoll_ctl(epfd, EPOLL_CTL_MOD, backend_fd, &ev);
            last_backend_ev = backend_mask;
        }

        int nfds = epoll_wait(epfd, events, 4, 1000);
        time_t now = time(NULL);

        if (now - last_activity >= timeout_sec) {
            add_log("\033[1;33m[TIMEOUT]\033[0m Connection closed due to inactivity (>%ds) Slowloris protection",
                    timeout_sec);
            break;
        }

        if (nfds < 0) {
            if (errno == EINTR) {
                if (!g_server_running) break;
                continue;
            }
            break;
        }

        bool fatal_err = false;
        for (int i = 0; i < nfds; i++) {
            int curr_fd = events[i].data.fd;
            uint32_t ev_mask = events[i].events;

            if (ev_mask & EPOLLERR) {
                fatal_err = true;
                break;
            }

            if (curr_fd == client_fd) {
                if (ev_mask & EPOLLIN) {
                    buffer_compact(&c2b);
                    size_t space = buffer_space(&c2b);
                    if (space > 0) {
                        bool want_io = false;
                        ssize_t r = nonblocking_read(client_fd, client_ssl, c2b.data + c2b.tail, space, &want_io);
                        if (r > 0) {
                            c2b.tail += (size_t)r;
                            last_activity = now;
                        } else if (r == 0 && !want_io) {
                            client_closed = true;
                        } else if (r < 0) {
                            fatal_err = true;
                            break;
                        }
                    }
                }

                if (ev_mask & EPOLLOUT) {
                    if (buffer_available(&b2c) > 0) {
                        bool want_io = false;
                        ssize_t w = nonblocking_write(client_fd, client_ssl, b2c.data + b2c.head, buffer_available(&b2c), &want_io);
                        if (w > 0) {
                            b2c.head += (size_t)w;
                            last_activity = now;
                        } else if (w < 0) {
                            fatal_err = true;
                            break;
                        }
                    }
                }

                if ((ev_mask & EPOLLHUP) && !(ev_mask & EPOLLIN)) {
                    client_closed = true;
                }
            }

            if (curr_fd == backend_fd) {
                if (ev_mask & EPOLLIN) {
                    buffer_compact(&b2c);
                    size_t space = buffer_space(&b2c);
                    if (space > 0) {
                        bool want_io = false;
                        ssize_t r = nonblocking_read(backend_fd, NULL, b2c.data + b2c.tail, space, &want_io);
                        if (r > 0) {
                            b2c.tail += (size_t)r;
                            last_activity = now;
                        } else if (r == 0 && !want_io) {
                            backend_closed = true;
                        } else if (r < 0) {
                            fatal_err = true;
                            break;
                        }
                    }
                }

                if (ev_mask & EPOLLOUT) {
                    if (buffer_available(&c2b) > 0) {
                        bool want_io = false;
                        ssize_t w = nonblocking_write(backend_fd, NULL, c2b.data + c2b.head, buffer_available(&c2b), &want_io);
                        if (w > 0) {
                            c2b.head += (size_t)w;
                            last_activity = now;
                        } else if (w < 0) {
                            fatal_err = true;
                            break;
                        }
                    }
                }

                if ((ev_mask & EPOLLHUP) && !(ev_mask & EPOLLIN)) {
                    backend_closed = true;
                }
            }
        }

        if (fatal_err) break;
    }

    close(epfd);
}

void *client_handler_thread(void *arg) {
    ClientContext *ctx = (ClientContext *)arg;
    int client_fd = ctx->client_fd;
    struct sockaddr_in client_addr = ctx->client_addr;
    free(ctx);

    if (g_config.enable_accept_proxy) {
        struct sockaddr_in real_client_addr = client_addr;
        if (parse_proxy_protocol_v1(client_fd, &real_client_addr)) {
            client_addr = real_client_addr;
            add_log("\033[1;35m[PPv1 IN]\033[0m Decoded real client IP: %s:%d",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        } else {
            add_log("\033[1;31m[PPv1 ERR]\033[0m Connection rejected: missing or invalid PROXY v1 header");
            close(client_fd);
            goto cleanup;
        }
    }

    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, sizeof(client_ip));
    int client_port = ntohs(client_addr.sin_port);

    SSL *client_ssl = NULL;

    if (g_config.enable_ssl_offloading) {
        client_ssl = SSL_new(g_global_ssl_ctx);
        if (!client_ssl) {
            close(client_fd);
            goto cleanup;
        }

        SSL_set_fd(client_ssl, client_fd);

        int ep = epoll_create1(0);
        if (ep < 0) {
            SSL_free(client_ssl);
            close(client_fd);
            goto cleanup;
        }

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = client_fd;
        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
        if (epoll_ctl(ep, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
            close(ep);
            SSL_free(client_ssl);
            close(client_fd);
            goto cleanup;
        }
        uint32_t current_events = ev.events;

        bool handshake_ok = false;
        time_t hs_start = time(NULL);
        const int hs_timeout_ms = 5000;

        while (g_server_running) {
            int acc_res = SSL_accept(client_ssl);
            if (acc_res > 0) {
                handshake_ok = true;
                break;
            }
            int err = SSL_get_error(client_ssl, acc_res);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                int elapsed_ms = (int)((time(NULL) - hs_start) * 1000);
                int remaining_ms = hs_timeout_ms - elapsed_ms;
                if (remaining_ms <= 0) break;

                uint32_t needed_events = (err == SSL_ERROR_WANT_READ) ? (EPOLLIN | EPOLLERR | EPOLLHUP) : (EPOLLOUT | EPOLLERR | EPOLLHUP);
                if (needed_events != current_events) {
                    ev.events = needed_events;
                    if (epoll_ctl(ep, EPOLL_CTL_MOD, client_fd, &ev) < 0) {
                        break;
                    }
                    current_events = needed_events;
                }

                struct epoll_event rev;
                int wait_res = epoll_wait(ep, &rev, 1, remaining_ms);
                if (wait_res < 0) {
                    if (errno == EINTR) continue;
                    break;
                }
                if (wait_res == 0) break;
                continue;
            }
            if (err == SSL_ERROR_SYSCALL && errno == EINTR) {
                continue;
            }
            break;
        }

        close(ep);

        if (!handshake_ok) {
            SSL_free(client_ssl);
            close(client_fd);
            goto cleanup;
        }
    }

    int backend_idx = -1;
    int backend_fd = -1;

    for (int retry = 0; retry < g_num_backends; retry++) {
        backend_idx = get_healthy_backend(&client_addr);
        if (backend_idx < 0) break;

        char b_ip[INET_ADDRSTRLEN];
        int b_port;
        pthread_mutex_lock(&g_backend_mutex);
        strncpy(b_ip, g_backends[backend_idx].ip, sizeof(b_ip));
        b_port = g_backends[backend_idx].port;
        pthread_mutex_unlock(&g_backend_mutex);

        backend_fd = connect_with_timeout_transparent(b_ip, b_port, 1000, &client_addr);
        if (backend_fd >= 0) {
            add_log("\033[1;36m[CONN]\033[0m Client %s:%d %s -> Backend [%d] %s:%d",
                    client_ip, client_port,
                    g_config.enable_ssl_offloading ? "\033[1;35m(TLS)\033[0m" : "",
                    backend_idx, b_ip, b_port);
            break;
        }

        record_backend_failure(backend_idx);
        backend_idx = -1;
    }

    if (backend_fd >= 0) {
        if (g_config.enable_proxy_protocol_v1) {
            struct sockaddr_in lb_addr;
            socklen_t lb_len = sizeof(lb_addr);
            if (getsockname(client_fd, (struct sockaddr *)&lb_addr, &lb_len) != 0) {
                memset(&lb_addr, 0, sizeof(lb_addr));
                lb_addr.sin_family = AF_INET;
                lb_addr.sin_port = htons((uint16_t)g_config.listen_port);
            }
            char pp_hdr[128];
            int pp_len = build_proxy_protocol_v1_header(pp_hdr, sizeof(pp_hdr), &client_addr, &lb_addr);
            if (write_all(backend_fd, pp_hdr, (size_t)pp_len) <= 0) {
                add_log("\033[1;31m[PPv1 ERR]\033[0m Failed sending PROXY v1 to backend [%d]", backend_idx);
            }
        }

        forward_traffic_dual_epoll(client_fd, client_ssl, backend_fd);
        close(backend_fd);
        release_backend(backend_idx);
        add_log("\033[1;30m[DISC]\033[0m Connection closed for client %s:%d", client_ip, client_port);
    } else {
        add_log("\033[1;31m[DROP]\033[0m No healthy backend available for %s:%d", client_ip, client_port);
    }

    if (client_ssl) {
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
    }
    close(client_fd);

cleanup:
    atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
    return NULL;
}
