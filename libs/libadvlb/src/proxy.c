#define _GNU_SOURCE
#include "advlb/proxy.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/net_utils.h"
#include "advlb/proxy_proto.h"
#include "advlb/compat_epoll.h"
#include "advlb/ssl_engine.h"
#include "advlb/conn_pool.h"
#include "advlb/session_table.h"
#include "advlb/cluster.h"

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
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
    size_t head; // monotonic read index
    size_t tail; // monotonic write index
} StreamBuffer;

static inline size_t buffer_available(const StreamBuffer *sb) {
    return sb->tail - sb->head;
}

static inline size_t buffer_space(const StreamBuffer *sb) {
    size_t avail = sb->tail - sb->head;
    return (avail < BUFFER_SIZE) ? (BUFFER_SIZE - avail) : 0;
}

// Contiguous write segment pointer and its length for nonblocking_read()
static inline char *buffer_write_ptr(StreamBuffer *sb) {
    return sb->data + (sb->tail & (BUFFER_SIZE - 1));
}

static inline size_t buffer_write_len(const StreamBuffer *sb) {
    size_t avail = sb->tail - sb->head;
    if (avail >= BUFFER_SIZE) return 0;
    size_t total_free = BUFFER_SIZE - avail;
    size_t to_end = BUFFER_SIZE - (sb->tail & (BUFFER_SIZE - 1));
    return (to_end < total_free) ? to_end : total_free;
}

static inline void buffer_produce(StreamBuffer *sb, size_t count) {
    sb->tail += count;
}

// Contiguous read segment pointer and its length for nonblocking_write()
static inline const char *buffer_read_ptr(const StreamBuffer *sb) {
    return sb->data + (sb->head & (BUFFER_SIZE - 1));
}

static inline size_t buffer_read_len(const StreamBuffer *sb) {
    size_t avail = sb->tail - sb->head;
    if (avail == 0) return 0;
    size_t to_end = BUFFER_SIZE - (sb->head & (BUFFER_SIZE - 1));
    return (to_end < avail) ? to_end : avail;
}

static inline void buffer_consume(StreamBuffer *sb, size_t count) {
    sb->head += count;
}

// Circular prepend for PROXY Protocol v1 header without moving existing data
static inline bool buffer_prepend(StreamBuffer *sb, const char *hdr, size_t len) {
    if (buffer_space(sb) < len) return false;
    sb->head -= len;
    for (size_t i = 0; i < len; i++) {
        sb->data[(sb->head + i) & (BUFFER_SIZE - 1)] = hdr[i];
    }
    return true;
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

static inline bool has_connection_close_header(const char *buf, size_t len) {
    if (!buf || len < 8) return false;
    size_t scan_len = (len < 1024) ? len : 1024;
    if (memmem(buf, scan_len, "HTTP/1.0", 8) != NULL) {
        return true;
    }
    const char *target = "connection: close";
    const size_t tlen = 17;
    if (scan_len < tlen) return false;
    for (size_t i = 0; i <= scan_len - tlen; i++) {
        if ((buf[i] == 'c' || buf[i] == 'C') &&
            strncasecmp(buf + i, target, tlen) == 0) {
            return true;
        }
    }
    return false;
}

static bool extract_http_session_token(const char *buf, size_t len,
                                       const char **out_tok, size_t *out_len) {
    if (!buf || len < 12 || !out_tok || !out_len) return false;
    size_t scan_len = (len < 1024) ? len : 1024;

    static const char *hdr_names[] = { "x-session-id:", "cookie:" };
    static const size_t hdr_lens[] = { 13, 7 };

    for (size_t h = 0; h < 2; h++) {
        const char *target = hdr_names[h];
        size_t tlen = hdr_lens[h];
        if (scan_len <= tlen) continue;
        for (size_t i = 0; i + tlen < scan_len; i++) {
            if (i > 0 && buf[i - 1] != '\n') continue;
            if (strncasecmp(buf + i, target, tlen) == 0) {
                size_t pos = i + tlen;
                while (pos < scan_len && (buf[pos] == ' ' || buf[pos] == '\t')) pos++;
                size_t end = pos;
                while (end < scan_len && buf[end] != '\r' && buf[end] != '\n') end++;
                if (end > pos) {
                    size_t tok_len = end - pos;
                    if (tok_len > 128) tok_len = 128;
                    *out_tok = buf + pos;
                    *out_len = tok_len;
                    return true;
                }
            }
        }
    }
    return false;
}

typedef enum {
    CONN_STATE_PROXY_PROTOCOL,
    CONN_STATE_SSL_HANDSHAKE,
    CONN_STATE_BACKEND_CONNECTING,
    CONN_STATE_FORWARDING
} ConnectionState;

struct WorkerThread;

typedef struct ProxyConnection {
    int client_fd;
    int backend_fd;
    int backend_idx;
    int retry_count;
    ConnectionState state;

    struct sockaddr_storage client_addr;
    SSL *client_ssl;

    bool client_closed;
    bool backend_closed;
    bool backend_shut_wr;
    bool client_shut_wr;
    bool had_error;
    bool from_pool;
    bool keep_alive_eligible;
    bool l7_session_checked;
    bool client_want_write;
    bool handed_over;
    bool fds_replicated;

    size_t bytes_to_backend;
    size_t bytes_from_backend;
    size_t bytes_to_client;
    size_t skip_backend_bytes;
    size_t last_replicated_bytes;

    uint16_t initial_req_len;
    char initial_req[512];

    uint32_t last_client_ev;
    uint32_t last_backend_ev;

    time_t last_activity;
    time_t hs_start;
    time_t last_session_sync;

    struct WorkerThread *worker;
    struct ProxyConnection *prev;
    struct ProxyConnection *next;

    StreamBuffer c2b; // client to backend (placed at end to avoid zeroing 64KB in slab alloc)
    StreamBuffer b2c; // backend to client
} ProxyConnection;

typedef struct NewConnNode {
    int client_fd;
    int backend_fd;
    int backend_idx;
    bool is_migrated;
    uint64_t bytes_to_client;
    uint16_t req_len;
    char initial_req[512];
    struct sockaddr_storage client_addr;
    MigratedStreamState *migrated;   /* backend socket state + proxy buffers, owned */
    struct NewConnNode *next;
} NewConnNode;

typedef struct WorkerThread {
    int id;
    pthread_t thread;
    int epfd;
    int notify_pipe[2];
    int listen_fd; // SO_REUSEPORT multi-accept socket

    pthread_mutex_t queue_mutex;
    NewConnNode *queue_head;
    NewConnNode *queue_tail;

    ProxyConnection *conn_list_head;
    int active_conn_count;

    ProxyConnection **fd_table;
    int fd_table_cap;

    struct epoll_event current_events[MAX_WORKER_EVENTS];
    int current_nfds;
    int current_event_idx;

    // 2.3: Worker-local Slab Allocator / Object Pool for ProxyConnection
    ProxyConnection *conn_pool_head;
    int conn_pool_count;
    atomic_bool handover_requested;
    atomic_bool handover_done;
    atomic_bool resync_requested;
    volatile bool running;
} WorkerThread;

static inline ProxyConnection *worker_alloc_conn(WorkerThread *worker) {
    ProxyConnection *conn = NULL;
    if (worker && worker->conn_pool_head) {
        conn = worker->conn_pool_head;
        worker->conn_pool_head = conn->next;
        worker->conn_pool_count--;
    } else {
        conn = malloc(sizeof(ProxyConnection));
        if (!conn) return NULL;
    }
    memset(conn, 0, offsetof(ProxyConnection, c2b));
    conn->c2b.head = 0;
    conn->c2b.tail = 0;
    conn->b2c.head = 0;
    conn->b2c.tail = 0;
    return conn;
}

static inline void worker_free_conn(WorkerThread *worker, ProxyConnection *conn) {
    if (worker && worker->conn_pool_count < 256) {
        conn->next = worker->conn_pool_head;
        worker->conn_pool_head = conn;
        worker->conn_pool_count++;
        return;
    }
    free(conn);
}

static WorkerThread *s_workers = NULL;
static int s_num_workers = 0;
static atomic_int s_next_worker = 0;

/* Helper prototypes */
static void worker_set_fd(WorkerThread *worker, int fd, ProxyConnection *conn);
static ProxyConnection *worker_get_fd(WorkerThread *worker, int fd);
static void worker_clear_fd(WorkerThread *worker, int fd);
static void worker_add_conn(WorkerThread *worker, ProxyConnection *conn);
static void worker_remove_conn(WorkerThread *worker, ProxyConnection *conn);
static void worker_close_conn(WorkerThread *worker, ProxyConnection *conn, const char *reason);
static void worker_update_conn_epoll(WorkerThread *worker, ProxyConnection *conn);
static void worker_on_backend_connected(WorkerThread *worker, ProxyConnection *conn);
static void worker_start_backend_connect(WorkerThread *worker, ProxyConnection *conn);
static void worker_retry_backend_connect(WorkerThread *worker, ProxyConnection *conn);
static void worker_handle_backend_connecting(WorkerThread *worker, ProxyConnection *conn, int fd, uint32_t events);
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
    if (worker && fd >= 0) {
        for (int j = worker->current_event_idx + 1; j < worker->current_nfds; j++) {
            if (worker->current_events[j].data.fd == fd) {
                worker->current_events[j].data.fd = -1;
                worker->current_events[j].events = 0;
            }
        }
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

/* Copy ring buffer contents out (linear) / in, without consuming */
static void ring_copy_out(const StreamBuffer *sb, uint8_t *out, size_t n) {
    size_t first = buffer_read_len(sb);
    if (first > n) first = n;
    memcpy(out, buffer_read_ptr(sb), first);
    if (n > first) memcpy(out + first, sb->data, n - first);
}

static void ring_copy_in(StreamBuffer *sb, const uint8_t *in, size_t n) {
    while (n > 0) {
        size_t chunk = buffer_write_len(sb);
        if (chunk == 0) break;
        if (chunk > n) chunk = n;
        memcpy(buffer_write_ptr(sb), in, chunk);
        buffer_produce(sb, chunk);
        in += chunk;
        n -= chunk;
    }
}

/* Replicate a stream; with a VIP-sourced backend socket the proxy buffers travel with it */
static void worker_replicate_conn(ProxyConnection *conn) {
    ClusterConnState st;
    memset(&st, 0, sizeof(st));
    uint8_t *c2b = NULL, *b2c = NULL;
    bool with_state = true;
    if (conn->backend_fd >= 0 && cluster_fd_is_vip_sourced(conn->backend_fd)) {
        size_t c2l = buffer_available(&conn->c2b);
        size_t b2l = buffer_available(&conn->b2c);
        if (c2l > 0 && (c2b = malloc(c2l)) != NULL) ring_copy_out(&conn->c2b, c2b, c2l);
        if (b2l > 0 && (b2c = malloc(b2l)) != NULL) ring_copy_out(&conn->b2c, b2c, b2l);
        /* A buffer we failed to copy would be silently lost: degrade to client-only migration */
        with_state = (c2l == 0 || c2b) && (b2l == 0 || b2c);
        st.c2b = c2b;
        st.c2b_len = (uint32_t)c2l;
        st.b2c = b2c;
        st.b2c_len = (uint32_t)b2l;
    }
    st.bytes_to_backend = conn->bytes_to_backend;
    st.bytes_from_backend = conn->bytes_from_backend;
    st.skip_backend_bytes = conn->skip_backend_bytes;
    st.flags = (uint8_t)((conn->keep_alive_eligible ? MIGRATED_F_KEEPALIVE : 0) |
                         (conn->client_shut_wr ? MIGRATED_F_CLIENT_SHUT_WR : 0) |
                         (conn->backend_shut_wr ? MIGRATED_F_BACKEND_SHUT_WR : 0) |
                         (conn->client_closed ? MIGRATED_F_CLIENT_CLOSED : 0) |
                         (conn->backend_closed ? MIGRATED_F_BACKEND_CLOSED : 0));
    cluster_replicate_live_conn(&conn->client_addr, conn->backend_idx,
                                conn->client_fd, with_state ? conn->backend_fd : -1,
                                conn->initial_req, conn->initial_req_len,
                                (uint64_t)conn->bytes_to_client, with_state ? &st : NULL);
    free(c2b);
    free(b2c);
}

/* Release a socket whose state now lives on another node: no FIN/RST may reach the peer */
static void close_silently_for_failover(int fd) {
#ifdef __linux__
    /* Clear any pending socket error before TCP_REPAIR so sk->sk_err is 0 */
    int so_err = 0;
    socklen_t so_err_len = sizeof(so_err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len);

    /* Enable TCP_REPAIR mode with TCP_NO_QUEUE: Linux tcp_close() checks sk->sk_repair
     * and cleanly runs sk_prot->disconnect(sk, 0), freeing descriptor with ZERO RST/FIN emitted */
    int repair_on = 1;
    if (setsockopt(fd, 6 /* SOL_TCP */, 19 /* TCP_REPAIR */, &repair_on, sizeof(repair_on)) < 0) {
        add_log("\033[1;33m[HA CLOSE]\033[0m setsockopt TCP_REPAIR before close: %s (errno %d, fd=%d)",
                strerror(errno), errno, fd);
    }
    int no_q = 0; /* TCP_NO_QUEUE */
    setsockopt(fd, 6 /* SOL_TCP */, 20 /* TCP_REPAIR_QUEUE */, &no_q, sizeof(no_q));

    /* Clear SO_ERROR again to guarantee clean closure without abort */
    so_err = 0;
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len);
#endif
    close(fd);
}

static void worker_close_conn(WorkerThread *worker, ProxyConnection *conn, const char *reason) {
    char client_ip[INET6_ADDRSTRLEN];
    int client_port = 0;
    get_client_ip_port(&conn->client_addr, client_ip, sizeof(client_ip), &client_port);

    bool preserve_for_failover = conn->handed_over || (!g_server_running && g_config.enable_cluster);

    if (conn->backend_fd >= 0) {
        epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->backend_fd, NULL);
        worker_clear_fd(worker, conn->backend_fd);

        bool pooled = false;
        // Only pool validated Keep-Alive connections
        if (!preserve_for_failover &&
            !conn->fds_replicated &&
            g_config.enable_upstream_pooling &&
            conn->keep_alive_eligible &&
            !conn->had_error &&
            conn->backend_idx >= 0 &&
            !conn->backend_closed &&
            !conn->backend_shut_wr &&
            !g_config.enable_proxy_protocol_v1 &&
            conn->state == CONN_STATE_FORWARDING &&
            conn->bytes_to_backend > 0 &&
            conn->bytes_from_backend > 0 &&
            buffer_available(&conn->c2b) == 0 &&
            buffer_available(&conn->b2c) == 0) {
            pooled = conn_pool_release(conn->backend_idx, conn->backend_fd);
        }

        if (!pooled) {
            if (conn->handed_over && cluster_fd_is_vip_sourced(conn->backend_fd)) {
                /* Backend socket migrated with the stream: a FIN would kill it on the new node */
                close_silently_for_failover(conn->backend_fd);
            } else {
                close(conn->backend_fd);
            }
        }
        conn->backend_fd = -1;
    }

    int closed_backend_idx = conn->backend_idx;
    if (conn->backend_idx >= 0) {
        release_backend(conn->backend_idx);
        conn->backend_idx = -1;
    }

    if (conn->client_fd >= 0) {
        epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->client_fd, NULL);
        worker_clear_fd(worker, conn->client_fd);
        if (conn->client_ssl) {
            if (!preserve_for_failover) {
                SSL_set_quiet_shutdown(conn->client_ssl, 0);
                SSL_shutdown(conn->client_ssl);
            }
            SSL_free(conn->client_ssl);
            conn->client_ssl = NULL;
        } else if (!preserve_for_failover && g_config.enable_ssl_offloading) {
            /* Send TLS close_notify alert over kTLS socket so peer terminates cleanly */
            add_log("\033[1;33m[HA CLOSE]\033[0m ktls_send_close_notify fd=%d (reason: %s)",
                    conn->client_fd, reason ? reason : "unspecified");
            ktls_send_close_notify(conn->client_fd);
        }
        if (!preserve_for_failover) {
            shutdown(conn->client_fd, SHUT_WR);
            close(conn->client_fd);
        } else {
#ifdef __linux__
            /* Drain any pending bytes from receive queue so data_was_unread == 0 in tcp_close()
             * (they were captured by the checkpoint) */
            char drain_buf[2048];
            while (recv(conn->client_fd, drain_buf, sizeof(drain_buf), MSG_DONTWAIT) > 0);
#endif
            close_silently_for_failover(conn->client_fd);
        }
        conn->client_fd = -1;
    }

    if (!preserve_for_failover && g_config.enable_cluster) {
        if (conn->fds_replicated) {
            cluster_notify_conn_closed(&conn->client_addr, closed_backend_idx);
        } else if (!g_config.enable_session_stickiness) {
            session_table_remove_client(&conn->client_addr, SESSION_PROTO_TCP, true, false);
        }
    }

    add_log("\033[1;30m[DISC]\033[0m Connection %s for client %s:%d (reason: %s)",
            preserve_for_failover ? "handed over to HA peer" : "closed",
            client_ip, client_port, reason ? reason : "unspecified");

    worker_remove_conn(worker, conn);
    worker_free_conn(worker, conn);
    atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
}

static void worker_update_conn_epoll(WorkerThread *worker, ProxyConnection *conn) {
    if (conn->state != CONN_STATE_FORWARDING) return;

    // Configure client epoll interest mask (Automatic Backpressure)
    uint32_t client_mask = 0;
    if (!conn->client_closed && buffer_space(&conn->c2b) > 0) client_mask |= EPOLLIN;
    if (buffer_available(&conn->b2c) > 0 || conn->client_want_write) client_mask |= EPOLLOUT;
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
        if (!conn->backend_closed && buffer_space(&conn->b2c) > 0 && !conn->client_want_write) backend_mask |= EPOLLIN;
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
    char client_ip[INET6_ADDRSTRLEN];
    int client_port = 0;
    get_client_ip_port(&conn->client_addr, client_ip, sizeof(client_ip), &client_port);

    const char *b_ip = g_backends[conn->backend_idx].ip;
    int b_port = g_backends[conn->backend_idx].port;

    add_log("\033[1;36m[CONN]\033[0m Client %s:%d %s -> Backend [%d] %s:%d (Worker %d)",
            client_ip, client_port,
            g_config.enable_ssl_offloading ? "\033[1;35m(TLS)\033[0m" : "",
            conn->backend_idx, b_ip, b_port, worker->id);

    // If PROXY Protocol v1 is enabled towards backend, prepend header to c2b buffer
    if (g_config.enable_proxy_protocol_v1) {
        struct sockaddr_storage lb_addr;
        socklen_t lb_len = sizeof(lb_addr);
        if (getsockname(conn->client_fd, (struct sockaddr *)&lb_addr, &lb_len) != 0) {
            memset(&lb_addr, 0, sizeof(lb_addr));
            lb_addr.ss_family = AF_INET;
            ((struct sockaddr_in *)&lb_addr)->sin_port = htons((uint16_t)g_config.listen_port);
        }
        char pp_hdr[128];
        int pp_len = build_proxy_protocol_v1_header_storage(pp_hdr, sizeof(pp_hdr), &conn->client_addr, &lb_addr);
        if (pp_len > 0) {
            if (!buffer_prepend(&conn->c2b, pp_hdr, (size_t)pp_len)) {
                add_log("\033[1;31m[PPv1 ERR]\033[0m Buffer full, failed prepending PROXY v1 header");
            }
        }
    }

    conn->state = CONN_STATE_FORWARDING;
    conn->last_activity = time(NULL);

    // Attempt immediate non-blocking flush of any pending c2b data
    while (buffer_available(&conn->c2b) > 0) {
        bool want_io = false;
        size_t rlen = buffer_read_len(&conn->c2b);
        ssize_t w = nonblocking_write(conn->backend_fd, NULL,
                                      buffer_read_ptr(&conn->c2b), rlen, &want_io);
        if (w > 0) {
            buffer_consume(&conn->c2b, (size_t)w);
            conn->bytes_to_backend += (size_t)w;
        } else if (w < 0) {
            int max_retries = (g_num_backends > 1) ? (g_num_backends * 2) : 2;
            if (conn->bytes_from_backend == 0 && conn->c2b.tail <= BUFFER_SIZE && conn->retry_count < max_retries) {
                conn->c2b.head = 0;
                conn->bytes_to_backend = 0;
                conn->from_pool = false;
                worker_retry_backend_connect(worker, conn);
                return;
            }
            conn->had_error = true;
            worker_close_conn(worker, conn, "backend_write_err_on_connect");
            return;
        } else {
            break;
        }
    }

    worker_update_conn_epoll(worker, conn);
}

static void worker_retry_backend_connect(WorkerThread *worker, ProxyConnection *conn) {
    if (conn->backend_fd >= 0) {
        epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->backend_fd, NULL);
        worker_clear_fd(worker, conn->backend_fd);
        close(conn->backend_fd);
        conn->backend_fd = -1;
        conn->last_backend_ev = 0;
    }
    if (conn->backend_idx >= 0) {
        release_backend(conn->backend_idx);
        conn->backend_idx = -1;
    }
    conn->backend_closed = false;
    conn->backend_shut_wr = false;
    conn->from_pool = false;

    worker_start_backend_connect(worker, conn);
}

static void worker_start_backend_connect(WorkerThread *worker, ProxyConnection *conn) {
    char client_ip[INET6_ADDRSTRLEN];
    int client_port = 0;
    get_client_ip_port(&conn->client_addr, client_ip, sizeof(client_ip), &client_port);

    // Register client_fd in epoll if not yet monitored so initial client data can be buffered
    if (conn->client_fd >= 0 && conn->last_client_ev == 0) {
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = conn->client_fd;
        ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
        conn->last_client_ev = ev.events;
        epoll_ctl(worker->epfd, EPOLL_CTL_ADD, conn->client_fd, &ev);
    }

    conn->bytes_to_backend = 0;
    conn->bytes_from_backend = 0;

    int max_retries = (g_num_backends > 1) ? (g_num_backends * 2) : 2;
    if (conn->retry_count >= max_retries) {
        conn->retry_count = 0;
    }
    while (conn->retry_count < max_retries) {
        conn->retry_count++;
        int b_idx = get_healthy_backend(&conn->client_addr);
        if (b_idx < 0) {
            break;
        }

        // Try to acquire an established, idle Keep-Alive socket from the connection pool
        int pooled_fd = -1;
        if (g_config.enable_upstream_pooling && !g_config.enable_proxy_protocol_v1) {
            pooled_fd = conn_pool_acquire(b_idx);
        }
        if (pooled_fd >= 0) {
            conn->backend_idx = b_idx;
            conn->backend_fd = pooled_fd;
            conn->from_pool = true;
            worker_set_fd(worker, pooled_fd, conn);
            record_backend_success(b_idx);
            worker_on_backend_connected(worker, conn);
            return;
        }

        const char *b_ip = g_backends[b_idx].ip;
        int b_port = g_backends[b_idx].port;

        bool in_progress = false;
        int bfd = connect_nonblocking_transparent(b_ip, b_port, &conn->client_addr, &in_progress);
        if (bfd >= 0) {
            conn->backend_idx = b_idx;
            conn->backend_fd = bfd;
            conn->from_pool = false;
            worker_set_fd(worker, bfd, conn);

            if (!in_progress) {
                record_backend_success(b_idx);
                worker_on_backend_connected(worker, conn);
                return;
            }

            conn->state = CONN_STATE_BACKEND_CONNECTING;
            conn->last_activity = time(NULL);

            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.data.fd = bfd;
            ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
            conn->last_backend_ev = ev.events;
            epoll_ctl(worker->epfd, EPOLL_CTL_ADD, bfd, &ev);
            return;
        }

        int err = errno;
        add_log("\033[1;33m[WARN]\033[0m Backend [%d] %s:%d immediate connect failed: %s (errno %d)",
                b_idx, b_ip, b_port, strerror(err), err);
        if (err == EADDRNOTAVAIL || err == EAGAIN || err == ENOBUFS || err == EMFILE || err == ENFILE) {
            release_backend(b_idx);
        } else {
            record_backend_failure(b_idx);
        }
    }

    add_log("\033[1;31m[DROP]\033[0m No healthy backend available for %s:%d", client_ip, client_port);
    conn->had_error = true;
    worker_close_conn(worker, conn, "no_healthy_backend");
}

static bool worker_apply_l7_session_affinity(WorkerThread *worker, ProxyConnection *conn) {
    if (conn->l7_session_checked || conn->bytes_to_backend > 0) return false;
    if (!g_config.enable_cluster && !g_config.enable_session_stickiness) {
        conn->l7_session_checked = true;
        return false;
    }

    size_t avail = buffer_read_len(&conn->c2b);
    if (avail < 16) return false;

    const char *rptr = buffer_read_ptr(&conn->c2b);
    const char *tok = NULL;
    size_t tok_len = 0;
    if (!extract_http_session_token(rptr, avail, &tok, &tok_len)) {
        if (avail >= 256 || memmem(rptr, avail, "\r\n\r\n", 4) != NULL) {
            conn->l7_session_checked = true;
        }
        return false;
    }

    conn->l7_session_checked = true;
    uint32_t ttl = (g_config.session_ttl_sec > 0) ? (uint32_t)g_config.session_ttl_sec : 120u;
    int target_b = session_table_lookup_token(tok, tok_len);

    if (target_b >= 0 && target_b < g_num_backends &&
        target_b != conn->backend_idx && !g_config.enable_proxy_protocol_v1) {
        int new_bfd = -1;
        bool in_prog = false;
        bool pooled = false;

        if (g_config.enable_upstream_pooling) {
            new_bfd = conn_pool_acquire(target_b);
            if (new_bfd >= 0) pooled = true;
        }
        if (new_bfd < 0) {
            new_bfd = connect_nonblocking_transparent(g_backends[target_b].ip,
                                                      g_backends[target_b].port,
                                                      &conn->client_addr, &in_prog);
        }

        if (new_bfd >= 0) {
            if (conn->backend_fd >= 0) {
                epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->backend_fd, NULL);
                worker_clear_fd(worker, conn->backend_fd);
                if (conn->from_pool && g_config.enable_upstream_pooling) {
                    if (!conn_pool_release(conn->backend_idx, conn->backend_fd)) {
                        close(conn->backend_fd);
                    }
                } else {
                    close(conn->backend_fd);
                }
            }
            if (conn->backend_idx >= 0) {
                release_backend(conn->backend_idx);
            }

            atomic_fetch_add_explicit(&g_backends[target_b].active_connections, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&g_backends[target_b].total_requests_handled, 1, memory_order_relaxed);

            conn->backend_idx = target_b;
            conn->backend_fd = new_bfd;
            conn->from_pool = pooled;
            conn->last_backend_ev = 0;
            worker_set_fd(worker, new_bfd, conn);

            bool use_port = !g_config.enable_session_stickiness;
            session_table_upsert_local(&conn->client_addr, SESSION_PROTO_TCP, use_port,
                                       target_b, ttl, g_config.enable_cluster);
            session_table_upsert_token(tok, tok_len, target_b, ttl, g_config.enable_cluster);

            if (!pooled && in_prog) {
                conn->state = CONN_STATE_BACKEND_CONNECTING;
                struct epoll_event ev;
                memset(&ev, 0, sizeof(ev));
                ev.data.fd = new_bfd;
                ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
                conn->last_backend_ev = ev.events;
                epoll_ctl(worker->epfd, EPOLL_CTL_ADD, new_bfd, &ev);
                return true;
            }

            record_backend_success(target_b);
            conn->state = CONN_STATE_FORWARDING;
            worker_update_conn_epoll(worker, conn);
            return false;
        }
    }

    if (conn->backend_idx >= 0) {
        session_table_upsert_token(tok, tok_len, conn->backend_idx, ttl, g_config.enable_cluster);
    }
    return false;
}

static void worker_handle_backend_connecting(WorkerThread *worker, ProxyConnection *conn, int fd, uint32_t events) {
    if (fd == conn->client_fd) {
        if (events & EPOLLERR) {
            conn->had_error = true;
            worker_close_conn(worker, conn, "backend_connecting_client_epollerr");
            return;
        }
        if (events & (EPOLLIN | EPOLLHUP)) {
            size_t space;
            while (!conn->client_closed && (space = buffer_write_len(&conn->c2b)) > 0) {
                bool want_io = false;
                char *wptr = buffer_write_ptr(&conn->c2b);
                ssize_t r = nonblocking_read(conn->client_fd, conn->client_ssl,
                                             wptr, space, &want_io);
                if (r > 0) {
                    if (conn->c2b.tail == 0 && has_connection_close_header(wptr, (size_t)r)) {
                        conn->keep_alive_eligible = false;
                    }
                    if (conn->initial_req_len < sizeof(conn->initial_req)) {
                        size_t can_copy = sizeof(conn->initial_req) - conn->initial_req_len;
                        if ((size_t)r < can_copy) can_copy = (size_t)r;
                        memcpy(conn->initial_req + conn->initial_req_len, wptr, can_copy);
                        conn->initial_req_len += (uint16_t)can_copy;
                    }
                    buffer_produce(&conn->c2b, (size_t)r);
                    conn->last_activity = time(NULL);
                } else if (r == 0 && !want_io) {
                    conn->client_closed = true;
                    break;
                } else if (r < 0) {
                    conn->had_error = true;
                    worker_close_conn(worker, conn, "backend_connecting_client_read_err");
                    return;
                } else {
                    break;
                }
            }
            if (!conn->l7_session_checked && buffer_available(&conn->c2b) > 0) {
                (void)worker_apply_l7_session_affinity(worker, conn);
            }
            if (conn->backend_fd < 0 && buffer_available(&conn->c2b) > 0) {
                worker_start_backend_connect(worker, conn);
                return;
            }
        }
        return;
    }

    if (fd == conn->backend_fd) {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(conn->backend_fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
            int failure_code = (err != 0) ? err : errno;
            const char *b_ip = g_backends[conn->backend_idx].ip;
            int b_port = g_backends[conn->backend_idx].port;

            add_log("\033[1;33m[WARN]\033[0m Backend [%d] %s:%d async connect failed: %s (errno %d)",
                    conn->backend_idx, b_ip, b_port, strerror(failure_code), failure_code);
            if (failure_code == EADDRNOTAVAIL || failure_code == EAGAIN || failure_code == ENOBUFS) {
                release_backend(conn->backend_idx);
            } else {
                record_backend_failure(conn->backend_idx);
            }
            conn->backend_idx = -1;

            worker_retry_backend_connect(worker, conn);
            return;
        }

        record_backend_success(conn->backend_idx);
        worker_on_backend_connected(worker, conn);
    }
}

static void worker_step_ssl_handshake(WorkerThread *worker, ProxyConnection *conn) {
    while (g_server_running && worker->running) {
        int acc_res = SSL_accept(conn->client_ssl);
        if (acc_res > 0) {
            conn->last_activity = time(NULL);
#if defined(BIO_get_ktls_send) && defined(BIO_get_ktls_recv)
            BIO *wb = SSL_get_wbio(conn->client_ssl);
            BIO *rb = SSL_get_rbio(conn->client_ssl);
            bool ktls_tx = wb && BIO_get_ktls_send(wb);
            bool ktls_rx = rb && BIO_get_ktls_recv(rb);
            add_log("\033[1;34m[TLS ACCEPT]\033[0m Handshake ok: %s | kTLS: TX=%s, RX=%s",
                    SSL_get_cipher_name(conn->client_ssl),
                    ktls_tx ? "\033[1;32mON\033[0m" : "\033[1;33mOFF\033[0m",
                    ktls_rx ? "\033[1;32mON\033[0m" : "\033[1;33mOFF\033[0m");
#endif
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

        conn->had_error = true;
        worker_close_conn(worker, conn, "ssl_handshake_failed");
        return;
    }
}

static bool worker_pump_cluster_b2c(WorkerThread *worker, ProxyConnection *conn, time_t now) {
    int max_retries = (g_num_backends > 1) ? (g_num_backends * 2) : 2;
    char peek_buf[16384];

    while (conn->backend_fd >= 0 && conn->client_fd >= 0 &&
           !conn->backend_closed && !conn->client_closed &&
           buffer_available(&conn->b2c) == 0) {
        ssize_t peeked = recv(conn->backend_fd, peek_buf, sizeof(peek_buf), MSG_PEEK);
        if (peeked > 0) {
            if (conn->skip_backend_bytes > 0) {
                size_t skip = ((size_t)peeked < conn->skip_backend_bytes)
                              ? (size_t)peeked
                              : conn->skip_backend_bytes;
                ssize_t cr = recv(conn->backend_fd, peek_buf, skip, 0);
                if (cr > 0) {
                    conn->skip_backend_bytes -= (size_t)cr;
                }
                continue;
            }
            if (conn->bytes_from_backend == 0 && has_connection_close_header(peek_buf, (size_t)peeked)) {
                conn->keep_alive_eligible = false;
            }

            bool want_io = false;
            ssize_t w = nonblocking_write(conn->client_fd, NULL, peek_buf, (size_t)peeked, &want_io);
            if (w > 0) {
                size_t to_consume = (size_t)w;
                while (to_consume > 0) {
                    ssize_t cr = recv(conn->backend_fd, peek_buf, to_consume, 0);
                    if (cr > 0) {
                        to_consume -= (size_t)cr;
                    } else if (cr < 0 && errno == EINTR) {
                        continue;
                    } else {
                        break;
                    }
                }
                conn->bytes_from_backend += (size_t)w;
                conn->bytes_to_client += (size_t)w;
                conn->last_activity = now;
                conn->client_want_write = ((size_t)w < (size_t)peeked) || want_io;

                if (!conn->fds_replicated && conn->bytes_to_client >= 4096) {
                    conn->fds_replicated = true;
                    conn->last_replicated_bytes = conn->bytes_to_client;
                    worker_replicate_conn(conn);
                }
                if (conn->client_want_write) {
                    break;
                }
            } else if (w == 0 && want_io) {
                conn->client_want_write = true;
                break;
            } else {
                conn->had_error = true;
                worker_close_conn(worker, conn, "pump_client_write_err");
                return false;
            }
        } else if (peeked == 0) {
            if (conn->bytes_from_backend == 0 && conn->c2b.tail > 0 &&
                conn->c2b.tail <= BUFFER_SIZE && conn->retry_count < max_retries) {
                conn->c2b.head = 0;
                conn->bytes_to_backend = 0;
                conn->from_pool = false;
                worker_retry_backend_connect(worker, conn);
                return false;
            }
            conn->backend_closed = true;
            conn->client_want_write = false;
            break;
        } else {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                conn->client_want_write = false;
                break;
            }
            if (conn->bytes_from_backend == 0 && conn->c2b.tail > 0 &&
                conn->c2b.tail <= BUFFER_SIZE && conn->retry_count < max_retries) {
                conn->c2b.head = 0;
                conn->bytes_to_backend = 0;
                conn->from_pool = false;
                worker_retry_backend_connect(worker, conn);
                return false;
            }
            conn->had_error = true;
            worker_close_conn(worker, conn, "pump_backend_recv_err");
            return false;
        }
    }
    return true;
}

static void worker_handle_forwarding_io(WorkerThread *worker, ProxyConnection *conn, int fd, uint32_t events) {
    time_t now = time(NULL);
    int max_retries = (g_num_backends > 1) ? (g_num_backends * 2) : 2;

    // Events on CLIENT socket
    if (fd == conn->client_fd) {
        if (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
            size_t space;
            while (!conn->client_closed && (space = buffer_write_len(&conn->c2b)) > 0) {
                bool want_io = false;
                char *wptr = buffer_write_ptr(&conn->c2b);
                ssize_t r = nonblocking_read(conn->client_fd, conn->client_ssl,
                                             wptr, space, &want_io);
                if (r > 0) {
                    if (conn->c2b.head == 0 && conn->c2b.tail == 0 && buffer_available(&conn->b2c) == 0) {
                        /* Start of new HTTP request transaction on keep-alive stream */
                        conn->bytes_to_backend = 0;
                        conn->bytes_from_backend = 0;
                        conn->retry_count = 0;
                    }
                    if (conn->c2b.tail == 0 && has_connection_close_header(wptr, (size_t)r)) {
                        conn->keep_alive_eligible = false;
                    }
                    if (conn->initial_req_len < sizeof(conn->initial_req)) {
                        size_t can_copy = sizeof(conn->initial_req) - conn->initial_req_len;
                        if ((size_t)r < can_copy) can_copy = (size_t)r;
                        memcpy(conn->initial_req + conn->initial_req_len, wptr, can_copy);
                        conn->initial_req_len += (uint16_t)can_copy;
                    }
                    buffer_produce(&conn->c2b, (size_t)r);
                    conn->last_activity = now;
                } else if (r == 0 && !want_io) {
                    add_log("\033[1;33m[HA EOF]\033[0m Client closed connection on fd=%d", conn->client_fd);
                    conn->client_closed = true;
                    break;
                } else if (r < 0) {
                    int r_err = errno;
                    add_log("\033[1;31m[HA ERR]\033[0m Client read error on fd=%d: %s (errno %d)",
                            conn->client_fd, strerror(r_err), r_err);
                    conn->had_error = true;
                    worker_close_conn(worker, conn, "client_read_err");
                    return;
                } else {
                    break;
                }
            }
            if (conn->backend_fd < 0 && buffer_available(&conn->c2b) > 0) {
                worker_start_backend_connect(worker, conn);
                return;
            }
            if (!conn->l7_session_checked && conn->bytes_to_backend == 0 && buffer_available(&conn->c2b) > 0) {
                if (worker_apply_l7_session_affinity(worker, conn)) {
                    return;
                }
            }
            if ((g_config.enable_cluster || g_config.enable_session_stickiness) &&
                conn->backend_idx >= 0 && (now - conn->last_session_sync >= 5)) {
                uint32_t ttl = (g_config.session_ttl_sec > 0) ? (uint32_t)g_config.session_ttl_sec : 120u;
                bool use_port = !g_config.enable_session_stickiness;
                session_table_upsert_local(&conn->client_addr, SESSION_PROTO_TCP, use_port,
                                           conn->backend_idx, ttl, g_config.enable_cluster);
                conn->last_session_sync = now;
            }
        }

        if (events & EPOLLOUT) {
            while (buffer_available(&conn->b2c) > 0) {
                size_t avail = buffer_read_len(&conn->b2c);
                bool want_io = false;
                ssize_t w = nonblocking_write(conn->client_fd, conn->client_ssl,
                                              buffer_read_ptr(&conn->b2c), avail, &want_io);
                if (w > 0) {
                    buffer_consume(&conn->b2c, (size_t)w);
                    conn->bytes_to_client += (size_t)w;
                    conn->last_activity = now;
                } else if (w < 0) {
                    conn->had_error = true;
                    worker_close_conn(worker, conn, "client_write_err");
                    return;
                } else {
                    break;
                }
            }
            if (g_config.enable_cluster && !g_config.enable_ssl_offloading && !conn->client_ssl && conn->client_want_write) {
                conn->client_want_write = false;
                if (!worker_pump_cluster_b2c(worker, conn, now)) {
                    return;
                }
            }
        }

        if (events & EPOLLERR) {
            conn->had_error = true;
            worker_close_conn(worker, conn, "client_epollerr");
            return;
        }
    }

    // Events on BACKEND socket
    if (fd == conn->backend_fd) {
        if (events & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
            if (g_config.enable_cluster && !g_config.enable_ssl_offloading && !conn->client_ssl && buffer_available(&conn->b2c) == 0) {
                if (!worker_pump_cluster_b2c(worker, conn, now)) {
                    return;
                }
            } else {
                size_t space;
                while (!conn->backend_closed && (space = buffer_write_len(&conn->b2c)) > 0) {
                    bool want_io = false;
                    char *wptr = buffer_write_ptr(&conn->b2c);
                    ssize_t r = nonblocking_read(conn->backend_fd, NULL,
                                                 wptr, space, &want_io);
                    if (r > 0) {
                        if (conn->skip_backend_bytes > 0) {
                            if ((size_t)r <= conn->skip_backend_bytes) {
                                conn->skip_backend_bytes -= (size_t)r;
                                continue;
                            }
                            size_t skip = conn->skip_backend_bytes;
                            conn->skip_backend_bytes = 0;
                            memmove(wptr, wptr + skip, (size_t)r - skip);
                            r -= (ssize_t)skip;
                        }
                        if (conn->bytes_from_backend == 0 && has_connection_close_header(wptr, (size_t)r)) {
                            conn->keep_alive_eligible = false;
                        }
                        buffer_produce(&conn->b2c, (size_t)r);
                        conn->bytes_from_backend += (size_t)r;
                        conn->last_activity = now;
                    } else if (r == 0 && !want_io) {
                        // If backend closed before sending any response bytes, retry transparently
                        if (conn->bytes_from_backend == 0 && conn->c2b.tail > 0 &&
                            conn->c2b.tail <= BUFFER_SIZE && conn->retry_count < max_retries) {
                            conn->c2b.head = 0;
                            conn->bytes_to_backend = 0;
                            conn->from_pool = false;
                            worker_retry_backend_connect(worker, conn);
                            return;
                        }
                        add_log("\033[1;33m[HA EOF]\033[0m Backend closed connection on fd=%d", conn->backend_fd);
                        conn->backend_closed = true;
                        break;
                    } else if (r < 0) {
                        if (conn->bytes_from_backend == 0 && conn->c2b.tail > 0 &&
                            conn->c2b.tail <= BUFFER_SIZE && conn->retry_count < max_retries) {
                            conn->c2b.head = 0;
                            conn->bytes_to_backend = 0;
                            conn->from_pool = false;
                            worker_retry_backend_connect(worker, conn);
                            return;
                        }
                        conn->had_error = true;
                        if (conn->bytes_from_backend > 0 && buffer_available(&conn->b2c) > 0) {
                            conn->backend_closed = true;
                            break;
                        }
                        worker_close_conn(worker, conn, "backend_read_err");
                        return;
                    } else {
                        break;
                    }
                }
            }
        }

        if (events & EPOLLOUT) {
            while (buffer_available(&conn->c2b) > 0) {
                size_t avail = buffer_read_len(&conn->c2b);
                bool want_io = false;
                ssize_t w = nonblocking_write(conn->backend_fd, NULL,
                                              buffer_read_ptr(&conn->c2b), avail, &want_io);
                if (w > 0) {
                    buffer_consume(&conn->c2b, (size_t)w);
                    conn->bytes_to_backend += (size_t)w;
                    conn->last_activity = now;
                } else if (w < 0) {
                    if (conn->bytes_from_backend == 0 && conn->c2b.tail <= BUFFER_SIZE &&
                        conn->retry_count < max_retries) {
                        conn->c2b.head = 0;
                        conn->bytes_to_backend = 0;
                        conn->from_pool = false;
                        worker_retry_backend_connect(worker, conn);
                        return;
                    }
                    conn->had_error = true;
                    worker_close_conn(worker, conn, "backend_write_err");
                    return;
                } else {
                    break;
                }
            }
        }

        if ((events & EPOLLERR) && buffer_available(&conn->b2c) == 0) {
            if (conn->bytes_from_backend == 0 && conn->c2b.tail > 0 &&
                conn->c2b.tail <= BUFFER_SIZE && conn->retry_count < max_retries) {
                conn->c2b.head = 0;
                conn->bytes_to_backend = 0;
                conn->from_pool = false;
                worker_retry_backend_connect(worker, conn);
                return;
            }
            conn->had_error = true;
            worker_close_conn(worker, conn, "backend_epollerr");
            return;
        }
    }

    // Immediate flush attempt for c2b to backend
    while (conn->backend_fd >= 0 && buffer_available(&conn->c2b) > 0) {
        bool want_io = false;
        size_t avail = buffer_read_len(&conn->c2b);
        ssize_t w = nonblocking_write(conn->backend_fd, NULL,
                                      buffer_read_ptr(&conn->c2b), avail, &want_io);
        if (w > 0) {
            buffer_consume(&conn->c2b, (size_t)w);
            conn->bytes_to_backend += (size_t)w;
            conn->last_activity = now;
        } else if (w < 0) {
            if (conn->bytes_from_backend == 0 && conn->c2b.tail <= BUFFER_SIZE &&
                conn->retry_count < max_retries) {
                conn->c2b.head = 0;
                conn->bytes_to_backend = 0;
                conn->from_pool = false;
                worker_retry_backend_connect(worker, conn);
                return;
            }
            conn->had_error = true;
            worker_close_conn(worker, conn, "c2b_flush_err");
            return;
        } else {
            break;
        }
    }

    // Immediate flush attempt for b2c to client
    while (conn->client_fd >= 0 && buffer_available(&conn->b2c) > 0) {
        bool want_io = false;
        size_t avail = buffer_read_len(&conn->b2c);
        ssize_t w = nonblocking_write(conn->client_fd, conn->client_ssl,
                                      buffer_read_ptr(&conn->b2c), avail, &want_io);
        if (w > 0) {
            buffer_consume(&conn->b2c, (size_t)w);
            conn->bytes_to_client += (size_t)w;
            conn->last_activity = now;
#ifdef TCP_QUICKACK
            int qack = 1;
            setsockopt(conn->client_fd, IPPROTO_TCP, TCP_QUICKACK, &qack, sizeof(qack));
#endif
        } else if (w < 0) {
            conn->had_error = true;
            worker_close_conn(worker, conn, "b2c_flush_err");
            return;
        } else {
            break;
        }
    }

    // If client closed after full response was received and drained, finish immediately
    // (allows Keep-Alive backend socket to be cleanly pooled or closed gracefully)
    if (conn->client_closed &&
        buffer_available(&conn->c2b) == 0 && buffer_available(&conn->b2c) == 0) {
        worker_close_conn(worker, conn, "client_closed_and_drained");
        return;
    }

    // If backend closed while connection is idle in Keep-Alive, release backend socket
    // and hold client connection open for future requests (HTTP keep-alive decoupling)
    if (conn->backend_closed && !conn->client_closed &&
        buffer_available(&conn->c2b) == 0 && buffer_available(&conn->b2c) == 0 &&
        conn->keep_alive_eligible) {
        if (conn->backend_fd >= 0) {
            epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->backend_fd, NULL);
            worker_clear_fd(worker, conn->backend_fd);
            close(conn->backend_fd);
            conn->backend_fd = -1;
            conn->last_backend_ev = 0;
        }
        if (conn->backend_idx >= 0) {
            release_backend(conn->backend_idx);
            conn->backend_idx = -1;
        }
        conn->backend_closed = false;
        conn->backend_shut_wr = false;
        conn->bytes_to_backend = 0;
        conn->bytes_from_backend = 0;
        conn->l7_session_checked = false;
        add_log("\033[1;36m[CONN POOL]\033[0m Backend closed idle keep-alive socket; holding client socket open for next request");
        worker_update_conn_epoll(worker, conn);
        return;
    }

    // Check half-close completion (send FIN exactly once per direction)
    if (conn->client_closed && buffer_available(&conn->c2b) == 0 && !conn->backend_shut_wr) {
        if (conn->backend_fd >= 0) shutdown(conn->backend_fd, SHUT_WR);
        conn->backend_shut_wr = true;
    }
    if (conn->backend_closed && buffer_available(&conn->b2c) == 0 && !conn->client_shut_wr) {
        add_log("\033[1;33m[HA HALF-CLOSE]\033[0m backend_closed=true, shutting down client_fd=%d SHUT_WR", conn->client_fd);
        if (conn->client_ssl) {
            SSL_shutdown(conn->client_ssl);
        } else if (conn->client_fd >= 0) {
            if (g_config.enable_ssl_offloading) {
                ktls_send_close_notify(conn->client_fd);
            }
            shutdown(conn->client_fd, SHUT_WR);
        }
        conn->client_shut_wr = true;
    }

    // If both closed and buffers drained, terminate connection gracefully
    if (conn->client_closed && conn->backend_closed &&
        buffer_available(&conn->c2b) == 0 && buffer_available(&conn->b2c) == 0) {
        worker_close_conn(worker, conn, "both_closed_and_drained");
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
        if (g_config.enable_cluster &&
            curr->state == CONN_STATE_FORWARDING && curr->backend_fd >= 0 && !curr->fds_replicated) {
            curr->fds_replicated = true;
            curr->last_replicated_bytes = curr->bytes_to_client;
            worker_replicate_conn(curr);
        }
        if (now - curr->last_activity >= timeout_sec) {
            add_log("\033[1;33m[TIMEOUT]\033[0m Connection closed due to inactivity (>%ds) Slowloris protection",
                    timeout_sec);
            curr->had_error = true;
            worker_close_conn(worker, curr, "inactivity_timeout");
        } else if (curr->state == CONN_STATE_PROXY_PROTOCOL && (now - curr->last_activity >= 3)) {
            add_log("\033[1;33m[TIMEOUT]\033[0m PROXY protocol header timeout (>3s) Slowloris protection");
            curr->had_error = true;
            worker_close_conn(worker, curr, "proxy_protocol_timeout");
        } else if (curr->state == CONN_STATE_SSL_HANDSHAKE && (now - curr->hs_start >= 5)) {
            add_log("\033[1;33m[TIMEOUT]\033[0m SSL handshake timeout (>5s)");
            curr->had_error = true;
            worker_close_conn(worker, curr, "ssl_handshake_timeout");
        } else if (curr->state == CONN_STATE_BACKEND_CONNECTING && (now - curr->last_activity >= 2)) {
            add_log("\033[1;33m[TIMEOUT]\033[0m Backend connect timeout (>2s)");
            if (curr->backend_idx >= 0) {
                record_backend_failure(curr->backend_idx);
                curr->backend_idx = -1;
            }
            worker_retry_backend_connect(worker, curr);
        }
        curr = next;
    }
}

static void worker_accept_connection(WorkerThread *worker, int client_fd, const struct sockaddr_storage *client_addr) {
    set_nonblocking(client_fd);
    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

#if defined(__linux__) && defined(SO_BINDTODEVICE)
    if (g_config.enable_cluster) {
        const char *vip_iface = cluster_get_active_vip_iface();
        if (vip_iface && vip_iface[0] != '\0') {
            setsockopt(client_fd, SOL_SOCKET, SO_BINDTODEVICE, vip_iface, (socklen_t)(strlen(vip_iface) + 1));
        }
    }
#endif

    ProxyConnection *conn = worker_alloc_conn(worker);
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
    conn->keep_alive_eligible = true;

    worker_set_fd(worker, client_fd, conn);
    worker_add_conn(worker, conn);

    // Check if PROXY Protocol v1 is expected from upstream client (Non-blocking & Slowloris resilient)
    if (g_config.enable_accept_proxy) {
        bool need_more = false;
        struct sockaddr_storage real_addr = *client_addr;
        if (try_parse_proxy_protocol_v1(client_fd, &real_addr, &need_more)) {
            conn->client_addr = real_addr;
            char real_ip[INET6_ADDRSTRLEN];
            int real_port = 0;
            get_client_ip_port(&conn->client_addr, real_ip, sizeof(real_ip), &real_port);
            add_log("\033[1;35m[PPv1 IN]\033[0m Decoded real client IP: %s:%d", real_ip, real_port);
        } else if (need_more) {
            // Header incomplete: wait for more data non-blockingly via epoll
            conn->state = CONN_STATE_PROXY_PROTOCOL;
            struct epoll_event ev;
            memset(&ev, 0, sizeof(ev));
            ev.data.fd = client_fd;
            ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
            conn->last_client_ev = ev.events;
            epoll_ctl(worker->epfd, EPOLL_CTL_ADD, client_fd, &ev);
            return;
        } else {
            add_log("\033[1;31m[PPv1 ERR]\033[0m Connection rejected: missing or invalid PROXY v1 header");
            conn->had_error = true;
            worker_close_conn(worker, conn, "missing_or_invalid_pp");
            return;
        }
    }

    if (g_config.enable_ssl_offloading) {
        conn->client_ssl = SSL_new(g_global_ssl_ctx);
        if (!conn->client_ssl) {
            conn->had_error = true;
            worker_close_conn(worker, conn, "ssl_new_failed");
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

static void worker_adopt_migrated_connection(WorkerThread *worker, NewConnNode *node) {
    set_nonblocking(node->client_fd);
    int flag = 1;
    setsockopt(node->client_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    ProxyConnection *conn = worker_alloc_conn(worker);
    if (!conn) {
        if (node->backend_fd >= 0) close(node->backend_fd);
        if (node->backend_idx >= 0) release_backend(node->backend_idx);
        close(node->client_fd);
        migrated_stream_release(node->migrated);
        node->migrated = NULL;
        atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
        return;
    }

    conn->client_fd = node->client_fd;
    conn->backend_fd = node->backend_fd;
    conn->backend_idx = node->backend_idx;
    conn->client_addr = node->client_addr;
    conn->last_activity = time(NULL);
    conn->worker = worker;
    conn->keep_alive_eligible = true;
    conn->l7_session_checked = true;
    conn->bytes_to_client = (size_t)node->bytes_to_client;
    conn->bytes_from_backend = 0;
    conn->bytes_to_backend = 0;
    conn->retry_count = 0;
    conn->last_replicated_bytes = conn->bytes_to_client;

    if (node->req_len > 0) {
        uint16_t copy_len = (node->req_len <= sizeof(conn->initial_req))
                            ? node->req_len
                            : (uint16_t)sizeof(conn->initial_req);
        memcpy(conn->initial_req, node->initial_req, copy_len);
        conn->initial_req_len = copy_len;
    }

    worker_set_fd(worker, conn->client_fd, conn);
    worker_add_conn(worker, conn);

    char client_ip[INET6_ADDRSTRLEN];
    int client_port = 0;
    get_client_ip_port(&conn->client_addr, client_ip, sizeof(client_ip), &client_port);

    if (conn->backend_fd >= 0) {
        set_nonblocking(conn->backend_fd);
        setsockopt(conn->backend_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
        worker_set_fd(worker, conn->backend_fd, conn);
        conn->state = CONN_STATE_FORWARDING;

        MigratedStreamState *st = node->migrated;
        bool full_migration = (st != NULL);
        if (st) {
            /* Backend socket came over TCP_REPAIR: resume exactly where the old node stopped */
            ring_copy_in(&conn->c2b, st->c2b, st->c2b_len);
            ring_copy_in(&conn->b2c, st->b2c, st->b2c_len);
            conn->bytes_to_backend = (size_t)st->bytes_to_backend;
            conn->bytes_from_backend = (size_t)st->bytes_from_backend;
            conn->skip_backend_bytes = (size_t)st->skip_backend_bytes;
            conn->keep_alive_eligible = (st->flags & MIGRATED_F_KEEPALIVE) != 0;
            conn->client_shut_wr = (st->flags & MIGRATED_F_CLIENT_SHUT_WR) != 0;
            conn->backend_shut_wr = (st->flags & MIGRATED_F_BACKEND_SHUT_WR) != 0;
            conn->client_closed = (st->flags & MIGRATED_F_CLIENT_CLOSED) != 0;
            conn->backend_closed = (st->flags & MIGRATED_F_BACKEND_CLOSED) != 0;
            conn->client_want_write = buffer_available(&conn->b2c) > 0;
            migrated_stream_release(st);
            node->migrated = NULL;
        }

        add_log("\033[1;32m[HA MIGRATED]\033[0m Adopted active TCP stream %s:%d -> Backend [%d] on Worker %d%s",
                client_ip, client_port, conn->backend_idx, worker->id,
                full_migration ? " (backend socket + buffers migrated)" : "");

        if (g_config.enable_cluster) {
            conn->fds_replicated = true;
            worker_replicate_conn(conn);
        }

        worker_update_conn_epoll(worker, conn);
        worker_handle_forwarding_io(worker, conn, conn->backend_fd, EPOLLIN);
    } else {
        migrated_stream_release(node->migrated);
        node->migrated = NULL;
        conn->fds_replicated = false;
        if (conn->backend_idx >= 0) {
            release_backend(conn->backend_idx);
            conn->backend_idx = -1;
        }
        if (conn->initial_req_len > 0 && conn->bytes_to_client == 0) {
            memcpy(buffer_write_ptr(&conn->c2b), conn->initial_req, conn->initial_req_len);
            buffer_produce(&conn->c2b, conn->initial_req_len);
            conn->skip_backend_bytes = 0;
            conn->retry_count = 0;
            worker_start_backend_connect(worker, conn);
        } else {
            /* Client is idle in Keep-Alive waiting for the next request */
            conn->skip_backend_bytes = 0;
            conn->retry_count = 0;
            conn->state = CONN_STATE_FORWARDING;
            worker_update_conn_epoll(worker, conn);
            add_log("\033[1;32m[HA MIGRATED]\033[0m Adopted idle Keep-Alive stream %s:%d (Worker %d)",
                    client_ip, client_port, worker->id);
        }
    }
}

static void worker_process_new_conns(WorkerThread *worker) {
    char dummy[128];
    while (read(worker->notify_pipe[0], dummy, sizeof(dummy)) > 0);

    if (atomic_exchange_explicit(&worker->resync_requested, false, memory_order_acq_rel)) {
        ProxyConnection *c = worker->conn_list_head;
        while (c) {
            if (c->state == CONN_STATE_FORWARDING &&
                c->client_fd >= 0 && c->backend_fd >= 0) {
                c->fds_replicated = true;
                worker_replicate_conn(c);
            }
            c = c->next;
        }
    }

    if (atomic_exchange_explicit(&worker->handover_requested, false, memory_order_acq_rel)) {
        ProxyConnection *c = worker->conn_list_head;
        while (c) {
            ProxyConnection *next = c->next;
            if (c->client_fd >= 0) {
                c->fds_replicated = true;
                worker_replicate_conn(c);
                c->handed_over = true;
            }
            worker_close_conn(worker, c, "failover_handover");
            c = next;
        }
        atomic_store_explicit(&worker->handover_done, true, memory_order_release);
    }

    pthread_mutex_lock(&worker->queue_mutex);
    NewConnNode *node = worker->queue_head;
    worker->queue_head = NULL;
    worker->queue_tail = NULL;
    pthread_mutex_unlock(&worker->queue_mutex);

    while (node) {
        NewConnNode *next = node->next;
        if (node->is_migrated) {
            worker_adopt_migrated_connection(worker, node);
        } else {
            worker_accept_connection(worker, node->client_fd, &node->client_addr);
        }
        free(node);
        node = next;
    }
}

static void *worker_event_loop(void *arg) {
    WorkerThread *worker = (WorkerThread *)arg;
    time_t last_timeout_check = time(NULL);

    while (g_server_running && worker->running) {
        // Priority drain of pending data in OpenSSL internal buffers
        ProxyConnection *c = worker->conn_list_head;
        while (c) {
            ProxyConnection *next_c = c->next;
            if (c->state == CONN_STATE_FORWARDING && c->client_ssl && !c->client_closed && SSL_pending(c->client_ssl) > 0) {
                size_t space = buffer_write_len(&c->c2b);
                if (space > 0) {
                    bool want_io = false;
                    ssize_t r = nonblocking_read(c->client_fd, c->client_ssl,
                                                 buffer_write_ptr(&c->c2b), space, &want_io);
                    if (r > 0) {
                        buffer_produce(&c->c2b, (size_t)r);
                        c->last_activity = time(NULL);
                        if (!c->l7_session_checked && c->bytes_to_backend == 0 && buffer_available(&c->c2b) > 0) {
                            if (worker_apply_l7_session_affinity(worker, c)) {
                                c = next_c;
                                continue;
                            }
                        }
                        if (c->backend_fd >= 0 && buffer_available(&c->c2b) > 0) {
                            size_t avail = buffer_read_len(&c->c2b);
                            ssize_t w = nonblocking_write(c->backend_fd, NULL,
                                                          buffer_read_ptr(&c->c2b), avail, &want_io);
                            if (w > 0) {
                                buffer_consume(&c->c2b, (size_t)w);
                                c->bytes_to_backend += (size_t)w;
                            } else if (w < 0) {
                                c->had_error = true;
                                worker_close_conn(worker, c, "ssl_pending_backend_write_err");
                                c = next_c;
                                continue;
                            }
                        }
                    } else if (r < 0) {
                        c->had_error = true;
                        worker_close_conn(worker, c, "ssl_pending_client_read_err");
                        c = next_c;
                        continue;
                    }
                }
            }
            c = next_c;
        }

        int nfds = epoll_wait(worker->epfd, worker->current_events, MAX_WORKER_EVENTS, 1000);
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

        worker->current_nfds = nfds;
        bool accept_pending = false;
        bool pipe_pending = false;

        for (int i = 0; i < nfds; i++) {
            worker->current_event_idx = i;
            int curr_fd = worker->current_events[i].data.fd;
            uint32_t ev_mask = worker->current_events[i].events;

            if (curr_fd < 0) continue;

            if (curr_fd == worker->notify_pipe[0]) {
                pipe_pending = true;
                continue;
            }

            if (worker->listen_fd >= 0 && curr_fd == worker->listen_fd) {
                accept_pending = true;
                continue;
            }

            ProxyConnection *conn = worker_get_fd(worker, curr_fd);
            if (!conn) continue;

            if (conn->state == CONN_STATE_PROXY_PROTOCOL) {
                if (ev_mask & EPOLLERR) {
                    conn->had_error = true;
                    worker_close_conn(worker, conn, "pp_epollerr");
                    continue;
                }
                bool need_more = false;
                struct sockaddr_storage real_addr = conn->client_addr;
                if (try_parse_proxy_protocol_v1(conn->client_fd, &real_addr, &need_more)) {
                    conn->client_addr = real_addr;
                    char real_ip[INET6_ADDRSTRLEN];
                    int real_port = 0;
                    get_client_ip_port(&conn->client_addr, real_ip, sizeof(real_ip), &real_port);
                    add_log("\033[1;35m[PPv1 IN]\033[0m Decoded real client IP: %s:%d", real_ip, real_port);

                    conn->last_activity = time(NULL);
                    if (g_config.enable_ssl_offloading) {
                        conn->client_ssl = SSL_new(g_global_ssl_ctx);
                        if (!conn->client_ssl) {
                            conn->had_error = true;
                            worker_close_conn(worker, conn, "pp_ssl_new_failed");
                            continue;
                        }
                        SSL_set_fd(conn->client_ssl, conn->client_fd);
                        conn->state = CONN_STATE_SSL_HANDSHAKE;
                        conn->hs_start = time(NULL);
                        worker_step_ssl_handshake(worker, conn);
                    } else {
                        epoll_ctl(worker->epfd, EPOLL_CTL_DEL, conn->client_fd, NULL);
                        conn->last_client_ev = 0;
                        worker_start_backend_connect(worker, conn);
                    }
                } else if (need_more) {
                    conn->last_activity = time(NULL);
                } else {
                    add_log("\033[1;31m[PPv1 ERR]\033[0m Connection rejected: malformed PROXY v1 header");
                    conn->had_error = true;
                    worker_close_conn(worker, conn, "malformed_pp_header");
                }
            } else if (conn->state == CONN_STATE_SSL_HANDSHAKE) {
                worker_step_ssl_handshake(worker, conn);
            } else if (conn->state == CONN_STATE_BACKEND_CONNECTING) {
                worker_handle_backend_connecting(worker, conn, curr_fd, ev_mask);
            } else if (conn->state == CONN_STATE_FORWARDING) {
                worker_handle_forwarding_io(worker, conn, curr_fd, ev_mask);
            }
        }

        worker->current_nfds = 0;
        worker->current_event_idx = 0;

        if (pipe_pending) {
            worker_process_new_conns(worker);
        }

        if (accept_pending && worker->listen_fd >= 0) {
            while (g_server_running && worker->running) {
                struct sockaddr_storage client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(worker->listen_fd, (struct sockaddr *)&client_addr, &client_len);
                if (client_fd < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                    break;
                }

                if (atomic_load_explicit(&g_active_clients, memory_order_relaxed) >= g_config.max_connections) {
                    close(client_fd);
                    static time_t last_warn = 0;
                    time_t now_w = time(NULL);
                    if (now_w - last_warn >= 2) {
                        add_log("\033[1;31m[DROP]\033[0m Connection rejected: max-connections limit (%d) reached",
                                g_config.max_connections);
                        last_warn = now_w;
                    }
                    continue;
                }

                atomic_fetch_add_explicit(&g_active_clients, 1, memory_order_relaxed);
                worker_accept_connection(worker, client_fd, &client_addr);
            }
        }
    }

    // Shutdown cleanup of active connections
    while (worker->conn_list_head) {
        worker_close_conn(worker, worker->conn_list_head, "worker_cleanup");
    }

    // Drain worker local slab pool
    while (worker->conn_pool_head) {
        ProxyConnection *next_p = worker->conn_pool_head->next;
        free(worker->conn_pool_head);
        worker->conn_pool_head = next_p;
    }
    worker->conn_pool_count = 0;

    if (worker->listen_fd >= 0) {
        close(worker->listen_fd);
        worker->listen_fd = -1;
    }

    return NULL;
}

bool worker_pool_init(int num_workers) {
    if (num_workers <= 0) num_workers = 4;
    s_workers = calloc((size_t)num_workers, sizeof(WorkerThread));
    if (!s_workers) {
        fprintf(stderr, "\033[1;31m[ERROR]\033[0m Failed to allocate memory for %d worker structures\n", num_workers);
        return false;
    }
    s_num_workers = num_workers;

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 512 * 1024); // 512 KB stack per worker

    for (int i = 0; i < num_workers; i++) {
        WorkerThread *w = &s_workers[i];
        w->id = i;
        w->running = true;
        w->epfd = epoll_create1(0);
        if (w->epfd < 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Worker [%d] failed to create epoll/kqueue: %s (errno %d)\n",
                    i, strerror(errno), errno);
            pthread_attr_destroy(&attr);
            return false;
        }

        if (pipe(w->notify_pipe) < 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Worker [%d] failed to create notify pipe: %s (errno %d)\n",
                    i, strerror(errno), errno);
            pthread_attr_destroy(&attr);
            return false;
        }
        set_nonblocking(w->notify_pipe[0]);
        set_nonblocking(w->notify_pipe[1]);

        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.data.fd = w->notify_pipe[0];
        ev.events = EPOLLIN;
        if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->notify_pipe[0], &ev) < 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Worker [%d] failed to add notify pipe to epoll: %s\n",
                    i, strerror(errno));
            pthread_attr_destroy(&attr);
            return false;
        }

        // Bind per-worker listening socket only in standalone mode when main global listener is inactive
        w->listen_fd = -1;
        if (g_config.listen_port > 0 && g_global_server_fd < 0 && !g_config.enable_cluster) {
            w->listen_fd = create_tcp_server_socket(g_config.listen_port);
            if (w->listen_fd >= 0) {
                set_nonblocking(w->listen_fd);
                struct epoll_event ev_listen;
                memset(&ev_listen, 0, sizeof(ev_listen));
                ev_listen.data.fd = w->listen_fd;
                ev_listen.events = EPOLLIN;
                if (epoll_ctl(w->epfd, EPOLL_CTL_ADD, w->listen_fd, &ev_listen) < 0) {
                    close(w->listen_fd);
                    w->listen_fd = -1;
                }
            }
        }

        pthread_mutex_init(&w->queue_mutex, NULL);

        if (pthread_create(&w->thread, &attr, worker_event_loop, w) != 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Worker [%d] failed to spawn pthread: %s (errno %d)\n",
                    i, strerror(errno), errno);
            pthread_attr_destroy(&attr);
            return false;
        }
    }
    pthread_attr_destroy(&attr);

    add_log("\033[1;32m[SYSTEM]\033[0m Initialized epoll worker pool with %d threads", num_workers);
    return true;
}

void worker_pool_dispatch(int client_fd, const struct sockaddr_storage *client_addr) {
    if (s_num_workers <= 0 || !s_workers) {
        close(client_fd);
        atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
        return;
    }

    int idx = (int)((unsigned int)atomic_fetch_add_explicit(&s_next_worker, 1, memory_order_relaxed) % (unsigned int)s_num_workers);
    WorkerThread *worker = &s_workers[idx];

    NewConnNode *node = calloc(1, sizeof(NewConnNode));
    if (!node) {
        close(client_fd);
        atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
        return;
    }
    node->client_fd = client_fd;
    node->backend_fd = -1;
    node->backend_idx = -1;
    node->is_migrated = false;
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
    ssize_t w_ign = write(worker->notify_pipe[1], &signal_byte, 1);
    (void)w_ign;
}

void worker_pool_adopt_migrated_conn(int client_fd,
                                     int backend_fd,
                                     int backend_idx,
                                     const struct sockaddr_storage *client_addr,
                                     const char *initial_req,
                                     uint16_t req_len,
                                     uint64_t bytes_to_client,
                                     MigratedStreamState *migrated) {
    if (s_num_workers <= 0 || !s_workers || client_fd < 0 || !client_addr) {
        if (backend_fd >= 0) close(backend_fd);
        if (client_fd >= 0) close(client_fd);
        migrated_stream_release(migrated);
        return;
    }

    NewConnNode *node = calloc(1, sizeof(NewConnNode));
    if (!node) {
        if (backend_fd >= 0) close(backend_fd);
        close(client_fd);
        migrated_stream_release(migrated);
        return;
    }
    node->migrated = (backend_fd >= 0) ? migrated : NULL;
    if (backend_fd < 0) migrated_stream_release(migrated);

    node->client_fd = client_fd;
    node->backend_fd = backend_fd;
    node->backend_idx = backend_idx;
    node->is_migrated = true;
    node->bytes_to_client = bytes_to_client;
    node->client_addr = *client_addr;
    if (initial_req && req_len > 0) {
        if (req_len > sizeof(node->initial_req)) req_len = sizeof(node->initial_req);
        memcpy(node->initial_req, initial_req, req_len);
        node->req_len = req_len;
    }
    node->next = NULL;

    atomic_fetch_add_explicit(&g_active_clients, 1, memory_order_relaxed);
    if (backend_idx >= 0 && backend_idx < g_num_backends) {
        atomic_fetch_add_explicit(&g_backends[backend_idx].active_connections, 1, memory_order_relaxed);
    }

    int idx = (int)((unsigned int)atomic_fetch_add_explicit(&s_next_worker, 1, memory_order_relaxed) % (unsigned int)s_num_workers);
    WorkerThread *worker = &s_workers[idx];

    pthread_mutex_lock(&worker->queue_mutex);
    if (worker->queue_tail) {
        worker->queue_tail->next = node;
        worker->queue_tail = node;
    } else {
        worker->queue_head = node;
        worker->queue_tail = node;
    }
    pthread_mutex_unlock(&worker->queue_mutex);

    char signal_byte = 'm';
    ssize_t w_ign1 = write(worker->notify_pipe[1], &signal_byte, 1);
    (void)w_ign1;
}

void worker_pool_handover_active_conns(void) {
    if (s_num_workers <= 0 || !s_workers) return;

    for (int i = 0; i < s_num_workers; i++) {
        WorkerThread *w = &s_workers[i];
        atomic_store_explicit(&w->handover_done, false, memory_order_relaxed);
        atomic_store_explicit(&w->handover_requested, true, memory_order_release);
        char signal_byte = 'h';
        ssize_t w_ign2 = write(w->notify_pipe[1], &signal_byte, 1);
        (void)w_ign2;
    }

    /* VIP release must wait for every checkpoint: a stream not yet checkpointed is lost */
    for (int wait_ms = 0; wait_ms < 1000; wait_ms++) {
        bool all_done = true;
        for (int i = 0; i < s_num_workers; i++) {
            if (!atomic_load_explicit(&s_workers[i].handover_done, memory_order_acquire)) {
                all_done = false;
                break;
            }
        }
        if (all_done) break;
        struct timespec ts = {0, 1000000L}; // 1ms
        nanosleep(&ts, NULL);
    }
}

void worker_pool_resync_live_conns(void) {
    if (s_num_workers <= 0 || !s_workers) return;
    for (int i = 0; i < s_num_workers; i++) {
        WorkerThread *w = &s_workers[i];
        atomic_store_explicit(&w->resync_requested, true, memory_order_release);
        char signal_byte = 'r';
        ssize_t w_ign3 = write(w->notify_pipe[1], &signal_byte, 1);
        (void)w_ign3;
    }
}

void worker_pool_shutdown(void) {
    if (!s_workers) return;

    // Stop accepting on worker sockets and allow in-flight active connections to drain gracefully
    for (int i = 0; i < s_num_workers; i++) {
        WorkerThread *w = &s_workers[i];
        if (w->listen_fd >= 0) {
            epoll_ctl(w->epfd, EPOLL_CTL_DEL, w->listen_fd, NULL);
            close(w->listen_fd);
            w->listen_fd = -1;
        }
    }

    for (int wait_ms = 0; wait_ms < 1500; wait_ms += 10) {
        if (atomic_load_explicit(&g_active_clients, memory_order_relaxed) <= 0) {
            break;
        }
        struct timespec ts = {0, 10000000L}; // 10ms
        nanosleep(&ts, NULL);
    }

    for (int i = 0; i < s_num_workers; i++) {
        WorkerThread *w = &s_workers[i];
        w->running = false;
        char c = 'q';
        ssize_t w_ign4 = write(w->notify_pipe[1], &c, 1);
        (void)w_ign4;
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
            migrated_stream_release(n->migrated);
            free(n);
            n = tmp;
        }
    }
    conn_pool_destroy();
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
            size_t space = buffer_write_len(&c2b);
            if (space > 0) {
                bool want_io = false;
                ssize_t r = nonblocking_read(client_fd, client_ssl, buffer_write_ptr(&c2b), space, &want_io);
                if (r > 0) {
                    buffer_produce(&c2b, (size_t)r);
                    last_activity = time(NULL);
                }
            }
        }

        if (buffer_available(&c2b) > 0) {
            bool want_io = false;
            size_t avail = buffer_read_len(&c2b);
            ssize_t w = nonblocking_write(backend_fd, NULL, buffer_read_ptr(&c2b), avail, &want_io);
            if (w > 0) {
                buffer_consume(&c2b, (size_t)w);
                last_activity = time(NULL);
            } else if (w < 0) {
                break;
            }
        }

        if (buffer_available(&b2c) > 0) {
            bool want_io = false;
            size_t avail = buffer_read_len(&b2c);
            ssize_t w = nonblocking_write(client_fd, client_ssl, buffer_read_ptr(&b2c), avail, &want_io);
            if (w > 0) {
                buffer_consume(&b2c, (size_t)w);
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
                    size_t space = buffer_write_len(&c2b);
                    if (space > 0) {
                        bool want_io = false;
                        ssize_t r = nonblocking_read(client_fd, client_ssl, buffer_write_ptr(&c2b), space, &want_io);
                        if (r > 0) {
                            buffer_produce(&c2b, (size_t)r);
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
                        size_t avail = buffer_read_len(&b2c);
                        ssize_t w = nonblocking_write(client_fd, client_ssl, buffer_read_ptr(&b2c), avail, &want_io);
                        if (w > 0) {
                            buffer_consume(&b2c, (size_t)w);
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
                    size_t space = buffer_write_len(&b2c);
                    if (space > 0) {
                        bool want_io = false;
                        ssize_t r = nonblocking_read(backend_fd, NULL, buffer_write_ptr(&b2c), space, &want_io);
                        if (r > 0) {
                            buffer_produce(&b2c, (size_t)r);
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
                        size_t avail = buffer_read_len(&c2b);
                        ssize_t w = nonblocking_write(backend_fd, NULL, buffer_read_ptr(&c2b), avail, &want_io);
                        if (w > 0) {
                            buffer_consume(&c2b, (size_t)w);
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
    struct sockaddr_storage client_addr = ctx->client_addr;
    free(ctx);

    if (g_config.enable_accept_proxy) {
        // In legacy blocking thread mode, parse_proxy_protocol_v1
        struct sockaddr_in real_in;
        if (parse_proxy_protocol_v1(client_fd, &real_in)) {
            memset(&client_addr, 0, sizeof(client_addr));
            memcpy(&client_addr, &real_in, sizeof(real_in));
            char real_ip[INET6_ADDRSTRLEN];
            int real_port = 0;
            get_client_ip_port(&client_addr, real_ip, sizeof(real_ip), &real_port);
            add_log("\033[1;35m[PPv1 IN]\033[0m Decoded real client IP: %s:%d", real_ip, real_port);
        } else {
            add_log("\033[1;31m[PPv1 ERR]\033[0m Connection rejected: missing or invalid PROXY v1 header");
            close(client_fd);
            goto cleanup;
        }
    }

    char client_ip[INET6_ADDRSTRLEN];
    int client_port = 0;
    get_client_ip_port(&client_addr, client_ip, sizeof(client_ip), &client_port);

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

        char b_ip[64];
        int b_port;
        pthread_mutex_lock(&g_backend_mutex);
        snprintf(b_ip, sizeof(b_ip), "%s", g_backends[backend_idx].ip);
        b_port = g_backends[backend_idx].port;
        pthread_mutex_unlock(&g_backend_mutex);

        backend_fd = connect_with_timeout_transparent(b_ip, b_port, 1000, &client_addr);
        if (backend_fd >= 0) {
            record_backend_success(backend_idx);
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
            struct sockaddr_storage lb_addr;
            socklen_t lb_len = sizeof(lb_addr);
            if (getsockname(client_fd, (struct sockaddr *)&lb_addr, &lb_len) != 0) {
                memset(&lb_addr, 0, sizeof(lb_addr));
                lb_addr.ss_family = AF_INET;
                ((struct sockaddr_in *)&lb_addr)->sin_port = htons((uint16_t)g_config.listen_port);
            }
            char pp_hdr[128];
            int pp_len = build_proxy_protocol_v1_header_storage(pp_hdr, sizeof(pp_hdr), &client_addr, &lb_addr);
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
        SSL_set_quiet_shutdown(client_ssl, 1);
        SSL_shutdown(client_ssl);
        SSL_free(client_ssl);
    }
    close(client_fd);

cleanup:
    atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
    return NULL;
}
