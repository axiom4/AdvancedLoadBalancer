#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdatomic.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#ifndef NO_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

#define MAX_CONCURRENCY 1024
#define MAX_MOCK_BACKENDS 32
#define MAX_DETECTED_BACKENDS 64
#define BUFFER_SIZE 8192

// Configuration structure
typedef struct {
    char target_ip[128];
    int target_port;
    int concurrency;
    unsigned long total_requests;
    int duration_sec;
    bool keep_alive;
    bool mixed_mode;
    int mixed_requests;
    int mixed_ratio;
    bool use_udp;
    bool use_ssl;
    bool send_proxy_proto;
    bool use_session;
    char http_path[256];
    char post_data[1024];
    int mock_backends_count;
    int mock_backend_base_port;
    bool mock_backends_only;
    bool verbose;
} ClientConfig;

static ClientConfig g_cfg;
static volatile sig_atomic_t g_running = 1;

// Global metrics
static atomic_ulong g_reqs_dispatched = 0;
static atomic_ulong g_reqs_completed = 0;
static atomic_ulong g_reqs_success = 0;
static atomic_ulong g_reqs_failed = 0;
static atomic_ulong g_bytes_received = 0;
static atomic_ulong g_connections_opened = 0;
static atomic_ulong g_reqs_keepalive = 0;
static atomic_ulong g_reqs_new_conn = 0;

// Diagnostics metrics
static atomic_ulong g_fail_connect = 0;
static atomic_ulong g_fail_ssl = 0;
static atomic_ulong g_fail_send = 0;
static atomic_ulong g_fail_recv = 0;
static atomic_ulong g_reqs_retried = 0;       // Distinct requests requiring >= 1 retry
static atomic_ulong g_app_retransmits = 0;    // Total application retry attempts
static atomic_ulong g_tcp_kernel_retrans = 0; // Kernel TCP packet retransmissions
static char g_last_ssl_err[128] = "none";
static char g_last_conn_err[128] = "none";
static char g_last_recv_err[128] = "none";
static pthread_mutex_t g_err_str_mutex = PTHREAD_MUTEX_INITIALIZER;

// Backend hit tracking
static pthread_mutex_t g_backend_map_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_detected_ports[MAX_DETECTED_BACKENDS];
static atomic_ulong g_detected_counts[MAX_DETECTED_BACKENDS];
static int g_num_detected = 0;

#ifndef NO_SSL
static SSL_CTX *g_ssl_ctx = NULL;
#endif

// Socket retransmission metric helpers
static unsigned long get_socket_retransmits(int fd) {
    if (fd < 0) return 0;
#if defined(__APPLE__) && defined(TCP_CONNECTION_INFO)
    struct tcp_connection_info ci;
    socklen_t len = sizeof(ci);
    if (getsockopt(fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &ci, &len) == 0) {
        return (unsigned long)ci.tcpi_txretransmitpackets;
    }
#elif defined(TCP_INFO)
    struct tcp_info ti;
    socklen_t len = sizeof(ti);
    if (getsockopt(fd, IPPROTO_TCP, TCP_INFO, &ti, &len) == 0) {
#if defined(__linux__)
        return (unsigned long)ti.tcpi_total_retrans;
#else
        return (unsigned long)ti.tcpi_retrans;
#endif
    }
#endif
    return 0;
}

static void harvest_socket_retransmits(int fd, unsigned long *prev_retrans) {
    if (fd < 0) return;
    unsigned long cur = get_socket_retransmits(fd);
    unsigned long prev = prev_retrans ? *prev_retrans : 0;
    if (cur > prev) {
        atomic_fetch_add_explicit(&g_tcp_kernel_retrans, cur - prev, memory_order_relaxed);
    }
    if (prev_retrans) {
        *prev_retrans = cur;
    }
}

// High-resolution timer helper
static double get_time_sec(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static void record_backend_hit(int port) {
    if (port <= 0) return;
    pthread_mutex_lock(&g_backend_map_mutex);
    int idx = -1;
    for (int i = 0; i < g_num_detected; i++) {
        if (g_detected_ports[i] == port) {
            idx = i;
            break;
        }
    }
    if (idx == -1 && g_num_detected < MAX_DETECTED_BACKENDS) {
        idx = g_num_detected++;
        g_detected_ports[idx] = port;
        atomic_init(&g_detected_counts[idx], 0);
    }
    pthread_mutex_unlock(&g_backend_map_mutex);

    if (idx >= 0) {
        atomic_fetch_add_explicit(&g_detected_counts[idx], 1, memory_order_relaxed);
    }
}

static void handle_sigint(int sig) {
    (void)sig;
    g_running = 0;
}

static int cmp_double(const void *a, const void *b) {
    double da = *(const double *)a;
    double db = *(const double *)b;
    if (da < db) return -1;
    if (da > db) return 1;
    return 0;
}

// ============================================================================
// MOCK BACKEND SERVERS (FOR INSTANT LOCAL ZERO-SETUP TESTING)
// ============================================================================
typedef struct {
    int port;
    bool use_udp;
} MockBackendArgs;

typedef struct {
    int fd;
    int port;
} MockClientConn;

static void *mock_client_worker(void *arg) {
    MockClientConn *mc = (MockClientConn *)arg;
    int cfd = mc->fd;
    int port = mc->port;
    free(mc);

    // Clear O_NONBLOCK inherited from listening socket on BSD/macOS
    int fl = fcntl(cfd, F_GETFL, 0);
    if (fl >= 0 && (fl & O_NONBLOCK)) {
        fcntl(cfd, F_SETFL, fl & ~O_NONBLOCK);
    }

    struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };
    setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int flag = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    char req[BUFFER_SIZE];
    while (g_running) {
        ssize_t n = recv(cfd, req, sizeof(req) - 1, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;

        req[n] = '\0';
        if (strncmp(req, "PING", 4) == 0) {
            const char *pong = "PONG\r\n";
            send(cfd, pong, strlen(pong), 0);
            break;
        }

        bool want_close = (strcasestr(req, "Connection: close") != NULL) ||
                          (strstr(req, "HTTP/1.0") != NULL && strcasestr(req, "Connection: keep-alive") == NULL);

        char body[256];
        int body_len = snprintf(body, sizeof(body), "Response from mock backend on port %d\n", port);

        char resp[1024];
        int resp_len = snprintf(resp, sizeof(resp),
            "HTTP/1.1 200 OK\r\n"
            "Server: MockBackend/%d\r\n"
            "X-Backend-Port: %d\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: %d\r\n"
            "Connection: %s\r\n"
            "\r\n"
            "%s",
            port, port, body_len, want_close ? "close" : "keep-alive", body);

        if (send(cfd, resp, (size_t)resp_len, 0) <= 0) {
            break;
        }
        if (want_close) {
            break;
        }
    }
    close(cfd);
    return NULL;
}

static void *mock_backend_thread(void *arg) {
    MockBackendArgs *m_args = (MockBackendArgs *)arg;
    int port = m_args->port;
    bool is_udp = m_args->use_udp;
    free(m_args);

    if (is_udp) {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) return NULL;

        int opt = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons((uint16_t)port);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            close(fd);
            return NULL;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        char buf[BUFFER_SIZE];

        while (g_running) {
            int ret = poll(&pfd, 1, 200);
            if (ret > 0 && (pfd.revents & POLLIN)) {
                struct sockaddr_in client;
                socklen_t clen = sizeof(client);
                ssize_t n = recvfrom(fd, buf, sizeof(buf) - 1, 0, (struct sockaddr *)&client, &clen);
                if (n > 0) {
                    buf[n] = '\0';
                    char reply[512];
                    int rlen = snprintf(reply, sizeof(reply), "PONG :%d (echo: %.*s)", port, (int)(n > 32 ? 32 : n), buf);
                    sendto(fd, reply, (size_t)rlen, 0, (struct sockaddr *)&client, clen);
                }
            }
        }
        close(fd);
        return NULL;
    }

    // TCP Mock Backend
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) return NULL;

    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
    setsockopt(sfd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((uint16_t)port);

    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        if (g_cfg.verbose) fprintf(stderr, "[MOCK BACKEND ERROR] Failed to bind to port %d: %s\n", port, strerror(errno));
        close(sfd);
        return NULL;
    }

    int flags = fcntl(sfd, F_GETFL, 0);
    fcntl(sfd, F_SETFL, flags | O_NONBLOCK);

    if (listen(sfd, 4096) < 0) {
        close(sfd);
        return NULL;
    }

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&attr, 256 * 1024);

    struct pollfd pfd = { .fd = sfd, .events = POLLIN, .revents = 0 };

    while (g_running) {
        int ret = poll(&pfd, 1, 100);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            while (g_running) {
                struct sockaddr_in caddr;
                socklen_t clen = sizeof(caddr);
                int cfd = accept(sfd, (struct sockaddr *)&caddr, &clen);
                if (cfd < 0) {
                    if (errno == EINTR) continue;
                    break;
                }

                MockClientConn *mc = malloc(sizeof(MockClientConn));
                if (!mc) {
                    close(cfd);
                    continue;
                }
                mc->fd = cfd;
                mc->port = port;

                pthread_t tid;
                if (pthread_create(&tid, &attr, mock_client_worker, mc) != 0) {
                    mock_client_worker(mc);
                }
            }
        }
    }

    pthread_attr_destroy(&attr);
    close(sfd);
    return NULL;
}

static void spawn_mock_backends(int count, int base_port, bool use_udp) {
    printf("\033[1;36m[MOCK BACKENDS]\033[0m Starting %d local mock servers on ports %d..%d (%s)...\n",
           count, base_port, base_port + count - 1, use_udp ? "UDP" : "TCP/HTTP");

    for (int i = 0; i < count; i++) {
        MockBackendArgs *args = malloc(sizeof(MockBackendArgs));
        if (!args) continue;
        args->port = base_port + i;
        args->use_udp = use_udp;

        pthread_t tid;
        if (pthread_create(&tid, NULL, mock_backend_thread, args) == 0) {
            pthread_detach(tid);
        } else {
            free(args);
        }
    }
    usleep(100000); // 100ms warm-up
}

// ============================================================================
// WORKER CLIENT THREAD
// ============================================================================
typedef struct {
    int thread_id;
    double *latencies;
    size_t latency_count;
    size_t latency_cap;
} WorkerContext;

static int connect_to_target(const char *ip, int port, bool use_udp) {
    int sock_type = use_udp ? SOCK_DGRAM : SOCK_STREAM;
    int fd = socket(AF_INET, sock_type, 0);
    if (fd < 0) return -1;

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &sin.sin_addr) <= 0) {
        close(fd);
        return -1;
    }

    struct timeval tv = { .tv_sec = 3, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

#ifdef TCP_CONNECTIONTIMEOUT
    int conn_timeout = 2; // macOS connect timeout
    setsockopt(fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &conn_timeout, sizeof(conn_timeout));
#endif
#ifdef TCP_SYNCNT
    int syn_retries = 2; // Linux connect timeout
    setsockopt(fd, IPPROTO_TCP, TCP_SYNCNT, &syn_retries, sizeof(syn_retries));
#endif

    if (!use_udp) {
        int opt = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        int rc = connect(fd, (struct sockaddr *)&sin, sizeof(sin));
        if (rc < 0) {
            if (errno == EINPROGRESS || errno == EWOULDBLOCK) {
                struct pollfd pfd;
                pfd.fd = fd;
                pfd.events = POLLOUT;
                pfd.revents = 0;
                int prc = poll(&pfd, 1, 2500);
                if (prc > 0 && (pfd.revents & (POLLOUT | POLLERR | POLLHUP))) {
                    int err = 0;
                    socklen_t errlen = sizeof(err);
                    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen) == 0 && err == 0) {
                        if (flags >= 0) fcntl(fd, F_SETFL, flags);
                        return fd;
                    } else if (err != 0) {
                        errno = err;
                    }
                } else if (prc == 0) {
                    errno = ETIMEDOUT;
                }
            }
            close(fd);
            return -1;
        }
        if (flags >= 0) fcntl(fd, F_SETFL, flags);
    } else {
        if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
            close(fd);
            return -1;
        }
    }

    return fd;
}

static const useconds_t s_failover_backoffs[] = {
    15000,   // 15ms
    35000,   // 35ms
    75000,   // 75ms
    150000,  // 150ms
    250000,  // 250ms
    400000,  // 400ms
    600000   // 600ms (~1.5s total retry window across cluster switchover)
};
#define MAX_CONN_ATTEMPTS (int)(sizeof(s_failover_backoffs) / sizeof(s_failover_backoffs[0]))

static void *worker_client_thread(void *arg) {
    WorkerContext *ctx = (WorkerContext *)arg;
    char req_buf_ka[2048];
    char req_buf_close[2048];
    char resp_buf[BUFFER_SIZE];

    // Build HTTP request payloads (precomputed for Keep-Alive and Close)
    int req_len_ka = 0;
    int req_len_close = 0;
    if (!g_cfg.use_udp) {
        char proxy_hdr[256] = "";
        if (g_cfg.send_proxy_proto) {
            snprintf(proxy_hdr, sizeof(proxy_hdr), "PROXY TCP4 192.168.1.100 %s 54321 %d\r\n",
                     g_cfg.target_ip, g_cfg.target_port);
        }

        char sess_hdr[128] = "";
        if (g_cfg.use_session || g_cfg.keep_alive || g_cfg.mixed_mode) {
            snprintf(sess_hdr, sizeof(sess_hdr), "X-Session-ID: adlb-sess-worker-%d\r\n", ctx->thread_id);
        }

        if (strlen(g_cfg.post_data) > 0) {
            req_len_ka = snprintf(req_buf_ka, sizeof(req_buf_ka),
                "%sPOST %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: adlb-test-client/1.0\r\n"
                "%s"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %zu\r\n"
                "Connection: keep-alive\r\n"
                "\r\n"
                "%s",
                proxy_hdr, g_cfg.http_path, g_cfg.target_ip, g_cfg.target_port,
                sess_hdr, strlen(g_cfg.post_data),
                g_cfg.post_data);

            req_len_close = snprintf(req_buf_close, sizeof(req_buf_close),
                "%sPOST %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: adlb-test-client/1.0\r\n"
                "%s"
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: %zu\r\n"
                "Connection: close\r\n"
                "\r\n"
                "%s",
                proxy_hdr, g_cfg.http_path, g_cfg.target_ip, g_cfg.target_port,
                sess_hdr, strlen(g_cfg.post_data),
                g_cfg.post_data);
        } else {
            req_len_ka = snprintf(req_buf_ka, sizeof(req_buf_ka),
                "%sGET %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: adlb-test-client/1.0\r\n"
                "%s"
                "Connection: keep-alive\r\n"
                "\r\n",
                proxy_hdr, g_cfg.http_path, g_cfg.target_ip, g_cfg.target_port,
                sess_hdr);

            req_len_close = snprintf(req_buf_close, sizeof(req_buf_close),
                "%sGET %s HTTP/1.1\r\n"
                "Host: %s:%d\r\n"
                "User-Agent: adlb-test-client/1.0\r\n"
                "%s"
                "Connection: close\r\n"
                "\r\n",
                proxy_hdr, g_cfg.http_path, g_cfg.target_ip, g_cfg.target_port,
                sess_hdr);
        }
    } else {
        req_len_ka = snprintf(req_buf_ka, sizeof(req_buf_ka), "PING adlb-load-test payload\r\n");
        req_len_close = req_len_ka;
        memcpy(req_buf_close, req_buf_ka, (size_t)req_len_ka);
    }

    int active_fd = -1;
    unsigned long active_fd_prev_retrans = 0;
#ifndef NO_SSL
    SSL *active_ssl = NULL;
#endif

    // Session / Burst state for realistic mixed traffic simulation
    unsigned int seed = (unsigned int)(time(NULL) ^ ((uintptr_t)&seed) ^ ((unsigned int)ctx->thread_id << 16));
    int burst_target = (g_cfg.mixed_requests > 0) ? g_cfg.mixed_requests : 10;
    int current_conn_reqs = 0;
    int current_burst_limit = burst_target;
    if (g_cfg.mixed_mode && g_cfg.mixed_ratio == 0) {
        int min_reqs = (burst_target > 2) ? (burst_target * 7 / 10) : 1;
        int max_reqs = (burst_target * 13 / 10) + 1;
        current_burst_limit = min_reqs + (rand_r(&seed) % (max_reqs - min_reqs + 1));
    }

    while (g_running) {
        unsigned long req_idx = atomic_fetch_add_explicit(&g_reqs_dispatched, 1, memory_order_relaxed);
        if (g_cfg.total_requests > 0 && req_idx >= g_cfg.total_requests) {
            break;
        }

        double t_start = get_time_sec();
        bool success = false;
        bool had_retry = false;
        bool is_new_conn = false;
        ssize_t received_bytes = 0;

        // Determine whether this request is the last in the current connection burst
        bool is_last_in_burst = false;
        if (g_cfg.mixed_mode) {
            if (g_cfg.mixed_ratio > 0) {
                if (current_conn_reqs > 0 && (rand_r(&seed) % 100) >= g_cfg.mixed_ratio) {
                    is_last_in_burst = true;
                }
            } else {
                if (current_conn_reqs + 1 >= current_burst_limit) {
                    is_last_in_burst = true;
                }
            }
        } else if (!g_cfg.keep_alive) {
            is_last_in_burst = true;
        }

        const char *cur_req_buf = is_last_in_burst ? req_buf_close : req_buf_ka;
        int cur_req_len = is_last_in_burst ? req_len_close : req_len_ka;

        for (int attempt = 0; attempt < MAX_CONN_ATTEMPTS && !success && g_running; attempt++) {
            if (attempt > 0) {
                had_retry = true;
                atomic_fetch_add_explicit(&g_app_retransmits, 1, memory_order_relaxed);
#ifndef NO_SSL
                if (active_ssl) {
                    SSL_free(active_ssl);
                    active_ssl = NULL;
                }
#endif
                if (active_fd >= 0) {
                    harvest_socket_retransmits(active_fd, &active_fd_prev_retrans);
#ifdef __APPLE__
                    struct linger sl = { .l_onoff = 1, .l_linger = 0 };
                    setsockopt(active_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#endif
                    close(active_fd);
                    active_fd = -1;
                    active_fd_prev_retrans = 0;
                }
                useconds_t backoff = s_failover_backoffs[attempt - 1];
                usleep(backoff);
            }

            if (active_fd < 0) {
                active_fd = connect_to_target(g_cfg.target_ip, g_cfg.target_port, g_cfg.use_udp);
                active_fd_prev_retrans = 0;
                if (active_fd < 0) {
                    if (attempt < MAX_CONN_ATTEMPTS - 1) continue;
                    atomic_fetch_add_explicit(&g_fail_connect, 1, memory_order_relaxed);
                    pthread_mutex_lock(&g_err_str_mutex);
                    snprintf(g_last_conn_err, sizeof(g_last_conn_err), "%s", strerror(errno));
                    pthread_mutex_unlock(&g_err_str_mutex);
                    if (g_cfg.verbose) fprintf(stderr, "[CLIENT ERROR] Connect failed to %s:%d: %s\n", g_cfg.target_ip, g_cfg.target_port, strerror(errno));
                    break;
                }

#ifndef NO_SSL
                if (g_cfg.use_ssl && !g_cfg.use_udp) {
                    active_ssl = SSL_new(g_ssl_ctx);
                    SSL_set_fd(active_ssl, active_fd);
                    if (SSL_connect(active_ssl) <= 0) {
                        unsigned long err = ERR_get_error();
                        char err_buf[128] = "";
                        ERR_error_string_n(err, err_buf, sizeof(err_buf));
                        SSL_free(active_ssl);
                        active_ssl = NULL;
                        harvest_socket_retransmits(active_fd, &active_fd_prev_retrans);
#ifdef __APPLE__
                        struct linger sl = { .l_onoff = 1, .l_linger = 0 };
                        setsockopt(active_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#endif
                        close(active_fd);
                        active_fd = -1;
                        active_fd_prev_retrans = 0;
                        if (attempt < MAX_CONN_ATTEMPTS - 1) continue;
                        atomic_fetch_add_explicit(&g_fail_ssl, 1, memory_order_relaxed);
                        pthread_mutex_lock(&g_err_str_mutex);
                        snprintf(g_last_ssl_err, sizeof(g_last_ssl_err), "%s", err_buf[0] ? err_buf : strerror(errno));
                        pthread_mutex_unlock(&g_err_str_mutex);
                        if (g_cfg.verbose) fprintf(stderr, "[CLIENT ERROR] SSL_connect failed: %s\n", g_last_ssl_err);
                        break;
                    }
                }
#endif
                atomic_fetch_add_explicit(&g_connections_opened, 1, memory_order_relaxed);
                is_new_conn = true;
            }

            // Send request
            bool write_ok = false;
#ifndef NO_SSL
            if (g_cfg.use_ssl && active_ssl) {
                int ret = SSL_write(active_ssl, cur_req_buf, cur_req_len);
                write_ok = (ret == cur_req_len);
            } else
#endif
            {
                ssize_t ret = send(active_fd, cur_req_buf, (size_t)cur_req_len, 0);
                write_ok = (ret == cur_req_len);
            }

            if (write_ok) {
                // Read response completely (supporting Content-Length and stream EOF)
                size_t total_resp_bytes = 0;
                size_t content_len = 0;
                bool has_content_len = false;
                bool headers_complete = false;
                size_t header_len = 0;

                while (1) {
                    ssize_t n = 0;
#ifndef NO_SSL
                    if (g_cfg.use_ssl && active_ssl) {
                        if (total_resp_bytes < sizeof(resp_buf) - 1) {
                            n = SSL_read(active_ssl, resp_buf + total_resp_bytes,
                                         (int)(sizeof(resp_buf) - 1 - total_resp_bytes));
                        } else {
                            char discard[4096];
                            n = SSL_read(active_ssl, discard, sizeof(discard));
                        }
                    } else
#endif
                    {
                        if (total_resp_bytes < sizeof(resp_buf) - 1) {
                            n = recv(active_fd, resp_buf + total_resp_bytes,
                                     sizeof(resp_buf) - 1 - total_resp_bytes, 0);
                        } else {
                            char discard[4096];
                            n = recv(active_fd, discard, sizeof(discard), 0);
                        }
                    }

                    if (n > 0) {
                        if (total_resp_bytes < sizeof(resp_buf) - 1) {
                            size_t copy_len = (size_t)n;
                            if (total_resp_bytes + copy_len > sizeof(resp_buf) - 1) {
                                copy_len = sizeof(resp_buf) - 1 - total_resp_bytes;
                            }
                            total_resp_bytes += copy_len;
                            resp_buf[total_resp_bytes] = '\0';
                        }
                        received_bytes += n;

                        if (!headers_complete) {
                            char *hdr_end = strstr(resp_buf, "\r\n\r\n");
                            if (hdr_end) {
                                headers_complete = true;
                                header_len = (size_t)(hdr_end - resp_buf) + 4;
                                char *cl_hdr = strcasestr(resp_buf, "Content-Length:");
                                if (cl_hdr && cl_hdr < hdr_end) {
                                    content_len = (size_t)strtoull(cl_hdr + 15, NULL, 10);
                                    has_content_len = true;
                                }
                            }
                        }

                        if (headers_complete) {
                            if (has_content_len) {
                                if ((size_t)received_bytes >= header_len + content_len) {
                                    break;
                                }
                            } else if (strstr(resp_buf, "\r\n0\r\n\r\n") != NULL ||
                                       strstr(resp_buf, "\r\n0\r\n") != NULL) {
                                break;
                            } else if (!is_last_in_burst && (g_cfg.keep_alive || g_cfg.mixed_mode)) {
                                break;
                            }
                        }
                    } else if (n == 0) {
                        /* Server closed socket (EOF) - response finished */
                        break;
                    } else {
                        if (errno == EINTR) continue;
                        break;
                    }
                }

                if (received_bytes > 0) {
                    resp_buf[total_resp_bytes] = '\0';
                    success = true;

                    // Inspect response for backend identity
                    int detected_port = 0;
                    char *hdr = strcasestr(resp_buf, "X-Backend-Port:");
                    if (hdr) {
                        sscanf(hdr + 15, " %d", &detected_port);
                    } else {
                        char *sub = strstr(resp_buf, "port ");
                        if (!sub) sub = strstr(resp_buf, "port:");
                        if (!sub) sub = strstr(resp_buf, ":900");
                        if (sub) {
                            while (*sub && (*sub < '0' || *sub > '9')) sub++;
                            sscanf(sub, "%d", &detected_port);
                        }
                    }
                    if (detected_port > 0) {
                        record_backend_hit(detected_port);
                    }

                    // Check if server requested connection closure
                    if (!is_last_in_burst && (g_cfg.keep_alive || g_cfg.mixed_mode)) {
                        char *conn_hdr = strcasestr(resp_buf, "Connection:");
                        if (conn_hdr) {
                            char *line_end = strstr(conn_hdr, "\r\n");
                            if (line_end && (size_t)(line_end - conn_hdr) < 64) {
                                char hdr_val[64];
                                size_t hlen = (size_t)(line_end - conn_hdr);
                                memcpy(hdr_val, conn_hdr, hlen);
                                hdr_val[hlen] = '\0';
                                if (strcasestr(hdr_val, "close")) {
                                    is_last_in_burst = true;
                                }
                            }
                        }
                    }
                } else {
                    if (attempt < MAX_CONN_ATTEMPTS - 1) continue;
                    atomic_fetch_add_explicit(&g_fail_recv, 1, memory_order_relaxed);
                    pthread_mutex_lock(&g_err_str_mutex);
                    if (received_bytes == 0) {
                        snprintf(g_last_recv_err, sizeof(g_last_recv_err), "Server closed socket prematurely (EOF)");
                    } else {
                        snprintf(g_last_recv_err, sizeof(g_last_recv_err), "%s", strerror(errno));
                    }
                    pthread_mutex_unlock(&g_err_str_mutex);
                    if (g_cfg.verbose) fprintf(stderr, "[CLIENT ERROR] Recv failed or EOF (n=%zd): %s\n", received_bytes, strerror(errno));
                }
            } else {
                if (attempt == 0) continue;
                atomic_fetch_add_explicit(&g_fail_send, 1, memory_order_relaxed);
                if (g_cfg.verbose) fprintf(stderr, "[CLIENT ERROR] Send failed: %s\n", strerror(errno));
            }
        }

        if (had_retry) {
            atomic_fetch_add_explicit(&g_reqs_retried, 1, memory_order_relaxed);
        }

        if (active_fd >= 0) {
            harvest_socket_retransmits(active_fd, &active_fd_prev_retrans);
        }

        double t_end = get_time_sec();
        double lat_ms = (t_end - t_start) * 1000.0;

        if (success) {
            atomic_fetch_add_explicit(&g_reqs_success, 1, memory_order_relaxed);
            atomic_fetch_add_explicit(&g_bytes_received, (unsigned long)received_bytes, memory_order_relaxed);
            if (is_new_conn) {
                atomic_fetch_add_explicit(&g_reqs_new_conn, 1, memory_order_relaxed);
            } else {
                atomic_fetch_add_explicit(&g_reqs_keepalive, 1, memory_order_relaxed);
            }

            // Record latency
            if (ctx->latency_count < ctx->latency_cap) {
                ctx->latencies[ctx->latency_count++] = lat_ms;
            }
        } else {
            atomic_fetch_add_explicit(&g_reqs_failed, 1, memory_order_relaxed);
        }

        atomic_fetch_add_explicit(&g_reqs_completed, 1, memory_order_relaxed);

        current_conn_reqs++;

        // Connection reuse & termination management
        bool should_close = false;
        if (!success) {
            should_close = true;
        } else if (g_cfg.mixed_mode) {
            if (is_last_in_burst) {
                should_close = true;
            }
        } else if (!g_cfg.keep_alive) {
            should_close = true;
        }

        if (should_close) {
#ifndef NO_SSL
            if (active_ssl) {
                SSL_set_quiet_shutdown(active_ssl, 1);
                SSL_shutdown(active_ssl);
                SSL_free(active_ssl);
                active_ssl = NULL;
            }
#endif
            if (active_fd >= 0) {
                harvest_socket_retransmits(active_fd, &active_fd_prev_retrans);
#ifdef __APPLE__
                struct linger sl = { .l_onoff = 1, .l_linger = 0 };
                setsockopt(active_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#endif
                close(active_fd);
                active_fd = -1;
                active_fd_prev_retrans = 0;
            }
            current_conn_reqs = 0;
            if (g_cfg.mixed_mode && g_cfg.mixed_ratio == 0) {
                int min_reqs = (burst_target > 2) ? (burst_target * 7 / 10) : 1;
                int max_reqs = (burst_target * 13 / 10) + 1;
                current_burst_limit = min_reqs + (rand_r(&seed) % (max_reqs - min_reqs + 1));
            }
        }
    }

#ifndef NO_SSL
    if (active_ssl) {
        SSL_set_quiet_shutdown(active_ssl, 1);
        SSL_shutdown(active_ssl);
        SSL_free(active_ssl);
    }
#endif
    if (active_fd >= 0) {
        harvest_socket_retransmits(active_fd, &active_fd_prev_retrans);
#ifdef __APPLE__
        struct linger sl = { .l_onoff = 1, .l_linger = 0 };
        setsockopt(active_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));
#endif
        close(active_fd);
    }

    return NULL;
}

// ============================================================================
// MAIN & SUMMARY REPORTING
// ============================================================================
static void print_usage(const char *prog) {
    printf("\n\033[1;36mADVANCED LOAD BALANCER BENCHMARK & TEST CLIENT\033[0m\n");
    printf("High-concurrency stress test client with automated mock backend support.\n\n");
    printf("Usage:\n");
    printf("  %s [OPTIONS]\n\n", prog);
    printf("Target Options:\n");
    printf("  -t, --target IP:PORT       Target address of Load Balancer (default: 127.0.0.1:8080)\n");
    printf("  -p, --path PATH            HTTP request path (default: /)\n");
    printf("      --post DATA            Send HTTP POST request with DATA body\n");
    printf("  -k, --keep-alive           Enable HTTP Keep-Alive connection reuse\n");
    printf("  -m, --mixed [NUM]          Mixed mode: realistic traffic with Keep-Alive bursts of NUM reqs/conn (default: 10)\n");
    printf("      --mixed-requests NUM   Target number of requests per connection in mixed mode (default: 10)\n");
    printf("      --mixed-ratio PCT      Mixed mode by probability: PCT%% Keep-Alive, (100-PCT)%% fresh connect\n");
    printf("  -s, --ssl                  Enable HTTPS / SSL/TLS mode\n");
    printf("  -u, --udp                  Enable Layer 4 UDP mode (default: TCP)\n");
    printf("  -P, --proxy-protocol       Prepend PROXY Protocol v1 header\n");
    printf("  -S, --session              Send per-worker X-Session-ID header for HA session affinity\n\n");
    printf("Load & Concurrency Options:\n");
    printf("  -c, --concurrency NUM      Number of concurrent client worker threads (default: 10)\n");
    printf("  -n, --requests NUM         Total number of requests to execute (default: 1000)\n");
    printf("  -d, --duration SEC         Run for SEC seconds instead of fixed request count\n\n");
    printf("Mock Backend Options (Automated Testing):\n");
    printf("  -M, --mock-backends NUM    Spin up NUM lightweight local backend servers (e.g. -M 3)\n");
    printf("      --backend-port PORT    Base port for mock backends (default: 9001 -> 9001, 9002...)\n");
    printf("      --backends-only        Start only the mock backends and stay running (Ctrl+C to exit)\n\n");
    printf("Other Options:\n");
    printf("  -v, --verbose              Display detailed error messages\n");
    printf("  -h, --help                 Display this help message and exit\n\n");
    printf("Examples:\n");
    printf("  1) Instant all-in-one test (spawns 3 backends on 9001-9003 and benchmarks LB on 8080):\n");
    printf("     %s -M 3 -c 20 -n 5000\n\n", prog);
    printf("  2) Test SSL termination on port 8443:\n");
    printf("     %s -t 127.0.0.1:8443 --ssl -c 10 -n 1000\n\n", prog);
    printf("  3) Run only 3 mock backends on 9001, 9002, 9003 for manual testing:\n");
    printf("     %s --mock-backends 3 --backends-only\n\n", prog);
    printf("  4) Realistic mixed web traffic (~10 requests per connection over SSL):\n");
    printf("     %s -t 127.0.0.1:8443 --ssl -m 10 -c 6 -n 10000\n\n", prog);
}

int main(int argc, char *argv[]) {
    // Default configuration
    snprintf(g_cfg.target_ip, sizeof(g_cfg.target_ip), "%s", "127.0.0.1");
    g_cfg.target_port = 8080;
    g_cfg.concurrency = 10;
    g_cfg.total_requests = 1000;
    g_cfg.duration_sec = 0;
    g_cfg.keep_alive = false;
    g_cfg.mixed_mode = false;
    g_cfg.mixed_requests = 10;
    g_cfg.mixed_ratio = 0;
    g_cfg.use_udp = false;
    g_cfg.use_ssl = false;
    g_cfg.send_proxy_proto = false;
    g_cfg.use_session = false;
    snprintf(g_cfg.http_path, sizeof(g_cfg.http_path), "%s", "/");
    g_cfg.post_data[0] = '\0';
    g_cfg.mock_backends_count = 0;
    g_cfg.mock_backend_base_port = 9001;
    g_cfg.mock_backends_only = false;
    g_cfg.verbose = false;

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--target") == 0) {
            if (++i < argc) {
                char *colon = strchr(argv[i], ':');
                if (colon) {
                    *colon = '\0';
                    snprintf(g_cfg.target_ip, sizeof(g_cfg.target_ip), "%s", argv[i]);
                    g_cfg.target_port = atoi(colon + 1);
                } else {
                    snprintf(g_cfg.target_ip, sizeof(g_cfg.target_ip), "%s", argv[i]);
                }
            }
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--concurrency") == 0) {
            if (++i < argc) g_cfg.concurrency = atoi(argv[i]);
        } else if (strcmp(argv[i], "-n") == 0 || strcmp(argv[i], "--requests") == 0) {
            if (++i < argc) g_cfg.total_requests = (unsigned long)atol(argv[i]);
        } else if (strcmp(argv[i], "-d") == 0 || strcmp(argv[i], "--duration") == 0) {
            if (++i < argc) g_cfg.duration_sec = atoi(argv[i]);
        } else if (strcmp(argv[i], "-k") == 0 || strcmp(argv[i], "--keep-alive") == 0) {
            g_cfg.keep_alive = true;
        } else if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--mixed") == 0) {
            g_cfg.mixed_mode = true;
            if (i + 1 < argc && argv[i + 1][0] >= '0' && argv[i + 1][0] <= '9') {
                g_cfg.mixed_requests = atoi(argv[++i]);
            }
        } else if (strcmp(argv[i], "--mixed-requests") == 0) {
            g_cfg.mixed_mode = true;
            if (++i < argc) g_cfg.mixed_requests = atoi(argv[i]);
        } else if (strcmp(argv[i], "--mixed-ratio") == 0) {
            g_cfg.mixed_mode = true;
            if (++i < argc) g_cfg.mixed_ratio = atoi(argv[i]);
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            g_cfg.use_udp = true;
        } else if (strcmp(argv[i], "-s") == 0 || strcmp(argv[i], "--ssl") == 0) {
            g_cfg.use_ssl = true;
        } else if (strcmp(argv[i], "-P") == 0 || strcmp(argv[i], "--proxy-protocol") == 0) {
            g_cfg.send_proxy_proto = true;
        } else if (strcmp(argv[i], "-S") == 0 || strcmp(argv[i], "--session") == 0) {
            g_cfg.use_session = true;
        } else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--path") == 0) {
            if (++i < argc) snprintf(g_cfg.http_path, sizeof(g_cfg.http_path), "%s", argv[i]);
        } else if (strcmp(argv[i], "--post") == 0) {
            if (++i < argc) snprintf(g_cfg.post_data, sizeof(g_cfg.post_data), "%s", argv[i]);
        } else if (strcmp(argv[i], "-M") == 0 || strcmp(argv[i], "--mock-backends") == 0) {
            if (++i < argc) g_cfg.mock_backends_count = atoi(argv[i]);
        } else if (strcmp(argv[i], "--backend-port") == 0) {
            if (++i < argc) g_cfg.mock_backend_base_port = atoi(argv[i]);
        } else if (strcmp(argv[i], "--backends-only") == 0) {
            g_cfg.mock_backends_only = true;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            g_cfg.verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (g_cfg.concurrency <= 0) g_cfg.concurrency = 1;
    if (g_cfg.concurrency > MAX_CONCURRENCY) g_cfg.concurrency = MAX_CONCURRENCY;

    // Signal handlers
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigint;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct sigaction sa_pipe;
    memset(&sa_pipe, 0, sizeof(sa_pipe));
    sa_pipe.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa_pipe, NULL);

    // Mock backends launch
    if (g_cfg.mock_backends_count > 0 || g_cfg.mock_backends_only) {
        if (g_cfg.mock_backends_count <= 0) g_cfg.mock_backends_count = 3;
        spawn_mock_backends(g_cfg.mock_backends_count, g_cfg.mock_backend_base_port, g_cfg.use_udp);

        if (g_cfg.mock_backends_only) {
            printf("\033[1;32m[READY]\033[0m Mock backends running on ports %d..%d. Press Ctrl+C to stop.\n",
                   g_cfg.mock_backend_base_port, g_cfg.mock_backend_base_port + g_cfg.mock_backends_count - 1);
            while (g_running) {
                sleep(1);
            }
            printf("\n\033[1;33m[STOPPED]\033[0m Mock backends terminated cleanly.\n");
            return 0;
        }
    }

#ifndef NO_SSL
    if (g_cfg.use_ssl) {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        g_ssl_ctx = SSL_CTX_new(TLS_client_method());
        if (!g_ssl_ctx) {
            fprintf(stderr, "Failed to initialize SSL client context.\n");
            return 1;
        }
        SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    }
#else
    if (g_cfg.use_ssl) {
        fprintf(stderr, "Error: Compiled with NO_SSL, HTTPS mode is not available.\n");
        return 1;
    }
#endif

    char conn_info[128];
    if (g_cfg.mixed_mode) {
        if (g_cfg.mixed_ratio > 0) {
            snprintf(conn_info, sizeof(conn_info), "Mixed (%d%% Keep-Alive / %d%% Fresh Connect)",
                     g_cfg.mixed_ratio, 100 - g_cfg.mixed_ratio);
        } else {
            snprintf(conn_info, sizeof(conn_info), "Mixed (~%d reqs/conn, realistic sessions)",
                     g_cfg.mixed_requests);
        }
    } else if (g_cfg.keep_alive) {
        snprintf(conn_info, sizeof(conn_info), "Keep-Alive");
    } else {
        snprintf(conn_info, sizeof(conn_info), "Close");
    }

    printf("\n\033[1;34m================================================================================\033[0m\n");
    printf("\033[1;37m        STARTING LOAD TEST ON %s://%s:%d%s\033[0m\n",
           g_cfg.use_udp ? "udp" : (g_cfg.use_ssl ? "https" : "http"),
           g_cfg.target_ip, g_cfg.target_port, g_cfg.http_path);
    printf("  Concurrency: %d workers | Target Requests: %lu | Connection: %s\n",
           g_cfg.concurrency, g_cfg.total_requests, conn_info);
    if (g_cfg.mixed_mode) {
        printf("  Traffic Profile   : Realistic Web Session Churn (bursts with clean reconnects)\n");
    }
    if (g_cfg.send_proxy_proto) printf("  PROXY Protocol v1: ENABLED\n");
    printf("\033[1;34m================================================================================\033[0m\n");

    // Allocate per-thread latency buffers
    pthread_t threads[MAX_CONCURRENCY];
    WorkerContext contexts[MAX_CONCURRENCY];
    size_t samples_per_thread = (g_cfg.total_requests / (size_t)g_cfg.concurrency) + 2048;
    if (samples_per_thread < 10000) samples_per_thread = 10000;
    if (samples_per_thread > 200000) samples_per_thread = 200000;

    for (int i = 0; i < g_cfg.concurrency; i++) {
        contexts[i].thread_id = i;
        contexts[i].latency_count = 0;
        contexts[i].latency_cap = samples_per_thread;
        contexts[i].latencies = malloc(samples_per_thread * sizeof(double));
    }

    double start_time = get_time_sec();

    // Spawn worker threads
    for (int i = 0; i < g_cfg.concurrency; i++) {
        pthread_create(&threads[i], NULL, worker_client_thread, &contexts[i]);
    }

    // Progress reporter loop
    unsigned long last_completed = 0;
    double last_time = start_time;

    while (g_running) {
        usleep(500000); // 500ms
        double now = get_time_sec();
        unsigned long completed = atomic_load_explicit(&g_reqs_completed, memory_order_relaxed);
        unsigned long failed = atomic_load_explicit(&g_reqs_failed, memory_order_relaxed);
        unsigned long retries = atomic_load_explicit(&g_app_retransmits, memory_order_relaxed);
        double delta_t = now - last_time;
        double current_rps = (delta_t > 0) ? (double)(completed - last_completed) / delta_t : 0.0;
        last_completed = completed;
        last_time = now;

        double pct = (g_cfg.total_requests > 0) ? ((double)completed / (double)g_cfg.total_requests) * 100.0 : 0.0;
        if (pct > 100.0) pct = 100.0;

        printf("\r\033[K[PROGRESS] %lu/%lu (%5.1f%%) | %8.1f req/s | failures: %lu | retries: %lu",
               completed, g_cfg.total_requests, pct, current_rps, failed, retries);
        fflush(stdout);

        if (g_cfg.duration_sec > 0 && (now - start_time) >= g_cfg.duration_sec) {
            g_running = 0;
            break;
        }
        if (g_cfg.total_requests > 0 && completed >= g_cfg.total_requests) {
            break;
        }
    }

    // Join workers
    for (int i = 0; i < g_cfg.concurrency; i++) {
        pthread_join(threads[i], NULL);
    }
    double end_time = get_time_sec();
    double total_duration = end_time - start_time;

    printf("\r\033[K\n");

    // Merge and sort latencies
    size_t total_samples = 0;
    for (int i = 0; i < g_cfg.concurrency; i++) {
        total_samples += contexts[i].latency_count;
    }

    double *all_latencies = NULL;
    if (total_samples > 0) {
        all_latencies = malloc(total_samples * sizeof(double));
        size_t offset = 0;
        for (int i = 0; i < g_cfg.concurrency; i++) {
            memcpy(all_latencies + offset, contexts[i].latencies, contexts[i].latency_count * sizeof(double));
            offset += contexts[i].latency_count;
        }
        qsort(all_latencies, total_samples, sizeof(double), cmp_double);
    }

    // Cleanup worker buffers
    for (int i = 0; i < g_cfg.concurrency; i++) {
        free(contexts[i].latencies);
    }

    unsigned long total_completed = atomic_load_explicit(&g_reqs_completed, memory_order_relaxed);
    unsigned long total_success = atomic_load_explicit(&g_reqs_success, memory_order_relaxed);
    unsigned long total_failed = atomic_load_explicit(&g_reqs_failed, memory_order_relaxed);
    unsigned long total_retried = atomic_load_explicit(&g_reqs_retried, memory_order_relaxed);
    unsigned long total_app_retries = atomic_load_explicit(&g_app_retransmits, memory_order_relaxed);
    unsigned long total_tcp_retrans = atomic_load_explicit(&g_tcp_kernel_retrans, memory_order_relaxed);
    unsigned long total_bytes = atomic_load_explicit(&g_bytes_received, memory_order_relaxed);

    double rps = (total_duration > 0) ? (double)total_completed / total_duration : 0.0;
    double mb_received = (double)total_bytes / (1024.0 * 1024.0);
    double mb_sec = (total_duration > 0) ? mb_received / total_duration : 0.0;

    double lat_min = 0.0, lat_avg = 0.0, lat_p50 = 0.0, lat_p90 = 0.0, lat_p95 = 0.0, lat_p99 = 0.0, lat_max = 0.0;
    if (total_samples > 0 && all_latencies) {
        lat_min = all_latencies[0];
        lat_max = all_latencies[total_samples - 1];
        lat_p50 = all_latencies[(size_t)(total_samples * 0.50)];
        lat_p90 = all_latencies[(size_t)(total_samples * 0.90)];
        lat_p95 = all_latencies[(size_t)(total_samples * 0.95)];
        lat_p99 = all_latencies[(size_t)(total_samples * 0.99)];

        double sum = 0.0;
        for (size_t i = 0; i < total_samples; i++) sum += all_latencies[i];
        lat_avg = sum / (double)total_samples;
    }

    // ============================================================================
    // BENCHMARK REPORT CARD
    // ============================================================================
    printf("\033[1;32m================================================================================\033[0m\n");
    printf("\033[1;37m                       LOAD BALANCER TEST REPORT\033[0m\n");
    printf("\033[1;32m================================================================================\033[0m\n");
    printf("Target Endpoint       : %s://%s:%d%s\n",
           g_cfg.use_udp ? "udp" : (g_cfg.use_ssl ? "https" : "http"),
           g_cfg.target_ip, g_cfg.target_port, g_cfg.http_path);
    printf("Mode / Protocol       : %s%s\n",
           g_cfg.use_udp ? "Layer 4 UDP" : "Layer 7 TCP / HTTP",
           g_cfg.use_ssl ? " (TLS/SSL Termination)" : "");
    printf("Concurrency Level     : %d client threads\n", g_cfg.concurrency);
    printf("Connection Mode       : %s\n", conn_info);
    if (!g_cfg.use_udp) {
        unsigned long conns = atomic_load_explicit(&g_connections_opened, memory_order_relaxed);
        unsigned long ka_reqs = atomic_load_explicit(&g_reqs_keepalive, memory_order_relaxed);
        unsigned long new_reqs = atomic_load_explicit(&g_reqs_new_conn, memory_order_relaxed);
        double avg_reqs = conns > 0 ? (double)total_completed / (double)conns : 0.0;
        printf("TCP Connections       : %lu opened (avg %.2f reqs/conn)\n", conns, avg_reqs);
        if (g_cfg.mixed_mode || g_cfg.keep_alive) {
            printf("Traffic Breakdown     : %lu fresh connects (%.1f%%) | %lu keep-alive reuses (%.1f%%)\n",
                   new_reqs, total_completed > 0 ? ((double)new_reqs / (double)total_completed) * 100.0 : 0.0,
                   ka_reqs, total_completed > 0 ? ((double)ka_reqs / (double)total_completed) * 100.0 : 0.0);
        }
    }
    printf("Total Test Time       : %6.3f seconds\n", total_duration);
    printf("Completed Requests    : %lu\n", total_completed);
    printf("Successful Requests   : \033[1;32m%lu\033[0m (%5.2f%%)\n",
           total_success, total_completed > 0 ? ((double)total_success / (double)total_completed) * 100.0 : 0.0);
    printf("Failed Requests       : %s%lu\033[0m (%5.2f%%)\n",
           total_failed > 0 ? "\033[1;31m" : "\033[1;32m",
           total_failed, total_completed > 0 ? ((double)total_failed / (double)total_completed) * 100.0 : 0.0);
    printf("Retried Requests      : %s%lu\033[0m (%5.2f%%)\n",
           total_retried > 0 ? "\033[1;33m" : "\033[1;32m",
           total_retried, total_completed > 0 ? ((double)total_retried / (double)total_completed) * 100.0 : 0.0);
    printf("Retransmissions       : %lu (app retries: %lu, kernel TCP pkts: %lu)\n",
           total_app_retries + total_tcp_retrans, total_app_retries, total_tcp_retrans);
    printf("Throughput (RPS)      : \033[1;36m%8.2f req/sec\033[0m\n", rps);
    printf("Data Transferred      : %6.2f MB (%6.2f MB/s)\n", mb_received, mb_sec);

    if (total_failed > 0) {
        printf("\n\033[1;31mFailure Breakdown & Diagnostics:\033[0m\n");
        unsigned long fc = atomic_load_explicit(&g_fail_connect, memory_order_relaxed);
        unsigned long fs = atomic_load_explicit(&g_fail_ssl, memory_order_relaxed);
        unsigned long f_snd = atomic_load_explicit(&g_fail_send, memory_order_relaxed);
        unsigned long fr = atomic_load_explicit(&g_fail_recv, memory_order_relaxed);
        if (fc > 0)    printf("  TCP Connect Errors  : %lu (Last: %s)\n", fc, g_last_conn_err);
        if (fs > 0)    printf("  SSL Handshake Errors: %lu (Last: %s)\n", fs, g_last_ssl_err);
        if (f_snd > 0) printf("  Send Request Errors : %lu\n", f_snd);
        if (fr > 0)    printf("  Recv Response / EOF : %lu (Last: %s)\n", fr, g_last_recv_err);
    }

    if (total_samples > 0) {
        printf("\n\033[1;37mLatency Distribution (Round-Trip Time):\033[0m\n");
        printf("  Min Latency         : %6.2f ms\n", lat_min);
        printf("  Avg Latency         : %6.2f ms\n", lat_avg);
        printf("  Median (p50)        : %6.2f ms\n", lat_p50);
        printf("  90%% Percentile (p90): %6.2f ms\n", lat_p90);
        printf("  95%% Percentile (p95): %6.2f ms\n", lat_p95);
        printf("  99%% Percentile (p99): %6.2f ms\n", lat_p99);
        printf("  Max Latency         : %6.2f ms\n", lat_max);
    }

    // Backend Distribution Breakdown
    if (g_num_detected > 0) {
        printf("\n\033[1;37mBackend Request Distribution Breakdown:\033[0m\n");
        unsigned long total_hits = 0;
        for (int i = 0; i < g_num_detected; i++) {
            total_hits += atomic_load_explicit(&g_detected_counts[i], memory_order_relaxed);
        }

        for (int i = 0; i < g_num_detected; i++) {
            unsigned long cnt = atomic_load_explicit(&g_detected_counts[i], memory_order_relaxed);
            double pct = (total_hits > 0) ? ((double)cnt / (double)total_hits) * 100.0 : 0.0;

            // Visual bar (20 chars)
            int bars = (int)(pct / 5.0);
            if (bars > 20) bars = 20;
            char bar_buf[64] = "";
            for (int b = 0; b < bars; b++) strcat(bar_buf, "█");
            for (int b = bars; b < 20; b++) strcat(bar_buf, "░");

            printf("  Backend :%-5d       : %6lu reqs (%5.1f%%) [%s]\n",
                   g_detected_ports[i], cnt, pct, bar_buf);
        }
    }
    printf("\033[1;32m================================================================================\033[0m\n\n");

    if (all_latencies) free(all_latencies);
#ifndef NO_SSL
    if (g_ssl_ctx) SSL_CTX_free(g_ssl_ctx);
#endif

    return (total_failed == 0) ? 0 : 1;
}
