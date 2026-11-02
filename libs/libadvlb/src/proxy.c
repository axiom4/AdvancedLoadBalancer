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

#define PROXY_INACTIVITY_TIMEOUT_SEC 30

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

// 100% Non-Blocking and Event-Driven forwarding with Slowloris / Slow-Read protection
void forward_traffic_dual_epoll(int client_fd, SSL *client_ssl, int backend_fd) {
    set_nonblocking(client_fd);
    set_nonblocking(backend_fd);

    int flag = 1;
    setsockopt(client_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));
    setsockopt(backend_fd, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(int));

    // Set safety inactivity timeout on socket level
    struct timeval sock_tv = { .tv_sec = PROXY_INACTIVITY_TIMEOUT_SEC, .tv_usec = 0 };
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &sock_tv, sizeof(sock_tv));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDTIMEO, &sock_tv, sizeof(sock_tv));
    setsockopt(backend_fd, SOL_SOCKET, SO_RCVTIMEO, &sock_tv, sizeof(sock_tv));
    setsockopt(backend_fd, SOL_SOCKET, SO_SNDTIMEO, &sock_tv, sizeof(sock_tv));

    int epfd = epoll_create1(0);
    if (epfd < 0) return;

    StreamBuffer c2b = { .head = 0, .tail = 0 };
    StreamBuffer b2c = { .head = 0, .tail = 0 };

    bool client_closed = false;
    bool backend_closed = false;

    uint32_t last_client_ev = 0;
    uint32_t last_backend_ev = 0;

    struct epoll_event ev;
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

    while (g_server_running) {
        // Priority drain of pending data in OpenSSL internal buffer
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

        // If c2b has data, attempt immediate flush to backend non-blocking
        if (buffer_available(&c2b) > 0) {
            bool want_io = false;
            ssize_t w = nonblocking_write(backend_fd, NULL, c2b.data + c2b.head, buffer_available(&c2b), &want_io);
            if (w > 0) {
                c2b.head += (size_t)w;
                last_activity = time(NULL);
            } else if (w < 0) {
                break; // Backend error
            }
        }

        // If b2c has data, attempt immediate flush to client non-blocking
        if (buffer_available(&b2c) > 0) {
            bool want_io = false;
            ssize_t w = nonblocking_write(client_fd, client_ssl, b2c.data + b2c.head, buffer_available(&b2c), &want_io);
            if (w > 0) {
                b2c.head += (size_t)w;
                last_activity = time(NULL);
            } else if (w < 0) {
                break; // Client error
            }
        }

        // Check connection completion / half-close
        if (client_closed && buffer_available(&c2b) == 0 && !backend_closed) {
            shutdown(backend_fd, SHUT_WR);
        }
        if (backend_closed && buffer_available(&b2c) == 0 && !client_closed) {
            if (client_ssl) {
                SSL_shutdown(client_ssl);
            } else {
                shutdown(client_fd, SHUT_WR);
            }
        }
        if (client_closed && backend_closed && buffer_available(&c2b) == 0 && buffer_available(&b2c) == 0) {
            break; // Both streams gracefully finished
        }

        // Dynamic epoll event configuration (Automatic Backpressure)
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

        // Wait for events with 1000ms timeout for periodic inactivity check
        int nfds = epoll_wait(epfd, events, 4, 1000);
        time_t now = time(NULL);

        if (now - last_activity >= PROXY_INACTIVITY_TIMEOUT_SEC) {
            add_log("\033[1;33m[TIMEOUT]\033[0m Connection closed due to inactivity (>%ds) Slowloris protection",
                    PROXY_INACTIVITY_TIMEOUT_SEC);
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

            // Events on CLIENT
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

            // Events on BACKEND
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

    // If accepting PROXY Protocol v1 from upstream client/proxy is enabled
    if (g_config.enable_accept_proxy) {
        struct sockaddr_in real_client_addr = client_addr;
        if (parse_proxy_protocol_v1(client_fd, &real_client_addr)) {
            client_addr = real_client_addr;
            add_log("\033[1;35m[PPv1 IN]\033[0m Decoded real client IP: %s:%d",
                    inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        } else {
            // If --accept-proxy is required and header is missing/invalid, close for safety
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
                if (wait_res == 0) break; // Timeout
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
