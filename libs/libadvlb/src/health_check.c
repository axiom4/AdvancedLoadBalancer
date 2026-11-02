#define _GNU_SOURCE
#include "advlb/health_check.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/net_utils.h"
#include "advlb/compat_epoll.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <strings.h>

const char *health_check_name(HealthCheckType type) {
    switch (type) {
        case HC_TYPE_TCP:     return "TCP (L4)";
        case HC_TYPE_HTTP:    return "HTTP (L7)";
        case HC_TYPE_PAYLOAD: return g_config.enable_udp_mode ? "UDP Payload" : "Payload";
        default:              return "Unknown";
    }
}

static inline const char *safe_http_path(const char *path) {
    if (!path || path[0] != '/') return "/";
    for (size_t i = 0; path[i] != '\0'; i++) {
        unsigned char c = (unsigned char)path[i];
        if (c <= 32 || c >= 127) return "/";
    }
    return path;
}

void finalize_payload_config(void) {
    bool is_http = (strncasecmp(g_config.hc_send_payload, "GET ", 4) == 0 ||
                    strncasecmp(g_config.hc_send_payload, "HEAD ", 5) == 0 ||
                    strncasecmp(g_config.hc_send_payload, "POST ", 5) == 0 ||
                    strncasecmp(g_config.hc_send_payload, "OPTIONS ", 8) == 0 ||
                    strncasecmp(g_config.hc_send_payload, "PUT ", 4) == 0);

    if (is_http) {
        if (!strstr(g_config.hc_send_payload, "\r\n\r\n") && !strstr(g_config.hc_send_payload, "\n\n")) {
            size_t len = strlen(g_config.hc_send_payload);
            if (len > 0 && g_config.hc_send_payload[len - 1] != '\n' && g_config.hc_send_payload[len - 1] != '\r') {
                strncat(g_config.hc_send_payload, "\r\n", sizeof(g_config.hc_send_payload) - strlen(g_config.hc_send_payload) - 1);
            }
            if (!strcasestr(g_config.hc_send_payload, "Host:")) {
                strncat(g_config.hc_send_payload, "Host: localhost\r\n", sizeof(g_config.hc_send_payload) - strlen(g_config.hc_send_payload) - 1);
            }
            if (!strcasestr(g_config.hc_send_payload, "Connection:")) {
                strncat(g_config.hc_send_payload, "Connection: close\r\n", sizeof(g_config.hc_send_payload) - strlen(g_config.hc_send_payload) - 1);
            }
            strncat(g_config.hc_send_payload, "\r\n", sizeof(g_config.hc_send_payload) - strlen(g_config.hc_send_payload) - 1);
        }

        if (!g_config.hc_expect_explicitly_set) {
            strncpy(g_config.hc_expect_payload, "HTTP/", sizeof(g_config.hc_expect_payload) - 1);
            g_config.hc_expect_payload[sizeof(g_config.hc_expect_payload) - 1] = '\0';
        }
    } else if (g_config.hc_send_explicitly_set) {
        size_t len = strlen(g_config.hc_send_payload);
        if (len > 0 && g_config.hc_send_payload[len - 1] != '\n' && g_config.hc_send_payload[len - 1] != '\r') {
            strncat(g_config.hc_send_payload, "\r\n", sizeof(g_config.hc_send_payload) - strlen(g_config.hc_send_payload) - 1);
        }
        if (!g_config.hc_expect_explicitly_set && strncasecmp(g_config.hc_send_payload, "PING", 4) != 0) {
            g_config.hc_expect_payload[0] = '\0';
        }
    }
}

void perform_health_check_cycle(bool is_startup) {
    int epfd = epoll_create1(0);
    if (epfd < 0) return;

    int probe_fds[MAX_BACKENDS];
    struct timespec start_times[MAX_BACKENDS];
    struct timespec end_times[MAX_BACKENDS];
    bool is_healthy[MAX_BACKENDS];
    int probe_stage[MAX_BACKENDS]; // 0=CONNECTING, 1=WAITING_REPLY, 2=DONE
    int active_probes = 0;

    int total_backends = g_num_backends;

    for (int i = 0; i < total_backends; i++) {
        probe_fds[i] = -1;
        is_healthy[i] = false;
        probe_stage[i] = 2; // default DONE

        char ip[INET_ADDRSTRLEN];
        int port;
        pthread_mutex_lock(&g_backend_mutex);
        strncpy(ip, g_backends[i].ip, sizeof(ip));
        port = g_backends[i].port;
        pthread_mutex_unlock(&g_backend_mutex);

        int sock_type = (g_config.enable_udp_mode && g_config.current_hc_type == HC_TYPE_PAYLOAD) ? SOCK_DGRAM : SOCK_STREAM;
        int sfd = socket(AF_INET, sock_type, 0);
        if (sfd < 0) continue;

        set_nonblocking(sfd);

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons((uint16_t)port);
        inet_pton(AF_INET, ip, &addr.sin_addr);

        clock_gettime(CLOCK_MONOTONIC, &start_times[i]);

        int res = connect(sfd, (struct sockaddr *)&addr, sizeof(addr));
        if (res == 0) {
            probe_fds[i] = sfd;
            if (g_config.current_hc_type == HC_TYPE_TCP) {
                clock_gettime(CLOCK_MONOTONIC, &end_times[i]);
                is_healthy[i] = true;
                probe_stage[i] = 2; // DONE
            } else {
                if (g_config.current_hc_type == HC_TYPE_HTTP) {
                    char req[512];
                    int req_len = snprintf(req, sizeof(req),
                                           "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: LB-HealthCheck/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                                           safe_http_path(g_config.hc_http_path), ip, port);
                    write_all(sfd, req, (size_t)req_len);
                } else {
                    write_all(sfd, g_config.hc_send_payload, strlen(g_config.hc_send_payload));
                }
                struct epoll_event ev;
                ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
                ev.data.fd = i;
                if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev) == 0) {
                    probe_stage[i] = 1; // WAITING_REPLY
                    active_probes++;
                } else {
                    close(sfd);
                    probe_fds[i] = -1;
                }
            }
        } else if (errno == EINPROGRESS || errno == EINTR) {
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLERR | EPOLLHUP;
            ev.data.fd = i;
            if (epoll_ctl(epfd, EPOLL_CTL_ADD, sfd, &ev) == 0) {
                probe_fds[i] = sfd;
                probe_stage[i] = 0; // CONNECTING
                active_probes++;
            } else {
                close(sfd);
            }
        } else {
            close(sfd);
        }
    }

    struct timespec wait_start, wait_now;
    clock_gettime(CLOCK_MONOTONIC, &wait_start);
    int remaining_ms = is_startup ? 500 : g_config.hc_timeout_ms;

    while (remaining_ms > 0 && active_probes > 0 && g_server_running) {
        struct epoll_event events[MAX_BACKENDS];
        int nfds = epoll_wait(epfd, events, MAX_BACKENDS, remaining_ms);
        if (nfds < 0) {
            if (errno == EINTR) {
                if (!g_server_running) break;
                continue;
            }
            break;
        }
        if (nfds == 0) break;

        struct timespec now_ts;
        clock_gettime(CLOCK_MONOTONIC, &now_ts);

        for (int e = 0; e < nfds; e++) {
            int idx = events[e].data.fd;
            if (idx < 0 || idx >= total_backends) continue;
            uint32_t ev_mask = events[e].events;

            if (probe_stage[idx] == 0) {
                // Waiting for connection completion (EPOLLOUT)
                int so_error = 0;
                socklen_t len = sizeof(so_error);
                if (getsockopt(probe_fds[idx], SOL_SOCKET, SO_ERROR, &so_error, &len) != 0 || so_error != 0) {
                    probe_stage[idx] = 2; // DONE
                    active_probes--;
                    continue;
                }

                if (g_config.current_hc_type == HC_TYPE_TCP) {
                    end_times[idx] = now_ts;
                    is_healthy[idx] = true;
                    probe_stage[idx] = 2; // DONE
                    active_probes--;
                } else {
                    char ip[INET_ADDRSTRLEN];
                    int port;
                    pthread_mutex_lock(&g_backend_mutex);
                    strncpy(ip, g_backends[idx].ip, sizeof(ip));
                    port = g_backends[idx].port;
                    pthread_mutex_unlock(&g_backend_mutex);

                    if (g_config.current_hc_type == HC_TYPE_HTTP) {
                        char req[512];
                        int req_len = snprintf(req, sizeof(req),
                                               "GET %s HTTP/1.1\r\nHost: %s:%d\r\nUser-Agent: LB-HealthCheck/2.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
                                               safe_http_path(g_config.hc_http_path), ip, port);
                        write_all(probe_fds[idx], req, (size_t)req_len);
                    } else {
                        write_all(probe_fds[idx], g_config.hc_send_payload, strlen(g_config.hc_send_payload));
                    }

                    struct epoll_event ev;
                    ev.events = EPOLLIN | EPOLLERR | EPOLLHUP;
                    ev.data.fd = idx;
                    epoll_ctl(epfd, EPOLL_CTL_MOD, probe_fds[idx], &ev);
                    probe_stage[idx] = 1; // WAITING_REPLY
                }
            } else if (probe_stage[idx] == 1) {
                // Waiting for response (EPOLLIN)
                if (ev_mask & EPOLLIN) {
                    char reply[2048] = {0};
                    ssize_t bytes = read(probe_fds[idx], reply, sizeof(reply) - 1);
                    if (bytes > 0) {
                        reply[bytes] = '\0';
                        if (g_config.current_hc_type == HC_TYPE_HTTP) {
                            char *p = strstr(reply, "HTTP/");
                            if (p) {
                                char *sp = strchr(p, ' ');
                                if (sp) {
                                    while (*sp == ' ') sp++;
                                    int code = atoi(sp);
                                    if (code >= 200 && code < 400) {
                                        is_healthy[idx] = true;
                                    }
                                }
                            }
                        } else if (g_config.current_hc_type == HC_TYPE_PAYLOAD) {
                            if (strlen(g_config.hc_expect_payload) == 0 || strstr(reply, g_config.hc_expect_payload) != NULL) {
                                is_healthy[idx] = true;
                            }
                        }
                        end_times[idx] = now_ts;
                        probe_stage[idx] = 2; // DONE
                        active_probes--;
                    } else if (bytes == 0 || (bytes < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                        end_times[idx] = now_ts;
                        probe_stage[idx] = 2; // DONE
                        active_probes--;
                    }
                } else if (ev_mask & (EPOLLERR | EPOLLHUP)) {
                    end_times[idx] = now_ts;
                    probe_stage[idx] = 2; // DONE
                    active_probes--;
                }
            }
        }

        clock_gettime(CLOCK_MONOTONIC, &wait_now);
        long elapsed = (wait_now.tv_sec - wait_start.tv_sec) * 1000 + 
                       (wait_now.tv_nsec - wait_start.tv_nsec) / 1000000;
        remaining_ms = (is_startup ? 500 : g_config.hc_timeout_ms) - (int)elapsed;
    }

    close(epfd);

    struct {
        int idx;
        int event_type; // 0=none, 1=init_up, 2=init_down, 3=regime_up, 4=regime_down
        char ip[INET_ADDRSTRLEN];
        int port;
        double latency;
        int fails;
    } log_events[MAX_BACKENDS];
    int event_count = 0;

    pthread_mutex_lock(&g_backend_mutex);
    for (int i = 0; i < total_backends; i++) {
        double rtt_ms = 0.0;

        if (is_healthy[i]) {
            rtt_ms = (double)(end_times[i].tv_sec - start_times[i].tv_sec) * 1000.0 +
                     (double)(end_times[i].tv_nsec - start_times[i].tv_nsec) / 1000000.0;
        }

        if (probe_fds[i] >= 0) {
            close(probe_fds[i]);
        }

        if (is_startup) {
            if (is_healthy[i]) {
                g_backends[i].is_alive = true;
                g_backends[i].consecutive_successes = RISE_THRESHOLD;
                g_backends[i].consecutive_failures = 0;
                g_backends[i].latency_ms = rtt_ms;
                log_events[event_count].idx = i;
                log_events[event_count].event_type = 1;
                strncpy(log_events[event_count].ip, g_backends[i].ip, sizeof(log_events[event_count].ip));
                log_events[event_count].port = g_backends[i].port;
                log_events[event_count].latency = rtt_ms;
                event_count++;
            } else {
                g_backends[i].is_alive = false;
                g_backends[i].consecutive_successes = 0;
                g_backends[i].consecutive_failures = FALL_THRESHOLD;
                log_events[event_count].idx = i;
                log_events[event_count].event_type = 2;
                strncpy(log_events[event_count].ip, g_backends[i].ip, sizeof(log_events[event_count].ip));
                log_events[event_count].port = g_backends[i].port;
                event_count++;
            }
        } else {
            if (is_healthy[i]) {
                g_backends[i].consecutive_successes++;
                g_backends[i].consecutive_failures = 0;
                g_backends[i].latency_ms = rtt_ms;

                if (!g_backends[i].is_alive && g_backends[i].consecutive_successes >= RISE_THRESHOLD) {
                    g_backends[i].is_alive = true;
                    log_events[event_count].idx = i;
                    log_events[event_count].event_type = 3;
                    strncpy(log_events[event_count].ip, g_backends[i].ip, sizeof(log_events[event_count].ip));
                    log_events[event_count].port = g_backends[i].port;
                    log_events[event_count].latency = rtt_ms;
                    event_count++;
                }
            } else {
                g_backends[i].consecutive_failures++;
                g_backends[i].consecutive_successes = 0;

                if (g_backends[i].is_alive && g_backends[i].consecutive_failures >= FALL_THRESHOLD) {
                    g_backends[i].is_alive = false;
                    log_events[event_count].idx = i;
                    log_events[event_count].event_type = 4;
                    strncpy(log_events[event_count].ip, g_backends[i].ip, sizeof(log_events[event_count].ip));
                    log_events[event_count].port = g_backends[i].port;
                    log_events[event_count].fails = g_backends[i].consecutive_failures;
                    event_count++;
                }
            }
        }
    }
    pthread_mutex_unlock(&g_backend_mutex);

    // Emit logs outside backend mutex
    for (int k = 0; k < event_count; k++) {
        if (log_events[k].event_type == 1) {
            add_log("\033[1;32m[INIT]\033[0m Backend [%d] %s:%d ready and UP (Latency: %.2f ms)",
                    log_events[k].idx, log_events[k].ip, log_events[k].port, log_events[k].latency);
        } else if (log_events[k].event_type == 2) {
            add_log("\033[1;31m[INIT]\033[0m Backend [%d] %s:%d unreachable (DOWN)",
                    log_events[k].idx, log_events[k].ip, log_events[k].port);
        } else if (log_events[k].event_type == 3) {
            add_log("\033[1;32m[HEALTH]\033[0m Backend [%d] %s:%d back UP! (Latency: %.2f ms)",
                    log_events[k].idx, log_events[k].ip, log_events[k].port, log_events[k].latency);
        } else if (log_events[k].event_type == 4) {
            add_log("\033[1;31m[HEALTH]\033[0m Backend [%d] %s:%d marked DOWN! (%d failures)",
                    log_events[k].idx, log_events[k].ip, log_events[k].port, log_events[k].fails);
        }
    }
}

void *health_check_thread(void *arg) {
    (void)arg;
    while (g_server_running) {
        unsigned int rem_sec = (g_config.hc_interval_sec > 0) ? (unsigned int)g_config.hc_interval_sec : HEALTH_CHECK_INTERVAL_SEC;
        while (rem_sec > 0 && g_server_running) {
            rem_sec = sleep(rem_sec);
        }
        if (!g_server_running) break;
        perform_health_check_cycle(false);
    }
    return NULL;
}

