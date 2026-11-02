#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

#include "advlb/types.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/utils.h"
#include "advlb/net_utils.h"
#include "advlb/balancer.h"
#include "advlb/health_check.h"
#include "advlb/ssl_engine.h"
#include "advlb/proxy.h"
#include "advlb/udp_proxy.h"
#include "advlb/tui.h"
#include "advlb/cli.h"

static void handle_sighup(int sig) {
    (void)sig;
    g_reload_requested = 1;
}

int main(int argc, char *argv[]) {
    g_start_time = time(NULL);
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

    increase_fd_limit();
    config_init_defaults(&g_config);
    log_init();

    if (parse_cli_args(argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    // Configure termination signals and SIGPIPE
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    struct sigaction sa_pipe;
    memset(&sa_pipe, 0, sizeof(sa_pipe));
    sa_pipe.sa_handler = SIG_IGN;
    sigemptyset(&sa_pipe.sa_mask);
    sigaction(SIGPIPE, &sa_pipe, NULL);

    struct sigaction sa_hup;
    memset(&sa_hup, 0, sizeof(sa_hup));
    sa_hup.sa_handler = handle_sighup;
    sigemptyset(&sa_hup.sa_mask);
    sa_hup.sa_flags = 0;
    sigaction(SIGHUP, &sa_hup, NULL);

    // Initialize SSL context if requested (TCP only)
    if (g_config.enable_ssl_offloading) {
        init_ssl_context(g_config.cert_file, g_config.key_file);
    }

    // UDP Mode
    if (g_config.enable_udp_mode) {
        if (g_config.enable_ssl_offloading) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m --ssl option is not supported in UDP mode (TLS is stream only).\n\n");
            exit(EXIT_FAILURE);
        }
        if (g_config.enable_proxy_protocol_v1 || g_config.enable_accept_proxy) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m PROXY Protocol v1 is supported only in TCP stream mode.\n\n");
            exit(EXIT_FAILURE);
        }

        int workers = g_config.num_workers > 0 ? g_config.num_workers : 1;
        if (!udp_worker_pool_start(workers, g_config.listen_port)) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Failed to start UDP multi-worker pool on port %d\n", g_config.listen_port);
            exit(EXIT_FAILURE);
        }

        if (g_config.enable_tui) {
            init_tui();
            add_log("\033[1;32m[SYSTEM]\033[0m UDP Load Balancer started on port %d (%d workers with SO_REUSEPORT).",
                    g_config.listen_port, workers);
        } else {
            printf("[SYSTEM] UDP Load Balancer started on port %d (%d workers with SO_REUSEPORT, TUI disabled).\n",
                   g_config.listen_port, workers);
        }

        perform_health_check_cycle(true);

        pthread_t hc_tid;
        if (pthread_create(&hc_tid, NULL, health_check_thread, NULL) != 0) {
            add_log("[ERROR] Failed to create health check thread");
        } else {
            pthread_detach(hc_tid);
        }

        if (g_config.enable_tui) {
            pthread_t tui_tid;
            if (pthread_create(&tui_tid, NULL, tui_thread, NULL) != 0) {
                add_log("[ERROR] Failed to create TUI thread");
            } else {
                pthread_detach(tui_tid);
            }
        }

        while (g_server_running) {
            if (g_reload_requested) {
                g_reload_requested = 0;
                add_log("\033[1;36m[SYSTEM]\033[0m SIGHUP received: reloading configuration...");
                config_reload();
            }
            struct timespec ts = {0, 100000000L}; // 100ms
            nanosleep(&ts, NULL);
        }

        udp_worker_pool_stop();

        cleanup_tui();
        printf("\n[SHUTDOWN] UDP Load Balancer shutdown complete.\n");
        log_shutdown();
        return 0;
    }

    // TCP Mode
    int server_fd = create_tcp_server_socket(g_config.listen_port);
    if (server_fd < 0) {
        exit(EXIT_FAILURE);
    }
    g_global_server_fd = server_fd;

    if (g_config.enable_tui) {
        init_tui();
        add_log("\033[1;32m[SYSTEM]\033[0m Load Balancer started in Full-Screen TUI mode on port %d (workers: %d, max-conns: %d).",
                g_config.listen_port, g_config.num_workers, g_config.max_connections);
    } else {
        printf("[SYSTEM] Load Balancer started on port %d (workers: %d, max-conns: %d, TUI disabled).\n",
               g_config.listen_port, g_config.num_workers, g_config.max_connections);
    }

    perform_health_check_cycle(true);

    pthread_t hc_tid;
    if (pthread_create(&hc_tid, NULL, health_check_thread, NULL) != 0) {
        add_log("[ERROR] Failed to create health check thread");
    } else {
        pthread_detach(hc_tid);
    }

    if (g_config.enable_tui) {
        pthread_t tui_tid;
        if (pthread_create(&tui_tid, NULL, tui_thread, NULL) != 0) {
            add_log("[ERROR] Failed to create TUI thread");
        } else {
            pthread_detach(tui_tid);
        }
    }

    // Initialize epoll worker pool
    if (!worker_pool_init(g_config.num_workers)) {
        fprintf(stderr, "\033[1;31m[ERROR]\033[0m Failed to initialize worker pool (%d workers)\n", g_config.num_workers);
        exit(EXIT_FAILURE);
    }

    while (g_server_running) {
        if (g_reload_requested) {
            g_reload_requested = 0;
            add_log("\033[1;36m[SYSTEM]\033[0m SIGHUP received: reloading configuration and certificates...");
            config_reload();
        }

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!g_server_running) break;
            if (g_reload_requested) {
                g_reload_requested = 0;
                add_log("\033[1;36m[SYSTEM]\033[0m SIGHUP received: reloading configuration and certificates...");
                config_reload();
            }
            if (errno == EINTR) continue;
            if (errno == ECONNABORTED || errno == EPROTO) continue;
            continue;
        }

        // Check concurrent connections limit (SEC-02 mitigation)
        if (atomic_load_explicit(&g_active_clients, memory_order_relaxed) >= g_config.max_connections) {
            close(client_fd);
            static time_t last_warn = 0;
            time_t now = time(NULL);
            if (now - last_warn >= 2) {
                add_log("\033[1;31m[DROP]\033[0m Connection rejected: max-connections limit (%d) reached",
                        g_config.max_connections);
                last_warn = now;
            }
            continue;
        }

        atomic_fetch_add_explicit(&g_active_clients, 1, memory_order_relaxed);
        worker_pool_dispatch(client_fd, &client_addr);
    }

    worker_pool_shutdown();

    cleanup_tui();
    printf("\n[SHUTDOWN] Load Balancer shutdown complete.\n");
    if (g_global_server_fd >= 0) {
        close(g_global_server_fd);
    }
    cleanup_ssl_context();
    log_shutdown();

    return 0;
}

