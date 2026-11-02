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

int main(int argc, char *argv[]) {
    g_start_time = time(NULL);
    srand((unsigned int)time(NULL) ^ (unsigned int)getpid());

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

        int udp_fd = create_udp_server_socket(g_config.listen_port);
        if (udp_fd < 0) {
            exit(EXIT_FAILURE);
        }
        g_global_server_fd = udp_fd;

        if (g_config.enable_tui) {
            init_tui();
            add_log("\033[1;32m[SYSTEM]\033[0m UDP Load Balancer started in Full-Screen TUI mode on port %d.", g_config.listen_port);
        } else {
            printf("[SYSTEM] UDP Load Balancer started on port %d (TUI disabled).\n", g_config.listen_port);
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

        run_udp_proxy_loop(udp_fd);

        cleanup_tui();
        printf("\n[SHUTDOWN] UDP Load Balancer shutdown complete.\n");
        if (g_global_server_fd >= 0) close(g_global_server_fd);
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
        add_log("\033[1;32m[SYSTEM]\033[0m Load Balancer started in Full-Screen TUI mode on port %d (max-conns: %d).",
                g_config.listen_port, g_config.max_connections);
    } else {
        printf("[SYSTEM] Load Balancer started on port %d (max-conns: %d, TUI disabled).\n",
               g_config.listen_port, g_config.max_connections);
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

    // Configure thread attributes with compact stack size (512KB) for optimized scalability
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    size_t stack_size = 512 * 1024;
    pthread_attr_setstacksize(&attr, stack_size);

    while (g_server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!g_server_running) break;
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

        ClientContext *ctx = malloc(sizeof(ClientContext));
        if (!ctx) {
            close(client_fd);
            continue;
        }
        ctx->client_fd = client_fd;
        ctx->client_addr = client_addr;

        atomic_fetch_add_explicit(&g_active_clients, 1, memory_order_relaxed);

        pthread_t client_tid;
        if (pthread_create(&client_tid, &attr, client_handler_thread, ctx) != 0) {
            atomic_fetch_sub_explicit(&g_active_clients, 1, memory_order_relaxed);
            close(client_fd);
            free(ctx);
        }
    }

    pthread_attr_destroy(&attr);

    cleanup_tui();
    printf("\n[SHUTDOWN] Load Balancer shutdown complete.\n");
    if (g_global_server_fd >= 0) {
        close(g_global_server_fd);
    }
    cleanup_ssl_context();

    return 0;
}

