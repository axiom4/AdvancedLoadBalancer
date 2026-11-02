#include "advlb/config.h"
#include <string.h>
#include <unistd.h>

LbConfig g_config;
atomic_int g_active_clients = 0;
volatile sig_atomic_t g_server_running = 1;
int g_global_server_fd = -1;
time_t g_start_time = 0;
volatile bool g_confirming_exit = false;
volatile int g_exit_popup_focus = 0; // 0: [ No, Cancel ], 1: [ Yes, Exit ]

void config_init_defaults(LbConfig *cfg) {
    if (!cfg) return;
    memset(cfg, 0, sizeof(LbConfig));
    cfg->listen_port = -1;
    cfg->max_connections = DEFAULT_MAX_CONNECTIONS;

    long nprocs = sysconf(_SC_NPROCESSORS_ONLN);
    if (nprocs <= 0) nprocs = 4;
    if (nprocs > 32) nprocs = 32;
    cfg->num_workers = (int)nprocs;
    cfg->inactivity_timeout_sec = 30;

    cfg->enable_transparent_mode = false;
    cfg->enable_ssl_offloading = false;
    cfg->enable_proxy_protocol_v1 = false;
    cfg->enable_accept_proxy = false;
    cfg->enable_udp_mode = false;
    cfg->udp_session_timeout_sec = 30;
    cfg->enable_tui = true;
    cfg->current_algorithm = ALG_LEAST_CONNECTIONS;
    cfg->current_hc_type = HC_TYPE_TCP;
    strncpy(cfg->hc_http_path, "/", sizeof(cfg->hc_http_path) - 1);
    strncpy(cfg->hc_send_payload, "PING\r\n", sizeof(cfg->hc_send_payload) - 1);
    strncpy(cfg->hc_expect_payload, "PONG", sizeof(cfg->hc_expect_payload) - 1);
    cfg->hc_send_explicitly_set = false;
    cfg->hc_expect_explicitly_set = false;
    cfg->hc_interval_sec = HEALTH_CHECK_INTERVAL_SEC;
    cfg->hc_timeout_ms = HEALTH_CHECK_TIMEOUT_MS;
}

