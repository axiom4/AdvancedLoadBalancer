#ifndef ADVLB_CONFIG_H
#define ADVLB_CONFIG_H

#include <stdbool.h>
#include <time.h>
#include <signal.h>
#include "advlb/types.h"

typedef struct {
    int listen_port;
    int max_connections;
    int num_workers;
    int inactivity_timeout_sec;
    bool enable_transparent_mode;
    bool enable_ssl_offloading;
    bool enable_proxy_protocol_v1;
    bool enable_accept_proxy;
    bool enable_udp_mode;
    int udp_session_timeout_sec;
    bool enable_tui;
    char cert_file[256];
    char key_file[256];

    BalancerAlgorithm current_algorithm;
    HealthCheckType current_hc_type;
    char hc_http_path[256];
    char hc_send_payload[1024];
    char hc_expect_payload[256];
    bool hc_send_explicitly_set;
    bool hc_expect_explicitly_set;
    int hc_interval_sec;
    int hc_timeout_ms;
} LbConfig;

extern LbConfig g_config;
extern atomic_int g_active_clients;
extern volatile sig_atomic_t g_server_running;
extern int g_global_server_fd;
extern time_t g_start_time;
extern volatile bool g_confirming_exit;
extern volatile int g_exit_popup_focus;

void config_init_defaults(LbConfig *cfg);

#endif /* ADVLB_CONFIG_H */

