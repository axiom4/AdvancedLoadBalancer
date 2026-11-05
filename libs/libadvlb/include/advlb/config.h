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
    char config_file[256];

    bool enable_upstream_pooling;
    int upstream_pool_size;
    int upstream_pool_idle_sec;

    /* High-Availability Cluster (VRRP + VIP + Session Replication) */
    bool enable_cluster;
    int vrrp_router_id;
    int vrrp_priority;
    int vrrp_advert_interval_ms;
    bool vrrp_preempt;
    char virtual_ip[64];
    char vip_interface[64];
    bool vrrp_use_vmac;
    char vrrp_vmac[32];
    char cluster_bind_ip[64];
    int cluster_port;
    bool cluster_enable_multicast;
    char cluster_secret[128];
    uint32_t cluster_node_id;
    bool backend_source_vip;   /* Backend connections sourced from the VIP so they migrate on failover */
    bool enable_session_stickiness;
    int session_ttl_sec;

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
extern volatile sig_atomic_t g_reload_requested;

void config_init_defaults(LbConfig *cfg);
bool config_load_file(const char *filepath, LbConfig *cfg);
bool config_reload(void);

#endif /* ADVLB_CONFIG_H */

