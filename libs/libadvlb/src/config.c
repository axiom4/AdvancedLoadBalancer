#include "advlb/config.h"
#include "advlb/cli.h"
#include "advlb/log.h"
#include "advlb/ssl_engine.h"
#include "advlb/cluster.h"
#include "advlb/session_table.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <strings.h>

LbConfig g_config;
atomic_int g_active_clients = 0;
volatile sig_atomic_t g_server_running = 1;
int g_global_server_fd = -1;
time_t g_start_time = 0;
volatile bool g_confirming_exit = false;
volatile int g_exit_popup_focus = 0; // 0: [ No, Cancel ], 1: [ Yes, Exit ]
volatile sig_atomic_t g_reload_requested = 0;

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

    cfg->enable_upstream_pooling = true;
    cfg->upstream_pool_size = 16;
    cfg->upstream_pool_idle_sec = 30;

    cfg->enable_cluster = false;
    cfg->vrrp_router_id = 51;
    cfg->vrrp_priority = 100;
    cfg->vrrp_advert_interval_ms = 200;
    cfg->vrrp_preempt = true;
    cfg->virtual_ip[0] = '\0';
    cfg->vip_interface[0] = '\0';
    cfg->vrrp_use_vmac = true;
    cfg->vrrp_vmac[0] = '\0';
    strncpy(cfg->cluster_bind_ip, "0.0.0.0", sizeof(cfg->cluster_bind_ip) - 1);
    cfg->cluster_port = DEFAULT_CLUSTER_PORT;
    cfg->cluster_enable_multicast = true;
    strncpy(cfg->cluster_secret, "adlb-cluster-default-hmac-key", sizeof(cfg->cluster_secret) - 1);
    cfg->cluster_node_id = 0;
    cfg->enable_session_stickiness = false;
    cfg->session_ttl_sec = DEFAULT_SESSION_TTL_SEC;
}

static bool parse_bool_val(const char *val) {
    if (!val) return false;
    if (strcasecmp(val, "true") == 0 || strcasecmp(val, "yes") == 0 ||
        strcasecmp(val, "1") == 0 || strcasecmp(val, "on") == 0) {
        return true;
    }
    return false;
}

static void trim_whitespace(char *str) {
    if (!str) return;
    char *start = str;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
    char *end = str + strlen(str) - 1;
    while (end >= str && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }
}

static void unescape_string(char *dest, const char *src, size_t max_len) {
    size_t d = 0;
    for (size_t s = 0; src[s] != '\0' && d + 1 < max_len; s++) {
        if (src[s] == '\\' && src[s + 1] != '\0') {
            if (src[s + 1] == 'r') { dest[d++] = '\r'; s++; }
            else if (src[s + 1] == 'n') { dest[d++] = '\n'; s++; }
            else if (src[s + 1] == 't') { dest[d++] = '\t'; s++; }
            else { dest[d++] = src[++s]; }
        } else {
            dest[d++] = src[s];
        }
    }
    dest[d] = '\0';
}

bool config_load_file(const char *filepath, LbConfig *cfg) {
    if (!filepath || !cfg) return false;
    FILE *f = fopen(filepath, "r");
    if (!f) {
        return false;
    }

    char line[1024];

    while (fgets(line, sizeof(line), f)) {
        // Remove trailing newline
        line[strcspn(line, "\r\n")] = '\0';

        // Strip comments starting with '#' or ';'
        char *comment = strpbrk(line, "#;");
        if (comment) *comment = '\0';

        trim_whitespace(line);
        if (line[0] == '\0') continue; // Blank line

        // Find separator '=' or ':'
        char *sep = strpbrk(line, "=:");
        if (!sep) continue;

        *sep = '\0';
        char *key = line;
        char *val = sep + 1;

        trim_whitespace(key);
        trim_whitespace(val);

        if (key[0] == '\0' || val[0] == '\0') continue;

        // Strip surrounding quotes if present
        size_t vlen = strlen(val);
        if (vlen >= 2 && ((val[0] == '"' && val[vlen - 1] == '"') || (val[0] == '\'' && val[vlen - 1] == '\''))) {
            val[vlen - 1] = '\0';
            val++;
        }

        // Parse key-value pairs
        if (strcasecmp(key, "port") == 0 || strcasecmp(key, "listen_port") == 0) {
            cfg->listen_port = atoi(val);
        } else if (strcasecmp(key, "backend") == 0 || strcasecmp(key, "server") == 0) {
            parse_backend_arg(val);
        } else if (strcasecmp(key, "workers") == 0 || strcasecmp(key, "num_workers") == 0) {
            int w = atoi(val);
            if (w < 1) w = 1;
            if (w > 256) w = 256;
            cfg->num_workers = w;
        } else if (strcasecmp(key, "max_connections") == 0 || strcasecmp(key, "max_conns") == 0) {
            int m = atoi(val);
            if (m > 0) cfg->max_connections = m;
        } else if (strcasecmp(key, "timeout") == 0 || strcasecmp(key, "inactivity_timeout") == 0) {
            cfg->inactivity_timeout_sec = atoi(val);
        } else if (strcasecmp(key, "transparent") == 0) {
            cfg->enable_transparent_mode = parse_bool_val(val);
        } else if (strcasecmp(key, "ssl") == 0) {
            cfg->enable_ssl_offloading = parse_bool_val(val);
        } else if (strcasecmp(key, "cert") == 0 || strcasecmp(key, "cert_file") == 0) {
            strncpy(cfg->cert_file, val, sizeof(cfg->cert_file) - 1);
        } else if (strcasecmp(key, "key") == 0 || strcasecmp(key, "key_file") == 0) {
            strncpy(cfg->key_file, val, sizeof(cfg->key_file) - 1);
        } else if (strcasecmp(key, "proxy_protocol") == 0 || strcasecmp(key, "ppv1") == 0) {
            cfg->enable_proxy_protocol_v1 = parse_bool_val(val);
        } else if (strcasecmp(key, "accept_proxy") == 0) {
            cfg->enable_accept_proxy = parse_bool_val(val);
        } else if (strcasecmp(key, "udp") == 0) {
            cfg->enable_udp_mode = parse_bool_val(val);
        } else if (strcasecmp(key, "udp_timeout") == 0) {
            cfg->udp_session_timeout_sec = atoi(val);
        } else if (strcasecmp(key, "tui") == 0) {
            cfg->enable_tui = parse_bool_val(val);
        } else if (strcasecmp(key, "no_tui") == 0) {
            cfg->enable_tui = !parse_bool_val(val);
        } else if (strcasecmp(key, "algorithm") == 0 || strcasecmp(key, "algo") == 0) {
            BalancerAlgorithm a;
            if (parse_algorithm(val, &a)) cfg->current_algorithm = a;
        } else if (strcasecmp(key, "hc_type") == 0) {
            HealthCheckType ht;
            if (parse_hc_type(val, &ht)) cfg->current_hc_type = ht;
        } else if (strcasecmp(key, "hc_path") == 0) {
            if (is_valid_http_path(val)) strncpy(cfg->hc_http_path, val, sizeof(cfg->hc_http_path) - 1);
        } else if (strcasecmp(key, "hc_send") == 0) {
            unescape_string(cfg->hc_send_payload, val, sizeof(cfg->hc_send_payload));
            cfg->hc_send_explicitly_set = true;
        } else if (strcasecmp(key, "hc_expect") == 0) {
            unescape_string(cfg->hc_expect_payload, val, sizeof(cfg->hc_expect_payload));
            cfg->hc_expect_explicitly_set = true;
        } else if (strcasecmp(key, "hc_interval") == 0) {
            cfg->hc_interval_sec = atoi(val);
        } else if (strcasecmp(key, "hc_timeout") == 0) {
            cfg->hc_timeout_ms = atoi(val);
        } else if (strcasecmp(key, "pool") == 0 || strcasecmp(key, "upstream_pooling") == 0 || strcasecmp(key, "upstream_keepalive") == 0) {
            cfg->enable_upstream_pooling = parse_bool_val(val);
        } else if (strcasecmp(key, "pool_size") == 0 || strcasecmp(key, "upstream_pool_size") == 0) {
            cfg->upstream_pool_size = atoi(val);
            if (cfg->upstream_pool_size < 0) cfg->upstream_pool_size = 0;
            if (cfg->upstream_pool_size > 32) cfg->upstream_pool_size = 32;
        } else if (strcasecmp(key, "pool_idle_timeout") == 0 || strcasecmp(key, "pool_timeout") == 0) {
            cfg->upstream_pool_idle_sec = atoi(val);
            if (cfg->upstream_pool_idle_sec <= 0) cfg->upstream_pool_idle_sec = 30;
        } else if (strcasecmp(key, "cluster") == 0 || strcasecmp(key, "enable_cluster") == 0) {
            cfg->enable_cluster = parse_bool_val(val);
        } else if (strcasecmp(key, "vrrp_router_id") == 0 || strcasecmp(key, "vrrp_id") == 0 || strcasecmp(key, "vrid") == 0) {
            int vrid = atoi(val);
            if (vrid >= 1 && vrid <= 255) cfg->vrrp_router_id = vrid;
        } else if (strcasecmp(key, "vrrp_priority") == 0 || strcasecmp(key, "vrrp_prio") == 0) {
            int prio = atoi(val);
            if (prio >= 1 && prio <= 254) cfg->vrrp_priority = prio;
        } else if (strcasecmp(key, "vrrp_interval_ms") == 0 || strcasecmp(key, "vrrp_advert_ms") == 0) {
            int ms = atoi(val);
            if (ms >= 20 && ms <= 10000) cfg->vrrp_advert_interval_ms = ms;
        } else if (strcasecmp(key, "vrrp_preempt") == 0) {
            cfg->vrrp_preempt = parse_bool_val(val);
        } else if (strcasecmp(key, "virtual_ip") == 0 || strcasecmp(key, "vip") == 0) {
            strncpy(cfg->virtual_ip, val, sizeof(cfg->virtual_ip) - 1);
            cfg->enable_cluster = true;
        } else if (strcasecmp(key, "vip_interface") == 0 || strcasecmp(key, "vip_iface") == 0) {
            snprintf(cfg->vip_interface, sizeof(cfg->vip_interface), "%.63s", val);
        } else if (strcasecmp(key, "vrrp_use_vmac") == 0 || strcasecmp(key, "use_vmac") == 0) {
            cfg->vrrp_use_vmac = parse_bool_val(val);
        } else if (strcasecmp(key, "vrrp_vmac") == 0 || strcasecmp(key, "vmac") == 0) {
            snprintf(cfg->vrrp_vmac, sizeof(cfg->vrrp_vmac), "%.31s", val);
            cfg->vrrp_use_vmac = true;
        } else if (strcasecmp(key, "cluster_bind") == 0 || strcasecmp(key, "cluster_bind_ip") == 0) {
            char *colon = strrchr(val, ':');
            if (colon && strchr(val, ':') == colon) {
                *colon = '\0';
                strncpy(cfg->cluster_bind_ip, val, sizeof(cfg->cluster_bind_ip) - 1);
                int cp = atoi(colon + 1);
                if (cp > 0 && cp <= 65535) cfg->cluster_port = cp;
            } else {
                strncpy(cfg->cluster_bind_ip, val, sizeof(cfg->cluster_bind_ip) - 1);
            }
        } else if (strcasecmp(key, "cluster_port") == 0) {
            int cp = atoi(val);
            if (cp > 0 && cp <= 65535) cfg->cluster_port = cp;
        } else if (strcasecmp(key, "cluster_peer") == 0 || strcasecmp(key, "cluster_peers") == 0 || strcasecmp(key, "peer") == 0) {
            cluster_add_peer(val);
            cfg->enable_cluster = true;
        } else if (strcasecmp(key, "cluster_multicast") == 0) {
            cfg->cluster_enable_multicast = parse_bool_val(val);
        } else if (strcasecmp(key, "cluster_secret") == 0 || strcasecmp(key, "vrrp_secret") == 0) {
            strncpy(cfg->cluster_secret, val, sizeof(cfg->cluster_secret) - 1);
        } else if (strcasecmp(key, "cluster_node_id") == 0 || strcasecmp(key, "node_id") == 0) {
            cfg->cluster_node_id = (uint32_t)strtoul(val, NULL, 0);
        } else if (strcasecmp(key, "session_stickiness") == 0 || strcasecmp(key, "sticky_sessions") == 0) {
            cfg->enable_session_stickiness = parse_bool_val(val);
        } else if (strcasecmp(key, "session_ttl") == 0 || strcasecmp(key, "session_ttl_sec") == 0) {
            int ttl = atoi(val);
            if (ttl > 0) cfg->session_ttl_sec = ttl;
        }
    }

    fclose(f);
    return true;
}

bool config_reload(void) {
    bool ok = true;
    if (g_config.config_file[0] != '\0') {
        if (config_load_file(g_config.config_file, &g_config)) {
            add_log("[CONFIG] Configuration reloaded from '%s'", g_config.config_file);
        } else {
            add_log("[ERROR] Failed to reload configuration from '%s'", g_config.config_file);
            ok = false;
        }
    }
    if (g_config.enable_ssl_offloading && g_config.cert_file[0] && g_config.key_file[0]) {
        if (reload_ssl_certificates(g_config.cert_file, g_config.key_file)) {
            add_log("[SSL] TLS certificates successfully reloaded");
        } else {
            add_log("[ERROR] Failed to reload TLS certificates (keeping active)");
            ok = false;
        }
    }
    return ok;
}

