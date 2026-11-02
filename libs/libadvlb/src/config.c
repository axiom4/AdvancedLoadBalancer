#include "advlb/config.h"
#include "advlb/cli.h"
#include "advlb/log.h"
#include "advlb/ssl_engine.h"
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

