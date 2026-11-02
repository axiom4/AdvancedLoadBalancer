#define _GNU_SOURCE
#include "advlb/cli.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/health_check.h"
#include "advlb/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>
#include <sys/stat.h>

void print_help(const char *prog_name) {
    printf("\n\033[1;36mADVANCED LOAD BALANCER (C / EPOLL / MULTITHREAD / TUI)\033[0m\n\n");
    printf("Usage:\n");
    printf("  %s -p PORT -b IP:PORT[:WEIGHT] [OPTIONS]\n", prog_name);
    printf("  %s -c /path/to/advlb.conf [OPTIONS]\n\n", prog_name);
    printf("Configuration File:\n");
    printf("  -c, --config FILE         Load configuration and backends from file (e.g. advlb.conf)\n\n");
    printf("Required Parameters (unless set in config file):\n");
    printf("  -p, --port PORT           Listening port for Load Balancer (1-65535) [\033[1;31mREQUIRED\033[0m]\n");
    printf("  -b, --backend IP:PORT[:W] Add a Real Server with optional weight (default weight: 1)\n");
    printf("                            Repeatable or comma-separated. E.g. -b 127.0.0.1:9001:3 or -b [::1]:9001\n\n");
    printf("Load Balancing Algorithms:\n");
    printf("      --algo NAME           Select initial balancing algorithm:\n");
    printf("                            * rr        : Sequential Round-Robin\n");
    printf("                            * lc        : Least-Connections (default)\n");
    printf("                            * ip-hash   : IP Hash / Client Sticky Sessions\n");
    printf("                            * latency   : Least-Latency (fastest response time)\n");
    printf("                            * wrr       : Smooth Weighted Round-Robin\n");
    printf("                            * random    : Power of Two Choices (2 random picks)\n");
    printf("      --rr, --lc, --ip-hash, --latency, --wrr, --random  (quick aliases)\n\n");
    printf("Protocol Modes (TCP / UDP):\n");
    printf("  -u, --udp                 Enable Layer 4 UDP load balancing (default: TCP)\n");
    printf("      --udp-timeout SEC     UDP session inactivity timeout in seconds (default: 30)\n\n");
    printf("Health Check Options:\n");
    printf("      --hc-type TYPE        Health check type: tcp (default), http, payload\n");
    printf("                            (Note: for UDP-only services, configure --hc-type payload or http)\n");
    printf("      --http-hc             Enable HTTP L7 health check (alias for --hc-type http)\n");
    printf("      --hc-path PATH        HTTP probe path (default: /)\n");
    printf("      --hc-send STR         Payload string sent for probe (default: PING\\r\\n)\n");
    printf("      --hc-expect STR       Expected response payload (default: PONG)\n");
    printf("      --hc-interval SEC     Interval between checks in seconds (default: 2)\n");
    printf("      --hc-timeout MS       Probe timeout in milliseconds (default: 800)\n\n");
    printf("PROXY Protocol (v1) Options:\n");
    printf("  -P, --proxy-protocol      Send HAProxy PROXY Protocol v1 header to backend Real Servers\n");
    printf("      --ppv1                (alias for --proxy-protocol)\n");
    printf("      --accept-proxy        Accept and decode PROXY Protocol v1 header from incoming clients\n\n");
    printf("SSL / TLS Options:\n");
    printf("  -s, --ssl                 Enable SSL/TLS termination (HTTPS/WSS)\n");
    printf("                            \033[1;33mNOTE:\033[0m with --ssl both --cert and --key are \033[1;31mREQUIRED\033[0m!\n");
    printf("      --cert FILE           SSL X.509 certificate file (required with --ssl)\n");
    printf("      --key FILE            SSL RSA private key file (required with --ssl)\n\n");
    printf("Other Options:\n");
    printf("  -m, --max-connections NUM Maximum concurrent connections limit (default: 4096)\n");
    printf("  -w, --workers NUM         Number of epoll worker threads (default: CPU cores)\n");
    printf("      --timeout SEC         TCP connection inactivity timeout in seconds (default: 30)\n");
    printf("  -t, --transparent         Enable IP transparency (requires root/CAP_NET_ADMIN privileges)\n");
    printf("      --no-tui              Disable full-screen TUI dashboard (plain logs on stdout)\n");
    printf("  -h, --help                Show this help message and exit\n\n");
    printf("Usage Examples:\n");
    printf("  %s -p 8080 -b 127.0.0.1:9001 -b 127.0.0.1:9002\n", prog_name);
    printf("  %s -p 8080 -b 127.0.0.1:9001:3,127.0.0.1:9002:1 --algo wrr\n", prog_name);
    printf("  %s -p 8080 -b 10.0.0.1:8080,10.0.0.2:8080 --algo ip-hash --http-hc --hc-path /healthz\n", prog_name);
    printf("  %s -p 8443 --ssl --cert server.crt --key server.key -b 127.0.0.1:9001 --latency\n\n", prog_name);
}

void parse_backend_arg(const char *arg) {
    if (!arg || !*arg) return;
    char copy[512];
    strncpy(copy, arg, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(copy, ",", &saveptr);
    while (token != NULL) {
        while (*token == ' ' || *token == '\t') token++;
        char *end = token + strlen(token) - 1;
        while (end >= token && (*end == ' ' || *end == '\t')) {
            *end = '\0';
            end--;
        }
        if (*token == '\0') {
            token = strtok_r(NULL, ",", &saveptr);
            continue;
        }

        char *ip = NULL;
        char *rest = NULL;

        if (token[0] == '[') {
            // Bracketed IPv6 notation: [2001:db8::1]:8080[:weight]
            char *closing = strchr(token, ']');
            if (!closing || *(closing + 1) != ':') {
                fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid IPv6 backend format: '%s' (expected [IPv6]:PORT[:WEIGHT])\n", token);
                exit(EXIT_FAILURE);
            }
            *closing = '\0';
            ip = token + 1; // Content inside brackets
            rest = closing + 2; // Content after ']:'
        } else {
            // IPv4 or hostname notation: 127.0.0.1:8080[:weight]
            char *first_colon = strchr(token, ':');
            if (first_colon) {
                *first_colon = '\0';
                ip = token;
                rest = first_colon + 1;
            } else {
                fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid backend format: '%s' (expected IP:PORT or [IPv6]:PORT)\n", token);
                exit(EXIT_FAILURE);
            }
        }

        char *second_colon = strchr(rest, ':');
        int port = 0;
        int weight = 1;
        if (second_colon) {
            *second_colon = '\0';
            port = atoi(rest);
            weight = atoi(second_colon + 1);
            if (weight <= 0) weight = 1;
        } else {
            port = atoi(rest);
        }

        if (port > 0 && port <= 65535 && strlen(ip) > 0) {
            if (!add_backend(ip, port, weight)) {
                exit(EXIT_FAILURE);
            }
        } else {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid backend '%s': port must be 1-65535\n", ip);
            exit(EXIT_FAILURE);
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
}

bool parse_algorithm(const char *name, BalancerAlgorithm *out_alg) {
    if (strcasecmp(name, "rr") == 0 || strcasecmp(name, "round-robin") == 0 || strcasecmp(name, "roundrobin") == 0) {
        *out_alg = ALG_ROUND_ROBIN;
        return true;
    }
    if (strcasecmp(name, "lc") == 0 || strcasecmp(name, "least-conn") == 0 || strcasecmp(name, "leastconn") == 0 || strcasecmp(name, "least-connections") == 0) {
        *out_alg = ALG_LEAST_CONNECTIONS;
        return true;
    }
    if (strcasecmp(name, "ip-hash") == 0 || strcasecmp(name, "iphash") == 0 || strcasecmp(name, "hash") == 0) {
        *out_alg = ALG_IP_HASH;
        return true;
    }
    if (strcasecmp(name, "latency") == 0 || strcasecmp(name, "least-latency") == 0 || strcasecmp(name, "fastest") == 0) {
        *out_alg = ALG_LEAST_LATENCY;
        return true;
    }
    if (strcasecmp(name, "wrr") == 0 || strcasecmp(name, "weighted") == 0 || strcasecmp(name, "weighted-rr") == 0) {
        *out_alg = ALG_WEIGHTED_RR;
        return true;
    }
    if (strcasecmp(name, "random") == 0 || strcasecmp(name, "random2") == 0 || strcasecmp(name, "power-of-2") == 0) {
        *out_alg = ALG_RANDOM_2;
        return true;
    }
    return false;
}

bool parse_hc_type(const char *name, HealthCheckType *out_type) {
    if (strcasecmp(name, "tcp") == 0 || strcasecmp(name, "l4") == 0) {
        *out_type = HC_TYPE_TCP;
        return true;
    }
    if (strcasecmp(name, "http") == 0 || strcasecmp(name, "l7") == 0 || strcasecmp(name, "get") == 0) {
        *out_type = HC_TYPE_HTTP;
        return true;
    }
    if (strcasecmp(name, "payload") == 0 || strcasecmp(name, "tcp-payload") == 0 || strcasecmp(name, "expect") == 0 || strcasecmp(name, "ping") == 0) {
        *out_type = HC_TYPE_PAYLOAD;
        return true;
    }
    return false;
}

bool is_valid_http_path(const char *path) {
    if (!path || path[0] != '/') {
        return false;
    }
    size_t len = strlen(path);
    if (len >= sizeof(g_config.hc_http_path)) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)path[i];
        // Reject CRLF, spaces, and control characters (RFC 7230 Request-Target validation)
        if (c <= 32 || c >= 127) {
            return false;
        }
    }
    return true;
}

int parse_cli_args(int argc, char *argv[]) {
    // Pre-scan for config file (-c / --config) to load base configuration before CLI overrides
    for (int i = 1; i < argc; i++) {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0) && (i + 1 < argc)) {
            strncpy(g_config.config_file, argv[i + 1], sizeof(g_config.config_file) - 1);
            if (!config_load_file(argv[i + 1], &g_config)) {
                fprintf(stderr, "\033[1;31m[ERROR]\033[0m Cannot open or parse config file '%s'\n", argv[i + 1]);
                exit(EXIT_FAILURE);
            }
            break;
        }
    }

    static struct option long_options[] = {
        {"config",      required_argument, 0, 'c'},
        {"port",        required_argument, 0, 'p'},
        {"backend",     required_argument, 0, 'b'},
        {"ssl",         no_argument,       0, 's'},
        {"cert",        required_argument, 0, 1001},
        {"key",         required_argument, 0, 1002},
        {"transparent", no_argument,       0, 't'},
        {"algo",        required_argument, 0, 1003},
        {"algorithm",   required_argument, 0, 1003},
        {"rr",          no_argument,       0, 1004},
        {"lc",          no_argument,       0, 1005},
        {"ip-hash",     no_argument,       0, 1006},
        {"latency",     no_argument,       0, 1007},
        {"wrr",         no_argument,       0, 1008},
        {"random",      no_argument,       0, 1009},
        {"no-tui",      no_argument,       0, 1010},
        {"hc-type",     required_argument, 0, 1011},
        {"http-hc",     no_argument,       0, 1012},
        {"hc-path",     required_argument, 0, 1013},
        {"hc-send",     required_argument, 0, 1014},
        {"hc-expect",   required_argument, 0, 1015},
        {"hc-interval", required_argument, 0, 1016},
        {"hc-timeout",  required_argument, 0, 1017},
        {"proxy-protocol", no_argument,    0, 'P'},
        {"ppv1",        no_argument,       0, 'P'},
        {"accept-proxy", no_argument,      0, 1018},
        {"udp",         no_argument,       0, 'u'},
        {"udp-timeout", required_argument, 0, 1019},
        {"max-connections", required_argument, 0, 'm'},
        {"max-conns",   required_argument, 0, 'm'},
        {"workers",     required_argument, 0, 'w'},
        {"timeout",     required_argument, 0, 1020},
        {"help",        no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    int option_index = 0;

    while ((c = getopt_long(argc, argv, "c:p:b:sthPum:w:", long_options, &option_index)) != -1) {
        switch (c) {
            case 'c':
                // Already loaded in pre-scan, ignore here
                break;
            case 'w':
                g_config.num_workers = atoi(optarg);
                if (g_config.num_workers <= 0) {
                    fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid value for --workers: '%s' (must be > 0)\n", optarg);
                    exit(EXIT_FAILURE);
                }
                if (g_config.num_workers > 256) {
                    g_config.num_workers = 256;
                }
                break;
            case 1020: // --timeout
                g_config.inactivity_timeout_sec = atoi(optarg);
                if (g_config.inactivity_timeout_sec <= 0) g_config.inactivity_timeout_sec = 30;
                break;
            case 'm':
                g_config.max_connections = atoi(optarg);
                if (g_config.max_connections <= 0) {
                    fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid value for --max-connections: '%s' (must be > 0)\n", optarg);
                    exit(EXIT_FAILURE);
                }
                break;
            case 'p':
                g_config.listen_port = atoi(optarg);
                break;
            case 'b':
                parse_backend_arg(optarg);
                break;
            case 's':
                g_config.enable_ssl_offloading = true;
                break;
            case 1001: // --cert
                strncpy(g_config.cert_file, optarg, sizeof(g_config.cert_file) - 1);
                g_config.cert_file[sizeof(g_config.cert_file) - 1] = '\0';
                break;
            case 1002: // --key
                strncpy(g_config.key_file, optarg, sizeof(g_config.key_file) - 1);
                g_config.key_file[sizeof(g_config.key_file) - 1] = '\0';
                break;
            case 1003: // --algo
                if (!parse_algorithm(optarg, &g_config.current_algorithm)) {
                    fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid algorithm: '%s'\n", optarg);
                    fprintf(stderr, "Valid options: rr, lc, ip-hash, latency, wrr, random\n\n");
                    print_help(argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            case 1004: // --rr
                g_config.current_algorithm = ALG_ROUND_ROBIN;
                break;
            case 1005: // --lc
                g_config.current_algorithm = ALG_LEAST_CONNECTIONS;
                break;
            case 1006: // --ip-hash
                g_config.current_algorithm = ALG_IP_HASH;
                break;
            case 1007: // --latency
                g_config.current_algorithm = ALG_LEAST_LATENCY;
                break;
            case 1008: // --wrr
                g_config.current_algorithm = ALG_WEIGHTED_RR;
                break;
            case 1009: // --random
                g_config.current_algorithm = ALG_RANDOM_2;
                break;
            case 1010: // --no-tui
                g_config.enable_tui = false;
                break;
            case 1011: // --hc-type
                if (!parse_hc_type(optarg, &g_config.current_hc_type)) {
                    fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid health check type: '%s'\n", optarg);
                    fprintf(stderr, "Valid options: tcp, http, payload\n\n");
                    print_help(argv[0]);
                    exit(EXIT_FAILURE);
                }
                break;
            case 1012: // --http-hc
                g_config.current_hc_type = HC_TYPE_HTTP;
                break;
            case 1013: // --hc-path
                if (!is_valid_http_path(optarg)) {
                    fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid HTTP health check path: '%s'\n", optarg);
                    fprintf(stderr, "Path must start with '/' and contain no CRLF (\\r, \\n), spaces, or control characters (RFC 7230).\n\n");
                    print_help(argv[0]);
                    exit(EXIT_FAILURE);
                }
                g_config.current_hc_type = HC_TYPE_HTTP;
                strncpy(g_config.hc_http_path, optarg, sizeof(g_config.hc_http_path) - 1);
                g_config.hc_http_path[sizeof(g_config.hc_http_path) - 1] = '\0';
                break;
            case 1014: // --hc-send
                g_config.current_hc_type = HC_TYPE_PAYLOAD;
                g_config.hc_send_explicitly_set = true;
                unescape_string(g_config.hc_send_payload, optarg, sizeof(g_config.hc_send_payload));
                break;
            case 1015: // --hc-expect
                g_config.current_hc_type = HC_TYPE_PAYLOAD;
                g_config.hc_expect_explicitly_set = true;
                unescape_string(g_config.hc_expect_payload, optarg, sizeof(g_config.hc_expect_payload));
                break;
            case 1016: // --hc-interval
                g_config.hc_interval_sec = atoi(optarg);
                if (g_config.hc_interval_sec <= 0) g_config.hc_interval_sec = HEALTH_CHECK_INTERVAL_SEC;
                break;
            case 1017: // --hc-timeout
                g_config.hc_timeout_ms = atoi(optarg);
                if (g_config.hc_timeout_ms <= 0) g_config.hc_timeout_ms = HEALTH_CHECK_TIMEOUT_MS;
                break;
            case 'P':
                g_config.enable_proxy_protocol_v1 = true;
                break;
            case 1018: // --accept-proxy
                g_config.enable_accept_proxy = true;
                break;
            case 'u':
                g_config.enable_udp_mode = true;
                break;
            case 1019: // --udp-timeout
                g_config.udp_session_timeout_sec = atoi(optarg);
                if (g_config.udp_session_timeout_sec <= 0) g_config.udp_session_timeout_sec = 30;
                break;
            case 't':
                g_config.enable_transparent_mode = true;
                break;
            case 'h':
                print_help(argv[0]);
                exit(0);
            case '?':
            default:
                print_help(argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // Handle remaining non-optional positional arguments (e.g. '127.0.0.1:9001')
    while (optind < argc) {
        if (strchr(argv[optind], ':')) {
            parse_backend_arg(argv[optind]);
        } else {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Invalid positional argument: '%s' (expected IP:PORT)\n\n", argv[optind]);
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }
        optind++;
    }

    finalize_payload_config();

    // 1. -b (--backend) is REQUIRED
    if (g_num_backends == 0) {
        fprintf(stderr, "\033[1;31m[ERROR]\033[0m Missing required parameter: -b / --backend (or positional IP:PORT)\n");
        fprintf(stderr, "You must specify at least one Real Server (e.g. -b 127.0.0.1:9001).\n\n");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    // 2. -p (--port) is REQUIRED
    if (g_config.listen_port <= 0 || g_config.listen_port > 65535) {
        fprintf(stderr, "\033[1;31m[ERROR]\033[0m Missing or invalid required parameter: -p / --port <1-65535>\n");
        fprintf(stderr, "You must specify the Load Balancer listening port (e.g. -p 8080).\n\n");
        print_help(argv[0]);
        exit(EXIT_FAILURE);
    }

    // 3. If --ssl (-s) is active, or if --cert / --key were supplied, both are REQUIRED
    if (g_config.enable_ssl_offloading || g_config.cert_file[0] != '\0' || g_config.key_file[0] != '\0') {
        g_config.enable_ssl_offloading = true;

        if (g_config.cert_file[0] == '\0' || g_config.key_file[0] == '\0') {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m With --ssl (-s), both --cert and --key must be specified:\n");
            fprintf(stderr, "  --cert <file.crt>   Path to X.509 SSL certificate file\n");
            fprintf(stderr, "  --key  <file.key>   Path to RSA SSL private key file\n\n");
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }

        struct stat st_cert;
        if (stat(g_config.cert_file, &st_cert) != 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m SSL certificate file '%s' not found: %s\n",
                    g_config.cert_file, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (!S_ISREG(st_cert.st_mode)) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m SSL certificate '%s' is not a regular file\n",
                    g_config.cert_file);
            exit(EXIT_FAILURE);
        }
        if (access(g_config.cert_file, R_OK) != 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m SSL certificate file '%s' is not readable: %s\n",
                    g_config.cert_file, strerror(errno));
            exit(EXIT_FAILURE);
        }

        struct stat st_key;
        if (stat(g_config.key_file, &st_key) != 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m SSL private key file '%s' not found: %s\n",
                    g_config.key_file, strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (!S_ISREG(st_key.st_mode)) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m SSL private key '%s' is not a regular file\n",
                    g_config.key_file);
            exit(EXIT_FAILURE);
        }
        if (access(g_config.key_file, R_OK) != 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m SSL private key file '%s' is not readable: %s\n",
                    g_config.key_file, strerror(errno));
            exit(EXIT_FAILURE);
        }

        // SEC-09: Enforce secure file permissions on private key (must be 0600 or 0400).
        // Reject files accessible by group (0070) or world/others (0007).
        if ((st_key.st_mode & 0077) != 0) {
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Insecure permissions on SSL private key '%s' (%04o).\n",
                    g_config.key_file, (unsigned int)(st_key.st_mode & 0777));
            fprintf(stderr, "SSL private keys must not be accessible by group or others (required: 0600 or 0400).\n");
            fprintf(stderr, "Hint: fix with 'chmod 600 %s'\n\n", g_config.key_file);
            exit(EXIT_FAILURE);
        }
    }

    return 0;
}

