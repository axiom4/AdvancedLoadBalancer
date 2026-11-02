#ifndef ADVLB_TYPES_H
#define ADVLB_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdatomic.h>

/* ============================================================================
 * GLOBAL CONFIGURATION CONSTANTS
 * ============================================================================ */
#define BUFFER_SIZE 32768
#define MAX_BACKENDS 16
#define DEFAULT_MAX_CONNECTIONS 4096

#ifndef SOMAXCONN
#define SOMAXCONN 1024
#endif

#define HEALTH_CHECK_INTERVAL_SEC 2
#define HEALTH_CHECK_TIMEOUT_MS 800
#define RISE_THRESHOLD 2
#define FALL_THRESHOLD 3

#define MAX_LOG_LINES 128
#define LOG_LINE_LEN 256

typedef enum {
    ALG_ROUND_ROBIN = 0,
    ALG_LEAST_CONNECTIONS = 1,
    ALG_IP_HASH = 2,
    ALG_LEAST_LATENCY = 3,
    ALG_WEIGHTED_RR = 4,
    ALG_RANDOM_2 = 5
} BalancerAlgorithm;

typedef enum {
    HC_TYPE_TCP = 0,        // Layer 4 TCP 3-way handshake (SYN/ACK)
    HC_TYPE_HTTP = 1,       // Layer 7 HTTP GET probe (verifies 2xx/3xx status)
    HC_TYPE_PAYLOAD = 2     // Layer 4/7 TCP Send/Expect (custom banner or command)
} HealthCheckType;

typedef struct {
    char ip[64];
    int port;
    int weight;
    int current_weight;
    atomic_bool is_alive;
    int consecutive_successes;
    int consecutive_failures;
    double latency_ms;
    atomic_int active_connections;
    atomic_ulong total_requests_handled;
} BackendServer;

typedef struct {
    int client_fd;
    struct sockaddr_in client_addr;
} ClientContext;

#endif /* ADVLB_TYPES_H */

