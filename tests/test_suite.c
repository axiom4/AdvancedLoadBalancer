#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/proxy_proto.h"
#include "advlb/net_utils.h"
#include "advnet/advnet.h"

static int g_tests_run = 0;
static int g_tests_passed = 0;
static int g_tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    g_tests_run++; \
    if (cond) { \
        g_tests_passed++; \
        printf("  \033[1;32m[PASS]\033[0m %s\n", msg); \
    } else { \
        g_tests_failed++; \
        printf("  \033[1;31m[FAIL]\033[0m %s (Line %d)\n", msg, __LINE__); \
    } \
} while (0)

static void reset_test_backends(int count) {
    g_num_backends = count;
    for (int i = 0; i < count; i++) {
        snprintf(g_backends[i].ip, sizeof(g_backends[i].ip), "10.0.0.%d", i + 1);
        g_backends[i].port = 8080 + i;
        g_backends[i].weight = (i + 1);
        g_backends[i].current_weight = 0;
        g_backends[i].is_alive = true;
        g_backends[i].consecutive_failures = 0;
        g_backends[i].consecutive_successes = 0;
        g_backends[i].latency_ms = (float)(i * 5 + 2);
        atomic_store(&g_backends[i].active_connections, 0);
        atomic_store(&g_backends[i].total_requests_handled, 0);
    }
}

/* -------------------------------------------------------------------------- */
/* Test 1: PROXY Protocol v1 Serialization                                    */
/* -------------------------------------------------------------------------- */
static void test_proxy_protocol_v1_build(void) {
    printf("\n=== Running Test Suite: PROXY Protocol v1 Serialization ===\n");

    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.100", &client_addr.sin_addr);
    client_addr.sin_port = htons(54321);

    struct sockaddr_in lb_addr;
    memset(&lb_addr, 0, sizeof(lb_addr));
    lb_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "10.0.0.1", &lb_addr.sin_addr);
    lb_addr.sin_port = htons(8443);

    char buf[128];
    int len = build_proxy_protocol_v1_header(buf, sizeof(buf), &client_addr, &lb_addr);
    TEST_ASSERT(len > 0, "build_proxy_protocol_v1_header returns positive length");
    TEST_ASSERT(strcmp(buf, "PROXY TCP4 192.168.1.100 10.0.0.1 54321 8443\r\n") == 0,
                "Header format exactly matches HAProxy v1 specification");

    // Test with NULL addresses (UNKNOWN fallback)
    len = build_proxy_protocol_v1_header(buf, sizeof(buf), NULL, NULL);
    TEST_ASSERT(len > 0, "build_proxy_protocol_v1_header handles NULL without crashing");
    TEST_ASSERT(strstr(buf, "PROXY TCP4 UNKNOWN UNKNOWN 0 0\r\n") != NULL,
                "Header gracefully falls back to UNKNOWN endpoints");
}

/* -------------------------------------------------------------------------- */
/* Test 2: PROXY Protocol v1 Parsing with Socketpair                         */
/* -------------------------------------------------------------------------- */
static void test_proxy_protocol_v1_parse(void) {
    printf("\n=== Running Test Suite: PROXY Protocol v1 Parsing (Socketpair) ===\n");

    int sv[2];
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "Created UNIX socketpair for stream testing");

    // Case 2a: Valid PROXY header
    const char *valid_hdr = "PROXY TCP4 203.0.113.195 198.51.100.1 56324 80\r\nPayloadData";
    ssize_t w = write(sv[0], valid_hdr, strlen(valid_hdr));
    TEST_ASSERT(w == (ssize_t)strlen(valid_hdr), "Wrote valid PROXY header into stream");

    struct sockaddr_in parsed_addr;
    memset(&parsed_addr, 0, sizeof(parsed_addr));
    bool ok = parse_proxy_protocol_v1(sv[1], &parsed_addr);
    TEST_ASSERT(ok == true, "parse_proxy_protocol_v1 parses valid TCP4 header successfully");

    char parsed_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &parsed_addr.sin_addr, parsed_ip, sizeof(parsed_ip));
    TEST_ASSERT(strcmp(parsed_ip, "203.0.113.195") == 0, "Parsed source IP matches 203.0.113.195");
    TEST_ASSERT(ntohs(parsed_addr.sin_port) == 56324, "Parsed source port matches 56324");

    // Verify stream preservation: "PayloadData" should remain in socket buffer!
    char remaining[32] = {0};
    ssize_t r = read(sv[1], remaining, sizeof(remaining) - 1);
    TEST_ASSERT(r == 11 && strcmp(remaining, "PayloadData") == 0,
                "Payload following PROXY header is preserved in socket buffer without data loss");

    close(sv[0]);
    close(sv[1]);

    // Case 2b: Invalid / Non-proxy stream
    TEST_ASSERT(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "Created second socketpair");
    const char *bad_hdr = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    (void)write(sv[0], bad_hdr, strlen(bad_hdr));
    ok = parse_proxy_protocol_v1(sv[1], &parsed_addr);
    TEST_ASSERT(ok == false, "parse_proxy_protocol_v1 rejects HTTP data missing PROXY header");

    close(sv[0]);
    close(sv[1]);
}

/* -------------------------------------------------------------------------- */
/* Test 3: IPv4 Address Validation                                            */
/* -------------------------------------------------------------------------- */
static void test_net_validate_ipv4(void) {
    printf("\n=== Running Test Suite: IPv4 Address Validation ===\n");

    TEST_ASSERT(net_validate_ipv4("127.0.0.1") == true, "Valid localhost 127.0.0.1");
    TEST_ASSERT(net_validate_ipv4("10.0.0.254") == true, "Valid private IP 10.0.0.254");
    TEST_ASSERT(net_validate_ipv4("255.255.255.255") == true, "Valid broadcast 255.255.255.255");
    TEST_ASSERT(net_validate_ipv4("0.0.0.0") == true, "Valid ANY 0.0.0.0");

    TEST_ASSERT(net_validate_ipv4("256.0.0.1") == false, "Invalid octet > 255 rejected");
    TEST_ASSERT(net_validate_ipv4("1.2.3") == false, "Incomplete IP (< 4 octets) rejected");
    TEST_ASSERT(net_validate_ipv4("1.2.3.4.5") == false, "Excessive octets (> 4 octets) rejected");
    TEST_ASSERT(net_validate_ipv4("abc.def.ghi.jkl") == false, "Alphanumeric string rejected");
    TEST_ASSERT(net_validate_ipv4("") == false, "Empty string rejected");
    TEST_ASSERT(net_validate_ipv4(NULL) == false, "NULL pointer rejected");
}

/* -------------------------------------------------------------------------- */
/* Test 4: Load Balancing Algorithms (Lock-Free)                             */
/* -------------------------------------------------------------------------- */
static void test_load_balancer_algorithms(void) {
    printf("\n=== Running Test Suite: Load Balancing Algorithms ===\n");

    reset_test_backends(3);
    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.50", &client.sin_addr);
    client.sin_port = htons(12345);

    // 4a. Round-Robin
    g_config.current_algorithm = ALG_ROUND_ROBIN;
    int b1 = get_healthy_backend(&client);
    int b2 = get_healthy_backend(&client);
    int b3 = get_healthy_backend(&client);
    int b4 = get_healthy_backend(&client);

    TEST_ASSERT(b1 == 0 && b2 == 1 && b3 == 2 && b4 == 0,
                "ALG_ROUND_ROBIN rotates cyclically 0 -> 1 -> 2 -> 0");

    // Clean up active connection counts added by get_healthy_backend
    release_backend(b1);
    release_backend(b2);
    release_backend(b3);
    release_backend(b4);

    // 4b. Least Connections
    reset_test_backends(3);
    atomic_store(&g_backends[0].active_connections, 15);
    atomic_store(&g_backends[1].active_connections, 2); // Lowest load
    atomic_store(&g_backends[2].active_connections, 8);

    g_config.current_algorithm = ALG_LEAST_CONNECTIONS;
    int selected = get_healthy_backend(&client);
    TEST_ASSERT(selected == 1, "ALG_LEAST_CONNECTIONS selects backend with minimum active connections (1)");
    release_backend(selected);

    // 4c. IP Hash Affinity
    reset_test_backends(3);
    g_config.current_algorithm = ALG_IP_HASH;

    int first_choice = get_healthy_backend(&client);
    bool consistent = true;
    for (int i = 0; i < 20; i++) {
        int next_choice = get_healthy_backend(&client);
        release_backend(next_choice);
        if (next_choice != first_choice) {
            consistent = false;
            break;
        }
    }
    TEST_ASSERT(consistent == true, "ALG_IP_HASH delivers 100% deterministic session affinity for same client IP");
    release_backend(first_choice);

    // 4d. Random-2 (Power of Two Random Choices)
    reset_test_backends(3);
    atomic_store(&g_backends[0].active_connections, 100);
    atomic_store(&g_backends[1].active_connections, 1);
    atomic_store(&g_backends[2].active_connections, 1);
    g_config.current_algorithm = ALG_RANDOM_2;

    int r2_choice = get_healthy_backend(&client);
    TEST_ASSERT(r2_choice >= 0 && r2_choice < 3, "ALG_RANDOM_2 selects valid backend index");
    release_backend(r2_choice);
}

/* -------------------------------------------------------------------------- */
/* Test 5: Circuit Breaker & Health State Machine                            */
/* -------------------------------------------------------------------------- */
static void test_circuit_breaker(void) {
    printf("\n=== Running Test Suite: Circuit Breaker State Machine ===\n");

    reset_test_backends(2);
    g_config.current_algorithm = ALG_ROUND_ROBIN;

    struct sockaddr_in client;
    memset(&client, 0, sizeof(client));
    client.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &client.sin_addr);

    // Backend 0 experiences client connection failures
    for (int i = 0; i < 19; i++) {
        record_backend_failure(0);
    }
    TEST_ASSERT(g_backends[0].is_alive == true,
                "Backend remains alive below threshold (19 consecutive failures < 20)");

    // 20th failure triggers circuit breaker trip
    record_backend_failure(0);
    TEST_ASSERT(g_backends[0].is_alive == false,
                "Backend marked DOWN when client failure threshold reached (20)");

    // Verify all traffic is routed to Backend 1
    int b1 = get_healthy_backend(&client);
    int b2 = get_healthy_backend(&client);
    TEST_ASSERT(b1 == 1 && b2 == 1,
                "Traffic strictly avoids dead backend [0], routing exclusively to healthy [1]");
    release_backend(b1);
    release_backend(b2);

    // Succeeded probe restores health
    record_backend_success(0);
    TEST_ASSERT(g_backends[0].is_alive == true && g_backends[0].consecutive_failures == 0,
                "record_backend_success immediately clears failures and brings backend UP");
}

/* -------------------------------------------------------------------------- */
/* Test 6: Backend Connection Counter Underflow Protection                    */
/* -------------------------------------------------------------------------- */
static void test_backend_release_underflow(void) {
    printf("\n=== Running Test Suite: Active Connections Underflow Guard ===\n");

    reset_test_backends(1);
    TEST_ASSERT(atomic_load(&g_backends[0].active_connections) == 0, "Initial active connections is 0");

    // Release when already zero must not underflow into negative or MAX_INT
    release_backend(0);
    release_backend(0);
    int val = atomic_load(&g_backends[0].active_connections);
    TEST_ASSERT(val == 0, "release_backend on 0 active connections is strictly clamped to 0");
}

/* -------------------------------------------------------------------------- */
/* Test 7: Multithreaded MPSC Logger Thread-Safety                           */
/* -------------------------------------------------------------------------- */
#define NUM_LOG_THREADS 8
#define LOGS_PER_THREAD 100

static void *log_worker(void *arg) {
    int tid = (int)(intptr_t)arg;
    for (int i = 0; i < LOGS_PER_THREAD; i++) {
        add_log("[TEST_THREAD_%d] Event seq #%d concurrent logging test", tid, i);
        usleep(50);
    }
    return NULL;
}

static void test_mpsc_logger_concurrency(void) {
    printf("\n=== Running Test Suite: Concurrent MPSC Logger Stability ===\n");

    pthread_t threads[NUM_LOG_THREADS];
    for (int i = 0; i < NUM_LOG_THREADS; i++) {
        pthread_create(&threads[i], NULL, log_worker, (void *)(intptr_t)i);
    }

    for (int i = 0; i < NUM_LOG_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    TEST_ASSERT(true, "Completed 800 concurrent log writes across 8 threads without deadlocks or segfaults");
}

/* -------------------------------------------------------------------------- */
/* Main Test Runner                                                           */
/* -------------------------------------------------------------------------- */
int main(void) {
    printf("====================================================================\n");
    printf("          ADVANCED LOAD BALANCER - AUTOMATED TEST SUITE             \n");
    printf("====================================================================\n");

    // Enable TUI mode in tests to buffer log messages in ring-buffer without stdout pollution
    g_config.enable_tui = true;
    log_init();

    test_proxy_protocol_v1_build();
    test_proxy_protocol_v1_parse();
    test_net_validate_ipv4();
    test_load_balancer_algorithms();
    test_circuit_breaker();
    test_backend_release_underflow();
    test_mpsc_logger_concurrency();

    printf("\n====================================================================\n");
    printf("TEST RESULTS: %d Run | \033[1;32m%d Passed\033[0m | \033[1;%sm%d Failed\033[0m\n",
           g_tests_run, g_tests_passed, (g_tests_failed > 0) ? "31" : "32", g_tests_failed);
    printf("====================================================================\n");

    return (g_tests_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
