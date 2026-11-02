#define _GNU_SOURCE
#include "advlb/cluster.h"
#include "advlb/session_table.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/net_utils.h"
#include "advnet/net_core.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <poll.h>
#include <stdatomic.h>

#ifndef NO_SSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#endif

#define CLUSTER_MAGIC 0x41444C42u /* "ADLB" */
#define CLUSTER_PROTO_VERSION 3

#define CLUSTER_PKT_VRRP_ADVERT    1
#define CLUSTER_PKT_SESSION_UPSERT 2
#define CLUSTER_PKT_SESSION_DELETE 3
#define CLUSTER_PKT_SYNC_REQ       4
#define CLUSTER_PKT_SYNC_CHUNK     5

#define CLUSTER_QUEUE_CAPACITY 4096
#define CLUSTER_ANTI_REPLAY_WINDOW_MS 30000ULL

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  version;
    uint8_t  pkt_type;
    uint8_t  vrrp_router_id;
    uint8_t  sender_state;
    uint8_t  base_priority;
    uint8_t  effective_priority;
    uint16_t advert_interval_ms;
    uint32_t sender_node_id;
    uint64_t seq_num;
    uint64_t timestamp_ms;
    char     virtual_ip[46];
    uint16_t session_count;
    uint16_t reserved;
    uint8_t  hmac[CLUSTER_HMAC_LEN];
} ClusterPacketHeader;

typedef struct __attribute__((packed)) {
    ClusterPacketHeader hdr;
    ClusterSessionWire  sessions[CLUSTER_MAX_BATCH_SESSIONS];
} ClusterWirePacket;

typedef struct {
    uint8_t op_type; /* CLUSTER_PKT_SESSION_UPSERT or CLUSTER_PKT_SESSION_DELETE */
    ClusterSessionWire wire;
} SyncQueueItem;

static ClusterPeer s_peers[MAX_CLUSTER_PEERS];
static int s_num_peers = 0;
static pthread_mutex_t s_cluster_mutex = PTHREAD_MUTEX_INITIALIZER;

static SyncQueueItem s_sync_queue[CLUSTER_QUEUE_CAPACITY];
static int s_sq_head = 0;
static int s_sq_tail = 0;
static int s_sq_count = 0;
static pthread_mutex_t s_sq_mutex = PTHREAD_MUTEX_INITIALIZER;

static int s_cluster_fd = -1;
static bool s_is_custom_socket = false;
static int s_wakeup_pipe[2] = {-1, -1};
static pthread_t s_cluster_thread;
static volatile bool s_cluster_running = false;
static bool s_cluster_initialized = false;

static atomic_int s_vrrp_state = VRRP_STATE_DISABLED;
static atomic_bool s_vip_active = false;
static bool s_vip_bound_kernel = false;
static uint32_t s_node_id = 0;
static _Atomic uint32_t s_current_master_id = 0;
static uint64_t s_last_master_advert_ms = 0;
static uint8_t s_master_effective_prio = 0;
static uint64_t s_stepdown_until_ms = 0;
static volatile bool s_bulk_sync_requested = false;

static _Atomic uint64_t s_seq_counter = 1;
static _Atomic uint64_t s_tx_packets = 0;
static _Atomic uint64_t s_rx_packets = 0;
static _Atomic uint64_t s_synced_sessions = 0;
static _Atomic uint64_t s_failover_count = 0;

static inline uint64_t u64_to_net(uint64_t val) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(val);
#else
    return val;
#endif
}

static inline uint64_t net_to_u64(uint64_t val) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return __builtin_bswap64(val);
#else
    return val;
#endif
}

static uint64_t now_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000ULL);
}

static uint64_t now_wallclock_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + (uint64_t)(tv.tv_usec / 1000ULL);
}

/* Compute HMAC-SHA256 over packet buffer (with fallback keyed FNV/Sip-style digest if NO_SSL) */
static void compute_packet_hmac(const void *data, size_t len, uint8_t out_hmac[CLUSTER_HMAC_LEN]) {
    const char *secret = (g_config.cluster_secret[0] != '\0') ? g_config.cluster_secret : "adlb-default-cluster-key";
    size_t secret_len = strlen(secret);
    memset(out_hmac, 0, CLUSTER_HMAC_LEN);

#ifndef NO_SSL
    unsigned int md_len = 0;
    HMAC(EVP_sha256(),
         secret, (int)secret_len,
         (const unsigned char *)data, len,
         out_hmac, &md_len);
#else
    /* Keyed 256-bit mixing fallback for NO_SSL builds */
    uint64_t s[4] = {
        0x736f6d6570736575ULL,
        0x646f72616e646f6dULL,
        0x6c7967656e657261ULL,
        0x7465646279746573ULL
    };
    for (size_t i = 0; i < secret_len; i++) {
        s[i % 4] ^= ((uint64_t)(unsigned char)secret[i]) << ((i % 8) * 8);
        s[i % 4] *= 1099511628211ULL;
    }
    const uint8_t *bytes = (const uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        uint64_t v = bytes[i];
        s[i & 3] ^= (v + 0x9e3779b97f4a7c15ULL + (s[(i + 1) & 3] << 6) + (s[(i + 2) & 3] >> 2));
        s[i & 3] = (s[i & 3] << 13) | (s[i & 3] >> 51);
        s[i & 3] *= 0xff51afd7ed558ccdULL;
    }
    for (int r = 0; r < 4; r++) {
        s[0] += s[1]; s[2] += s[3];
        s[1] = (s[1] << 17) | (s[1] >> 47);
        s[3] = (s[3] << 21) | (s[3] >> 43);
        s[1] ^= s[0]; s[3] ^= s[2];
    }
    memcpy(out_hmac, s, CLUSTER_HMAC_LEN);
#endif
}

static bool verify_packet_hmac(ClusterWirePacket *pkt, size_t total_len) {
    uint8_t received_hmac[CLUSTER_HMAC_LEN];
    memcpy(received_hmac, pkt->hdr.hmac, CLUSTER_HMAC_LEN);
    memset(pkt->hdr.hmac, 0, CLUSTER_HMAC_LEN);

    uint8_t computed_hmac[CLUSTER_HMAC_LEN];
    compute_packet_hmac(pkt, total_len, computed_hmac);
    memcpy(pkt->hdr.hmac, received_hmac, CLUSTER_HMAC_LEN);

#ifndef NO_SSL
    return (CRYPTO_memcmp(received_hmac, computed_hmac, CLUSTER_HMAC_LEN) == 0);
#else
    uint8_t diff = 0;
    for (size_t i = 0; i < CLUSTER_HMAC_LEN; i++) {
        diff |= (received_hmac[i] ^ computed_hmac[i]);
    }
    return (diff == 0);
#endif
}

static bool is_safe_iface_name(const char *iface) {
    if (!iface || iface[0] == '\0') return false;
    size_t len = strlen(iface);
    if (len > 32) return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)iface[i];
        if (!isalnum(c) && c != '.' && c != '_' && c != '-') {
            return false;
        }
    }
    return true;
}

static bool parse_vip_cidr(const char *vip_cfg, char *out_ip, size_t ip_sz, int *out_prefix) {
    if (!vip_cfg || vip_cfg[0] == '\0') return false;
    char tmp[64];
    strncpy(tmp, vip_cfg, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *slash = strchr(tmp, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
        if (prefix <= 0 || prefix > 128) prefix = 32;
    }
    if (!net_validate_ip(tmp)) return false;
    strncpy(out_ip, tmp, ip_sz - 1);
    out_ip[ip_sz - 1] = '\0';
    if (out_prefix) *out_prefix = prefix;
    return true;
}

static void acquire_virtual_ip(void) {
    if (atomic_load_explicit(&s_vip_active, memory_order_relaxed)) return;
    atomic_store_explicit(&s_vip_active, true, memory_order_release);

    char clean_vip[64] = {0};
    int prefix = 32;
    if (!parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) {
        add_log("\033[1;32m[VRRP MASTER]\033[0m Node %08X promoted to MASTER (no VIP configured)", s_node_id);
        return;
    }

    if (is_safe_iface_name(g_config.vip_interface) && geteuid() == 0) {
        char cmd[256];
#ifdef __APPLE__
        snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s/32 alias >/dev/null 2>&1",
                 g_config.vip_interface, clean_vip);
#else
        snprintf(cmd, sizeof(cmd), "ip addr add %s/%d dev %s >/dev/null 2>&1; arping -U -c 1 -I %s %s >/dev/null 2>&1 || true",
                 clean_vip, prefix, g_config.vip_interface, g_config.vip_interface, clean_vip);
#endif
        int rc = system(cmd);
        s_vip_bound_kernel = (rc == 0);
        add_log("\033[1;32m[VRRP VIP]\033[0m Bound Virtual IP %s on %s + sent Gratuitous ARP",
                clean_vip, g_config.vip_interface);
    } else {
        s_vip_bound_kernel = false;
        add_log("\033[1;32m[VRRP VIP]\033[0m Virtual IP %s ACTIVE on MASTER Node %08X (user-space mode)",
                clean_vip, s_node_id);
    }
}

static void release_virtual_ip(void) {
    if (!atomic_load_explicit(&s_vip_active, memory_order_relaxed)) return;
    atomic_store_explicit(&s_vip_active, false, memory_order_release);

    char clean_vip[64] = {0};
    int prefix = 32;
    if (!parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) {
        return;
    }

    if (s_vip_bound_kernel && is_safe_iface_name(g_config.vip_interface) && geteuid() == 0) {
        char cmd[256];
#ifdef __APPLE__
        snprintf(cmd, sizeof(cmd), "ifconfig %s inet %s -alias >/dev/null 2>&1",
                 g_config.vip_interface, clean_vip);
#else
        snprintf(cmd, sizeof(cmd), "ip addr del %s/%d dev %s >/dev/null 2>&1",
                 clean_vip, prefix, g_config.vip_interface);
#endif
        int rc = system(cmd);
        (void)rc;
        s_vip_bound_kernel = false;
    }
    add_log("\033[1;33m[VRRP VIP]\033[0m Released Virtual IP %s from Node %08X", clean_vip, s_node_id);
}

static uint8_t compute_effective_priority(void) {
    int base = g_config.vrrp_priority;
    if (base < 1) base = 1;
    if (base > 254) base = 254;

    uint64_t now_ms = now_monotonic_ms();
    if (s_stepdown_until_ms > now_ms) {
        return 1;
    }

    int num_b = g_num_backends;
    if (num_b > 0) {
        int alive = 0;
        for (int i = 0; i < num_b; i++) {
            if (atomic_load_explicit(&g_backends[i].is_alive, memory_order_relaxed)) {
                alive++;
            }
        }
        if (alive == 0) {
            return (base > 50) ? (uint8_t)(base - 50) : 1;
        }
    }
    return (uint8_t)base;
}

static bool is_peer_better_than(uint8_t peer_prio, uint32_t peer_id, uint8_t ref_prio, uint32_t ref_id) {
    if (peer_prio > ref_prio) return true;
    if (peer_prio == ref_prio && peer_id > ref_id) return true;
    return false;
}

void cluster_init(void) {
    if (s_cluster_initialized) return;
    session_table_init();
    pthread_mutex_lock(&s_cluster_mutex);
    memset(s_peers, 0, sizeof(s_peers));
    s_num_peers = 0;
    pthread_mutex_unlock(&s_cluster_mutex);

    pthread_mutex_lock(&s_sq_mutex);
    s_sq_head = 0;
    s_sq_tail = 0;
    s_sq_count = 0;
    pthread_mutex_unlock(&s_sq_mutex);

    atomic_store(&s_vrrp_state, VRRP_STATE_DISABLED);
    atomic_store(&s_vip_active, false);
    atomic_store(&s_current_master_id, 0);
    s_cluster_initialized = true;
}

void cluster_clear_peers(void) {
    if (!s_cluster_initialized) cluster_init();
    pthread_mutex_lock(&s_cluster_mutex);
    memset(s_peers, 0, sizeof(s_peers));
    s_num_peers = 0;
    pthread_mutex_unlock(&s_cluster_mutex);
}

bool cluster_add_peer(const char *ip_port) {
    if (!s_cluster_initialized) cluster_init();
    if (!ip_port || ip_port[0] == '\0') return false;

    char copy[256];
    strncpy(copy, ip_port, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';

    char *saveptr = NULL;
    char *tok = strtok_r(copy, ",", &saveptr);
    bool any_added = false;

    while (tok) {
        while (*tok && isspace((unsigned char)*tok)) tok++;
        char *end = tok + strlen(tok) - 1;
        while (end >= tok && isspace((unsigned char)*end)) {
            *end = '\0';
            end--;
        }
        if (*tok == '\0') {
            tok = strtok_r(NULL, ",", &saveptr);
            continue;
        }

        char host[64] = {0};
        int port = (g_config.cluster_port > 0) ? g_config.cluster_port : DEFAULT_CLUSTER_PORT;

        char *colon = strrchr(tok, ':');
        if (colon && strchr(tok, ':') == colon) {
            *colon = '\0';
            strncpy(host, tok, sizeof(host) - 1);
            port = atoi(colon + 1);
        } else {
            strncpy(host, tok, sizeof(host) - 1);
        }

        if (port <= 0 || port > 65535) {
            return false;
        }

        struct sockaddr_storage ss;
        socklen_t ss_len = 0;
        memset(&ss, 0, sizeof(ss));

        struct in_addr a4;
        struct in6_addr a6;
        if (inet_pton(AF_INET, host, &a4) == 1) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&ss;
            s4->sin_family = AF_INET;
            s4->sin_port = htons((uint16_t)port);
            s4->sin_addr = a4;
            ss_len = sizeof(struct sockaddr_in);
        } else if (inet_pton(AF_INET6, host, &a6) == 1) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ss;
            s6->sin6_family = AF_INET6;
            s6->sin6_port = htons((uint16_t)port);
            s6->sin6_addr = a6;
            ss_len = sizeof(struct sockaddr_in6);
        } else {
            return false;
        }

        pthread_mutex_lock(&s_cluster_mutex);
        bool exists = false;
        for (int i = 0; i < s_num_peers; i++) {
            if (s_peers[i].port == port && strcmp(s_peers[i].ip, host) == 0) {
                exists = true;
                break;
            }
        }
        if (!exists && s_num_peers < MAX_CLUSTER_PEERS) {
            ClusterPeer *p = &s_peers[s_num_peers++];
            memset(p, 0, sizeof(*p));
            strncpy(p->ip, host, sizeof(p->ip) - 1);
            p->port = port;
            p->addr = ss;
            p->addr_len = ss_len;
            any_added = true;
        } else if (exists) {
            any_added = true;
        }
        pthread_mutex_unlock(&s_cluster_mutex);

        tok = strtok_r(NULL, ",", &saveptr);
    }

    return any_added;
}

static void wakeup_cluster_thread(void) {
    if (s_wakeup_pipe[1] >= 0) {
        char b = 1;
        ssize_t r = write(s_wakeup_pipe[1], &b, 1);
        (void)r;
    }
}

void cluster_queue_session_upsert(const ClusterSessionWire *wire) {
    if (!s_cluster_running || !wire) return;
    pthread_mutex_lock(&s_sq_mutex);
    if (s_sq_count >= CLUSTER_QUEUE_CAPACITY) {
        /* Drop oldest if full */
        s_sq_head = (s_sq_head + 1) % CLUSTER_QUEUE_CAPACITY;
        s_sq_count--;
    }
    s_sync_queue[s_sq_tail].op_type = CLUSTER_PKT_SESSION_UPSERT;
    s_sync_queue[s_sq_tail].wire = *wire;
    s_sq_tail = (s_sq_tail + 1) % CLUSTER_QUEUE_CAPACITY;
    s_sq_count++;
    pthread_mutex_unlock(&s_sq_mutex);
    wakeup_cluster_thread();
}

void cluster_queue_session_delete(const ClusterSessionWire *wire) {
    if (!s_cluster_running || !wire) return;
    pthread_mutex_lock(&s_sq_mutex);
    if (s_sq_count >= CLUSTER_QUEUE_CAPACITY) {
        s_sq_head = (s_sq_head + 1) % CLUSTER_QUEUE_CAPACITY;
        s_sq_count--;
    }
    s_sync_queue[s_sq_tail].op_type = CLUSTER_PKT_SESSION_DELETE;
    s_sync_queue[s_sq_tail].wire = *wire;
    s_sq_tail = (s_sq_tail + 1) % CLUSTER_QUEUE_CAPACITY;
    s_sq_count++;
    pthread_mutex_unlock(&s_sq_mutex);
    wakeup_cluster_thread();
}

static size_t prepare_packet(ClusterWirePacket *pkt,
                             uint8_t pkt_type,
                             uint8_t eff_prio_override,
                             bool use_override,
                             const ClusterSessionWire *sessions,
                             uint16_t session_count) {
    if (session_count > CLUSTER_MAX_BATCH_SESSIONS) {
        session_count = CLUSTER_MAX_BATCH_SESSIONS;
    }
    memset(pkt, 0, sizeof(ClusterPacketHeader));
    pkt->hdr.magic = htonl(CLUSTER_MAGIC);
    pkt->hdr.version = CLUSTER_PROTO_VERSION;
    pkt->hdr.pkt_type = pkt_type;
    pkt->hdr.vrrp_router_id = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
    pkt->hdr.sender_state = (uint8_t)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);
    pkt->hdr.base_priority = (uint8_t)(g_config.vrrp_priority > 0 ? g_config.vrrp_priority : 100);
    pkt->hdr.effective_priority = use_override ? eff_prio_override : compute_effective_priority();
    uint16_t adv_ms = (uint16_t)(g_config.vrrp_advert_interval_ms > 0 ? g_config.vrrp_advert_interval_ms : 200);
    pkt->hdr.advert_interval_ms = htons(adv_ms);
    pkt->hdr.sender_node_id = htonl(s_node_id);

    uint64_t seq = atomic_fetch_add_explicit(&s_seq_counter, 1, memory_order_relaxed);
    pkt->hdr.seq_num = u64_to_net(seq);
    pkt->hdr.timestamp_ms = u64_to_net(now_wallclock_ms());
    strncpy(pkt->hdr.virtual_ip, g_config.virtual_ip, sizeof(pkt->hdr.virtual_ip) - 1);
    pkt->hdr.session_count = htons(session_count);

    if (session_count > 0 && sessions != NULL) {
        memcpy(pkt->sessions, sessions, (size_t)session_count * sizeof(ClusterSessionWire));
    }

    size_t total_len = sizeof(ClusterPacketHeader) + (size_t)session_count * sizeof(ClusterSessionWire);
    compute_packet_hmac(pkt, total_len, pkt->hdr.hmac);
    return total_len;
}

static void broadcast_cluster_packet(const ClusterWirePacket *pkt, size_t total_len) {
    if (s_cluster_fd < 0) return;

    if (s_is_custom_socket) {
        ssize_t s = send(s_cluster_fd, pkt, total_len, 0);
        if (s > 0) {
            atomic_fetch_add_explicit(&s_tx_packets, 1, memory_order_relaxed);
        }
        return;
    }

    pthread_mutex_lock(&s_cluster_mutex);
    for (int i = 0; i < s_num_peers; i++) {
        ssize_t s = sendto(s_cluster_fd, pkt, total_len, 0,
                           (const struct sockaddr *)&s_peers[i].addr, s_peers[i].addr_len);
        if (s > 0) {
            atomic_fetch_add_explicit(&s_tx_packets, 1, memory_order_relaxed);
        }
    }
    pthread_mutex_unlock(&s_cluster_mutex);

    if (g_config.cluster_enable_multicast) {
        struct sockaddr_in mcast_addr;
        memset(&mcast_addr, 0, sizeof(mcast_addr));
        mcast_addr.sin_family = AF_INET;
        int cport = (g_config.cluster_port > 0) ? g_config.cluster_port : DEFAULT_CLUSTER_PORT;
        mcast_addr.sin_port = htons((uint16_t)cport);
        inet_pton(AF_INET, VRRP_MULTICAST_GROUP, &mcast_addr.sin_addr);
        ssize_t s = sendto(s_cluster_fd, pkt, total_len, 0,
                           (const struct sockaddr *)&mcast_addr, sizeof(mcast_addr));
        if (s > 0) {
            atomic_fetch_add_explicit(&s_tx_packets, 1, memory_order_relaxed);
        }
    }
}

static void send_packet_to_addr(const ClusterWirePacket *pkt,
                                size_t total_len,
                                const struct sockaddr_storage *dest,
                                socklen_t dest_len) {
    if (s_cluster_fd < 0) return;
    ssize_t s;
    if (s_is_custom_socket || !dest || dest_len == 0) {
        s = send(s_cluster_fd, pkt, total_len, 0);
    } else {
        s = sendto(s_cluster_fd, pkt, total_len, 0, (const struct sockaddr *)dest, dest_len);
    }
    if (s > 0) {
        atomic_fetch_add_explicit(&s_tx_packets, 1, memory_order_relaxed);
    }
}

static void drain_and_broadcast_sync_queue(void) {
    while (1) {
        ClusterSessionWire batch[CLUSTER_MAX_BATCH_SESSIONS];
        uint16_t count = 0;
        uint8_t batch_type = 0;

        pthread_mutex_lock(&s_sq_mutex);
        while (s_sq_count > 0 && count < CLUSTER_MAX_BATCH_SESSIONS) {
            SyncQueueItem *item = &s_sync_queue[s_sq_head];
            if (count == 0) {
                batch_type = item->op_type;
            } else if (item->op_type != batch_type) {
                break;
            }
            batch[count++] = item->wire;
            s_sq_head = (s_sq_head + 1) % CLUSTER_QUEUE_CAPACITY;
            s_sq_count--;
        }
        pthread_mutex_unlock(&s_sq_mutex);

        if (count == 0) break;

        ClusterWirePacket pkt;
        size_t len = prepare_packet(&pkt, batch_type, 0, false, batch, count);
        broadcast_cluster_packet(&pkt, len);
    }
}

static void handle_bulk_sync_request(const struct sockaddr_storage *requester_addr, socklen_t requester_len) {
    #define SNAPSHOT_CAP 2048
    ClusterSessionWire *snapshot = calloc(SNAPSHOT_CAP, sizeof(ClusterSessionWire));
    if (!snapshot) return;

    int total = session_table_export_snapshot(snapshot, SNAPSHOT_CAP);
    int offset = 0;
    while (offset < total) {
        uint16_t chunk = (uint16_t)((total - offset > CLUSTER_MAX_BATCH_SESSIONS)
                                    ? CLUSTER_MAX_BATCH_SESSIONS
                                    : (total - offset));
        ClusterWirePacket pkt;
        size_t len = prepare_packet(&pkt, CLUSTER_PKT_SYNC_CHUNK, 0, false, &snapshot[offset], chunk);
        send_packet_to_addr(&pkt, len, requester_addr, requester_len);
        offset += chunk;
    }
    free(snapshot);
    #undef SNAPSHOT_CAP
}

static ClusterPeer *update_or_register_peer_locked(uint32_t sender_id,
                                                   const struct sockaddr_storage *src_addr,
                                                   socklen_t src_len,
                                                   uint8_t state,
                                                   uint8_t base_prio,
                                                   uint8_t eff_prio,
                                                   uint64_t seq,
                                                   uint64_t now_ms) {
    char src_ip[64] = {0};
    int src_port = 0;
    if (src_addr->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)src_addr;
        inet_ntop(AF_INET, &s4->sin_addr, src_ip, sizeof(src_ip));
        src_port = ntohs(s4->sin_port);
    } else if (src_addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)src_addr;
        inet_ntop(AF_INET6, &s6->sin6_addr, src_ip, sizeof(src_ip));
        src_port = ntohs(s6->sin6_port);
    }

    ClusterPeer *found = NULL;
    for (int i = 0; i < s_num_peers; i++) {
        if (s_peers[i].node_id == sender_id && sender_id != 0) {
            found = &s_peers[i];
            break;
        }
        if (s_peers[i].port == src_port && strcmp(s_peers[i].ip, src_ip) == 0) {
            found = &s_peers[i];
            break;
        }
    }

    if (!found && s_num_peers < MAX_CLUSTER_PEERS && (src_port > 0 || s_is_custom_socket)) {
        found = &s_peers[s_num_peers++];
        memset(found, 0, sizeof(*found));
        strncpy(found->ip, (src_ip[0] != '\0') ? src_ip : "unix-peer", sizeof(found->ip) - 1);
        found->port = src_port;
        if (src_addr && src_len > 0) {
            found->addr = *src_addr;
            found->addr_len = src_len;
        }
    }

    if (found) {
        /* Anti-replay check on sequence number if peer did not restart */
        if (found->is_reachable && found->node_id == sender_id && seq <= found->last_seq &&
            (found->last_seq - seq) < 100000ULL) {
            return NULL;
        }
        found->node_id = sender_id;
        found->state = state;
        found->base_priority = base_prio;
        found->effective_priority = eff_prio;
        found->last_seen_ms = now_ms;
        found->last_seq = seq;
        found->is_reachable = true;
    }
    return found;
}

static void transition_to_master(uint64_t now_ms) {
    VrrpState prev = (VrrpState)atomic_exchange_explicit(&s_vrrp_state, VRRP_STATE_MASTER, memory_order_acq_rel);
    atomic_store_explicit(&s_current_master_id, s_node_id, memory_order_relaxed);
    s_last_master_advert_ms = now_ms;
    s_master_effective_prio = compute_effective_priority();

    if (prev != VRRP_STATE_MASTER) {
        atomic_fetch_add_explicit(&s_failover_count, 1, memory_order_relaxed);
        acquire_virtual_ip();
        add_log("\033[1;32m[VRRP ELECTION]\033[0m Node %08X transitioned %s -> MASTER (prio %u, VRID %d)",
                s_node_id, cluster_state_name(prev),
                (unsigned int)s_master_effective_prio, g_config.vrrp_router_id);

        /* Immediately broadcast MASTER advertisement */
        ClusterWirePacket pkt;
        size_t len = prepare_packet(&pkt, CLUSTER_PKT_VRRP_ADVERT, 0, false, NULL, 0);
        broadcast_cluster_packet(&pkt, len);
    }
}

static void transition_to_backup(uint32_t new_master_id, uint8_t master_prio, uint64_t now_ms) {
    VrrpState prev = (VrrpState)atomic_exchange_explicit(&s_vrrp_state, VRRP_STATE_BACKUP, memory_order_acq_rel);
    atomic_store_explicit(&s_current_master_id, new_master_id, memory_order_relaxed);
    s_last_master_advert_ms = now_ms;
    s_master_effective_prio = master_prio;

    if (prev == VRRP_STATE_MASTER) {
        release_virtual_ip();
        add_log("\033[1;33m[VRRP ELECTION]\033[0m Node %08X stepped down MASTER -> BACKUP (new Master %08X, prio %u)",
                s_node_id, new_master_id, (unsigned int)master_prio);
    }
}

static void process_incoming_packet(ClusterWirePacket *pkt,
                                    size_t bytes_read,
                                    const struct sockaddr_storage *src_addr,
                                    socklen_t src_len,
                                    uint64_t now_ms) {
    if (bytes_read < sizeof(ClusterPacketHeader)) return;
    if (ntohl(pkt->hdr.magic) != CLUSTER_MAGIC) return;
    if (pkt->hdr.version != CLUSTER_PROTO_VERSION) return;

    uint8_t expected_vrid = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
    if (pkt->hdr.vrrp_router_id != expected_vrid) return;

    uint32_t sender_id = ntohl(pkt->hdr.sender_node_id);
    if (sender_id == s_node_id) {
        /* Ignore our own multicast loopback */
        return;
    }

    uint16_t sess_count = ntohs(pkt->hdr.session_count);
    if (sess_count > CLUSTER_MAX_BATCH_SESSIONS) return;
    size_t expected_len = sizeof(ClusterPacketHeader) + (size_t)sess_count * sizeof(ClusterSessionWire);
    if (bytes_read < expected_len) return;

    /* Wall-clock anti-replay check */
    uint64_t pkt_wall_ms = net_to_u64(pkt->hdr.timestamp_ms);
    uint64_t local_wall_ms = now_wallclock_ms();
    uint64_t diff_ms = (local_wall_ms > pkt_wall_ms) ? (local_wall_ms - pkt_wall_ms) : (pkt_wall_ms - local_wall_ms);
    if (diff_ms > CLUSTER_ANTI_REPLAY_WINDOW_MS) {
        return;
    }

    /* Cryptographic HMAC-SHA256 verification */
    if (!verify_packet_hmac(pkt, expected_len)) {
        return;
    }

    atomic_fetch_add_explicit(&s_rx_packets, 1, memory_order_relaxed);

    uint64_t seq = net_to_u64(pkt->hdr.seq_num);
    uint8_t sender_state = pkt->hdr.sender_state;
    uint8_t sender_base_prio = pkt->hdr.base_priority;
    uint8_t sender_eff_prio = pkt->hdr.effective_priority;

    pthread_mutex_lock(&s_cluster_mutex);
    ClusterPeer *peer = update_or_register_peer_locked(sender_id, src_addr, src_len,
                                                       sender_state, sender_base_prio,
                                                       sender_eff_prio, seq, now_ms);
    pthread_mutex_unlock(&s_cluster_mutex);
    if (!peer) {
        /* Replayed sequence number */
        return;
    }

    uint8_t my_eff_prio = compute_effective_priority();
    VrrpState my_state = (VrrpState)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);

    /* VRRP State Machine & Master Election */
    if (pkt->hdr.pkt_type == CLUSTER_PKT_VRRP_ADVERT) {
        if (sender_eff_prio == 0) {
            /* Current Master sent Priority-0 release (graceful shutdown or manual stepdown) */
            if (atomic_load_explicit(&s_current_master_id, memory_order_relaxed) == sender_id) {
                s_last_master_advert_ms = 0;
                s_master_effective_prio = 0;
                atomic_store_explicit(&s_current_master_id, 0, memory_order_relaxed);
            }
        } else if (sender_state == VRRP_STATE_MASTER) {
            if (my_state == VRRP_STATE_MASTER) {
                /* Split-brain / simultaneous Master tie-break */
                if (is_peer_better_than(sender_eff_prio, sender_id, my_eff_prio, s_node_id)) {
                    transition_to_backup(sender_id, sender_eff_prio, now_ms);
                } else {
                    /* We outrank the remote Master: re-assert our Master state immediately */
                    ClusterWirePacket assert_pkt;
                    size_t len = prepare_packet(&assert_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, false, NULL, 0);
                    broadcast_cluster_packet(&assert_pkt, len);
                }
            } else {
                /* We are BACKUP or INIT */
                bool preempt = g_config.vrrp_preempt;
                if (!preempt || is_peer_better_than(sender_eff_prio, sender_id, my_eff_prio, s_node_id)) {
                    transition_to_backup(sender_id, sender_eff_prio, now_ms);
                }
            }
        } else if (sender_state == VRRP_STATE_BACKUP) {
            /* Even from a BACKUP peer, if it outranks us while we are BACKUP, note its presence */
            if (my_state != VRRP_STATE_MASTER &&
                is_peer_better_than(sender_eff_prio, sender_id, my_eff_prio, s_node_id) &&
                is_peer_better_than(sender_eff_prio, sender_id, s_master_effective_prio,
                                    atomic_load_explicit(&s_current_master_id, memory_order_relaxed))) {
                s_last_master_advert_ms = now_ms;
            }
        }
    } else if (pkt->hdr.pkt_type == CLUSTER_PKT_SESSION_UPSERT ||
               pkt->hdr.pkt_type == CLUSTER_PKT_SYNC_CHUNK) {
        for (uint16_t i = 0; i < sess_count; i++) {
            if (session_table_apply_remote(&pkt->sessions[i])) {
                atomic_fetch_add_explicit(&s_synced_sessions, 1, memory_order_relaxed);
            }
        }
    } else if (pkt->hdr.pkt_type == CLUSTER_PKT_SESSION_DELETE) {
        for (uint16_t i = 0; i < sess_count; i++) {
            session_table_delete_remote(&pkt->sessions[i]);
        }
    } else if (pkt->hdr.pkt_type == CLUSTER_PKT_SYNC_REQ) {
        /* If we are MASTER (or have active sessions), send snapshot back to requester */
        if (my_state == VRRP_STATE_MASTER || session_table_count() > 0) {
            handle_bulk_sync_request(src_addr, src_len);
        }
    }
}

static void *cluster_worker_thread(void *arg) {
    (void)arg;
    uint64_t advert_ms = (uint64_t)(g_config.vrrp_advert_interval_ms > 0 ? g_config.vrrp_advert_interval_ms : 200);
    if (advert_ms < 20) advert_ms = 20;

    uint64_t now_ms = now_monotonic_ms();
    uint64_t last_advert_sent_ms = 0;
    uint64_t last_cleanup_ms = now_ms;
    s_last_master_advert_ms = now_ms;

    /* Initial announcement + request Bulk Session Sync from existing cluster nodes */
    {
        ClusterWirePacket sync_req;
        size_t len = prepare_packet(&sync_req, CLUSTER_PKT_SYNC_REQ, 0, false, NULL, 0);
        broadcast_cluster_packet(&sync_req, len);

        ClusterWirePacket adv_pkt;
        len = prepare_packet(&adv_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, false, NULL, 0);
        broadcast_cluster_packet(&adv_pkt, len);
        last_advert_sent_ms = now_ms;
    }

    while (s_cluster_running && g_server_running) {
        struct pollfd pfds[2];
        int nfds = 1;
        pfds[0].fd = s_cluster_fd;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;

        if (s_wakeup_pipe[0] >= 0) {
            pfds[1].fd = s_wakeup_pipe[0];
            pfds[1].events = POLLIN;
            pfds[1].revents = 0;
            nfds = 2;
        }

        int timeout_ms = (int)(advert_ms / 2);
        if (timeout_ms < 10) timeout_ms = 10;
        if (timeout_ms > 100) timeout_ms = 100;

        int pr = poll(pfds, (nfds_t)nfds, timeout_ms);
        now_ms = now_monotonic_ms();

        if (pr > 0) {
            if (nfds == 2 && (pfds[1].revents & POLLIN)) {
                char drain[64];
                while (read(s_wakeup_pipe[0], drain, sizeof(drain)) > 0) {}
            }
            if (pfds[0].revents & POLLIN) {
                while (1) {
                    ClusterWirePacket rx_pkt;
                    struct sockaddr_storage src_addr;
                    socklen_t src_len = sizeof(src_addr);
                    ssize_t n = recvfrom(s_cluster_fd, &rx_pkt, sizeof(rx_pkt), 0,
                                         (struct sockaddr *)&src_addr, &src_len);
                    if (n <= 0) break;
                    process_incoming_packet(&rx_pkt, (size_t)n, &src_addr, src_len, now_ms);
                }
            }
        }

        if (s_bulk_sync_requested) {
            s_bulk_sync_requested = false;
            ClusterWirePacket sync_req;
            size_t len = prepare_packet(&sync_req, CLUSTER_PKT_SYNC_REQ, 0, false, NULL, 0);
            broadcast_cluster_packet(&sync_req, len);
        }

        /* Drain pending session replication deltas */
        drain_and_broadcast_sync_queue();

        /* Evaluate VRRP Election & Master Down Timer */
        uint8_t my_eff_prio = compute_effective_priority();
        uint64_t skew_ms = ((uint64_t)(256 - my_eff_prio) * advert_ms) / 256ULL;
        uint64_t master_down_ms = 3ULL * advert_ms + skew_ms;

        /* Expire unreachable peers */
        uint32_t best_alive_peer_id = 0;
        uint8_t best_alive_peer_prio = 0;
        pthread_mutex_lock(&s_cluster_mutex);
        for (int i = 0; i < s_num_peers; i++) {
            if (s_peers[i].is_reachable && (now_ms - s_peers[i].last_seen_ms) > (3ULL * advert_ms + 250ULL)) {
                s_peers[i].is_reachable = false;
                s_peers[i].state = VRRP_STATE_INIT;
                add_log("\033[1;31m[CLUSTER PEER]\033[0m Peer %s:%d (Node %08X) timed out -> UNREACHABLE",
                        s_peers[i].ip, s_peers[i].port, s_peers[i].node_id);
            }
            if (s_peers[i].is_reachable) {
                if (is_peer_better_than(s_peers[i].effective_priority, s_peers[i].node_id,
                                        best_alive_peer_prio, best_alive_peer_id)) {
                    best_alive_peer_prio = s_peers[i].effective_priority;
                    best_alive_peer_id = s_peers[i].node_id;
                }
            }
        }
        pthread_mutex_unlock(&s_cluster_mutex);

        VrrpState cur_state = (VrrpState)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);
        if (cur_state != VRRP_STATE_MASTER) {
            bool better_peer_alive = is_peer_better_than(best_alive_peer_prio, best_alive_peer_id,
                                                         my_eff_prio, s_node_id);
            if (!better_peer_alive && (now_ms - s_last_master_advert_ms) >= master_down_ms) {
                transition_to_master(now_ms);
            } else if (better_peer_alive && g_config.vrrp_preempt) {
                /* Keep timer refreshed while a higher-priority peer is alive */
                s_last_master_advert_ms = now_ms;
            }
        } else {
            /* If we are MASTER but stepped down or a higher-priority peer is alive with preemption */
            if (g_config.vrrp_preempt &&
                is_peer_better_than(best_alive_peer_prio, best_alive_peer_id, my_eff_prio, s_node_id)) {
                transition_to_backup(best_alive_peer_id, best_alive_peer_prio, now_ms);
            }
        }

        /* Send periodic VRRP Advertisement */
        if ((now_ms - last_advert_sent_ms) >= advert_ms) {
            ClusterWirePacket adv_pkt;
            size_t len = prepare_packet(&adv_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, false, NULL, 0);
            broadcast_cluster_packet(&adv_pkt, len);
            last_advert_sent_ms = now_ms;
        }

        /* Periodic session expiration cleanup every 5 seconds */
        if ((now_ms - last_cleanup_ms) >= 5000ULL) {
            session_table_cleanup_expired();
            last_cleanup_ms = now_ms;
        }
    }

    return NULL;
}

bool cluster_start_with_socket(int custom_dgram_fd) {
    if (!s_cluster_initialized) cluster_init();
    if (s_cluster_running) return true;
    if (custom_dgram_fd < 0) return false;

    int cport = (g_config.cluster_port > 0) ? g_config.cluster_port : DEFAULT_CLUSTER_PORT;
    if (g_config.cluster_node_id != 0) {
        s_node_id = g_config.cluster_node_id;
    } else {
        s_node_id = (0x7F000001u << 16) ^ ((uint32_t)cport & 0xFFFFu) ^ ((uint32_t)getpid() & 0xFFFFu);
        if (s_node_id == 0) s_node_id = 1;
    }

    net_set_nonblocking(custom_dgram_fd);
    if (pipe(s_wakeup_pipe) == 0) {
        net_set_nonblocking(s_wakeup_pipe[0]);
        net_set_nonblocking(s_wakeup_pipe[1]);
    } else {
        s_wakeup_pipe[0] = s_wakeup_pipe[1] = -1;
    }

    s_cluster_fd = custom_dgram_fd;
    s_is_custom_socket = true;
    atomic_store(&s_vrrp_state, VRRP_STATE_BACKUP);
    atomic_store(&s_vip_active, false);
    atomic_store(&s_current_master_id, 0);
    s_stepdown_until_ms = 0;
    s_cluster_running = true;

    if (pthread_create(&s_cluster_thread, NULL, cluster_worker_thread, NULL) != 0) {
        s_cluster_running = false;
        s_cluster_fd = -1;
        s_is_custom_socket = false;
        if (s_wakeup_pipe[0] >= 0) close(s_wakeup_pipe[0]);
        if (s_wakeup_pipe[1] >= 0) close(s_wakeup_pipe[1]);
        s_wakeup_pipe[0] = s_wakeup_pipe[1] = -1;
        return false;
    }
    return true;
}

bool cluster_start(void) {
    if (!s_cluster_initialized) cluster_init();
    if (s_cluster_running) return true;
    s_is_custom_socket = false;

    int cport = (g_config.cluster_port > 0) ? g_config.cluster_port : DEFAULT_CLUSTER_PORT;
    const char *bind_ip = (g_config.cluster_bind_ip[0] != '\0') ? g_config.cluster_bind_ip : "0.0.0.0";

    if (g_config.cluster_node_id != 0) {
        s_node_id = g_config.cluster_node_id;
    } else {
        struct in_addr b4;
        uint32_t ip_part = 0x7F000001u;
        if (inet_pton(AF_INET, bind_ip, &b4) == 1 && b4.s_addr != 0) {
            ip_part = ntohl(b4.s_addr);
        }
        s_node_id = (ip_part << 16) ^ ((uint32_t)cport & 0xFFFFu) ^ ((uint32_t)getpid() & 0xFFFFu);
        if (s_node_id == 0) s_node_id = 1;
    }

    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return false;
    }
    net_set_reuse(fd, 1, 1);
    net_set_nonblocking(fd);

    struct sockaddr_in baddr;
    memset(&baddr, 0, sizeof(baddr));
    baddr.sin_family = AF_INET;
    baddr.sin_port = htons((uint16_t)cport);
    if (inet_pton(AF_INET, bind_ip, &baddr.sin_addr) != 1) {
        baddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(fd, (struct sockaddr *)&baddr, sizeof(baddr)) < 0) {
        close(fd);
        return false;
    }

    if (g_config.cluster_enable_multicast) {
        struct ip_mreq mreq;
        memset(&mreq, 0, sizeof(mreq));
        inet_pton(AF_INET, VRRP_MULTICAST_GROUP, &mreq.imr_multiaddr);
        mreq.imr_interface.s_addr = baddr.sin_addr.s_addr;
        setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));

        unsigned char loop = 1;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof(loop));
        unsigned char ttl = 255;
        setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
    }

    if (pipe(s_wakeup_pipe) == 0) {
        net_set_nonblocking(s_wakeup_pipe[0]);
        net_set_nonblocking(s_wakeup_pipe[1]);
    } else {
        s_wakeup_pipe[0] = s_wakeup_pipe[1] = -1;
    }

    s_cluster_fd = fd;
    atomic_store(&s_vrrp_state, VRRP_STATE_BACKUP);
    atomic_store(&s_vip_active, false);
    atomic_store(&s_current_master_id, 0);
    s_stepdown_until_ms = 0;
    s_cluster_running = true;

    if (pthread_create(&s_cluster_thread, NULL, cluster_worker_thread, NULL) != 0) {
        s_cluster_running = false;
        close(s_cluster_fd);
        s_cluster_fd = -1;
        if (s_wakeup_pipe[0] >= 0) close(s_wakeup_pipe[0]);
        if (s_wakeup_pipe[1] >= 0) close(s_wakeup_pipe[1]);
        s_wakeup_pipe[0] = s_wakeup_pipe[1] = -1;
        return false;
    }

    add_log("\033[1;36m[CLUSTER]\033[0m VRRP & Session Sync started on %s:%d (Node %08X, VRID %d, prio %d)",
            bind_ip, cport, s_node_id, g_config.vrrp_router_id, g_config.vrrp_priority);
    return true;
}

void cluster_stop(void) {
    if (!s_cluster_running) return;

    /* If we are MASTER, send Priority-0 release packet for instant failover (<5ms) */
    if (atomic_load_explicit(&s_vrrp_state, memory_order_relaxed) == VRRP_STATE_MASTER) {
        ClusterWirePacket rel_pkt;
        size_t len = prepare_packet(&rel_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, true, NULL, 0);
        broadcast_cluster_packet(&rel_pkt, len);
        release_virtual_ip();
    }

    s_cluster_running = false;
    wakeup_cluster_thread();
    pthread_join(s_cluster_thread, NULL);

    if (s_cluster_fd >= 0) {
        close(s_cluster_fd);
        s_cluster_fd = -1;
    }
    s_is_custom_socket = false;
    if (s_wakeup_pipe[0] >= 0) {
        close(s_wakeup_pipe[0]);
        s_wakeup_pipe[0] = -1;
    }
    if (s_wakeup_pipe[1] >= 0) {
        close(s_wakeup_pipe[1]);
        s_wakeup_pipe[1] = -1;
    }
    atomic_store(&s_vrrp_state, VRRP_STATE_DISABLED);
}

VrrpState cluster_get_state(void) {
    return (VrrpState)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);
}

const char *cluster_state_name(VrrpState state) {
    switch (state) {
        case VRRP_STATE_DISABLED: return "DISABLED";
        case VRRP_STATE_INIT:     return "INIT";
        case VRRP_STATE_BACKUP:   return "BACKUP";
        case VRRP_STATE_MASTER:   return "MASTER";
        default:                  return "UNKNOWN";
    }
}

bool cluster_is_vip_active(void) {
    return atomic_load_explicit(&s_vip_active, memory_order_relaxed);
}

int cluster_get_alive_peers(int *out_total_peers) {
    int alive = 0;
    pthread_mutex_lock(&s_cluster_mutex);
    if (out_total_peers) *out_total_peers = s_num_peers;
    for (int i = 0; i < s_num_peers; i++) {
        if (s_peers[i].is_reachable) alive++;
    }
    pthread_mutex_unlock(&s_cluster_mutex);
    return alive;
}

uint32_t cluster_get_node_id(void) {
    return s_node_id;
}

uint32_t cluster_get_current_master_id(void) {
    return atomic_load_explicit(&s_current_master_id, memory_order_relaxed);
}

void cluster_trigger_stepdown(void) {
    if (!s_cluster_running) return;
    uint64_t adv_ms = (uint64_t)(g_config.vrrp_advert_interval_ms > 0 ? g_config.vrrp_advert_interval_ms : 200);
    s_stepdown_until_ms = now_monotonic_ms() + (adv_ms * 8ULL) + 1500ULL;

    if (atomic_load_explicit(&s_vrrp_state, memory_order_relaxed) == VRRP_STATE_MASTER) {
        release_virtual_ip();
        atomic_store_explicit(&s_vrrp_state, VRRP_STATE_BACKUP, memory_order_release);
        atomic_store_explicit(&s_current_master_id, 0, memory_order_relaxed);

        /* Broadcast priority-0 packet so best Backup immediately takes over */
        ClusterWirePacket rel_pkt;
        size_t len = prepare_packet(&rel_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, true, NULL, 0);
        broadcast_cluster_packet(&rel_pkt, len);
        add_log("\033[1;33m[VRRP STEPDOWN]\033[0m Manual failover triggered: Node %08X stepped down to BACKUP", s_node_id);
    }
    wakeup_cluster_thread();
}

void cluster_request_bulk_sync(void) {
    if (!s_cluster_running) return;
    s_bulk_sync_requested = true;
    wakeup_cluster_thread();
}

uint64_t cluster_get_tx_packets(void) {
    return atomic_load_explicit(&s_tx_packets, memory_order_relaxed);
}

uint64_t cluster_get_rx_packets(void) {
    return atomic_load_explicit(&s_rx_packets, memory_order_relaxed);
}

uint64_t cluster_get_synced_sessions_count(void) {
    return atomic_load_explicit(&s_synced_sessions, memory_order_relaxed);
}

uint64_t cluster_get_failover_count(void) {
    return atomic_load_explicit(&s_failover_count, memory_order_relaxed);
}
