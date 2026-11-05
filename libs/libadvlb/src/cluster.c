#define _GNU_SOURCE
#include "advlb/cluster.h"
#include "advlb/session_table.h"
#include "advlb/tcp_repair.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/net_utils.h"
#include "advlb/proxy.h"
#include "advlb/sysnet.h"
#include "advlb/types.h"
#include "advnet/net_core.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <poll.h>
#include <stdatomic.h>
#ifdef __linux__
#include <net/ethernet.h>
#include <netpacket/packet.h>
#endif

#ifndef NO_SSL
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#endif

#define CLUSTER_MAGIC 0x41444C42u /* "ADLB" */
#define CLUSTER_PROTO_VERSION 4 /* v4: variable-length TCP checkpoint with kernel queues */

#define CLUSTER_PKT_VRRP_ADVERT    1
#define CLUSTER_PKT_SESSION_UPSERT 2
#define CLUSTER_PKT_SESSION_DELETE 3
#define CLUSTER_PKT_SYNC_REQ       4
#define CLUSTER_PKT_SYNC_CHUNK     5
#define CLUSTER_PKT_SWITCHOVER     6
#define CLUSTER_PKT_TCP_CHECKPOINT 7

#define CLUSTER_UNIX_FD_MAGIC        0x41444644u /* "ADFD" */
#define CLUSTER_UNIX_OP_UPSERT_FDS   1
#define CLUSTER_UNIX_OP_CLOSE_FDS    2
#define CLUSTER_UNIX_OP_HEARTBEAT_FD 3

typedef struct {
    uint32_t magic;
    uint8_t  op;
    uint8_t  vrid;
    uint8_t  has_client_fd;
    uint8_t  has_backend_fd;
    uint8_t  has_alive_fd;
    uint8_t  reserved[3];
    uint32_t sender_node_id;
    int32_t  backend_idx;
    uint16_t backend_port;
    char     backend_ip[46];
    struct sockaddr_storage client_addr;
    uint64_t bytes_to_client;
    uint16_t req_len;
    char     initial_req[512];
} ClusterUnixFdMsg;

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
    union {
        ClusterSessionWire       sessions[CLUSTER_MAX_BATCH_SESSIONS];
        ClusterTcpCheckpointWire tcp_cp;
    };
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
static bool s_custom_socket_hup = false;
static void broadcast_cluster_packet(const ClusterWirePacket *pkt, size_t total_len);
static size_t prepare_tcp_checkpoint_packet(ClusterWirePacket *pkt, const ClusterTcpCheckpointWire *cp_wire);
static int s_unix_fd = -1;
static char s_unix_path[108] = {0};
static int s_alive_pipe[2] = {-1, -1};
static int s_master_alive_fd = -1;
static int s_wakeup_pipe[2] = {-1, -1};
static pthread_t s_cluster_thread;
static volatile bool s_cluster_running = false;
static bool s_cluster_initialized = false;

static atomic_int s_vrrp_state = VRRP_STATE_DISABLED;
static atomic_bool s_vip_active = false;
static bool s_vip_bound_kernel = false;
static char s_active_vmac[32] = {0};
static char s_active_vip_iface[64] = {0};
static char s_saved_orig_mac[32] = {0};
static char s_iface_primary_ip[64] = {0};
static char s_iface_subnet_cidr[64] = {0};
static char s_iface_default_gw[64] = {0};
static bool s_mac_switched_on_iface = false;
static bool s_vmac_iface_created = false;
static int  s_vip_guard_pipe[2] = {-1, -1};
static uint64_t s_last_garp_sent_ms = 0;
static int  s_garp_burst_remaining = 0;
static uint32_t s_node_id = 0;
static _Atomic uint32_t s_current_master_id = 0;
static uint64_t s_last_master_advert_ms = 0;
static uint8_t s_master_effective_prio = 0;
static uint64_t s_stepdown_until_ms = 0;
static bool s_manual_demoted = false;
static volatile bool s_bulk_sync_requested = false;
static volatile sig_atomic_t s_stepdown_requested = 0;
static volatile bool s_cluster_stopping = false;

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

void cluster_format_vrrp_mac(int vrid, bool is_ipv6, char *out_mac, size_t mac_sz) {
    if (!out_mac || mac_sz == 0) return;
    unsigned int id = (unsigned int)((vrid >= 1 && vrid <= 255) ? vrid : 51);
    snprintf(out_mac, mac_sz, "00:00:5e:00:%02x:%02x", is_ipv6 ? 0x02u : 0x01u, id);
}

bool cluster_parse_mac_bytes(const char *mac_str, uint8_t out_bytes[6]) {
    if (!mac_str || !out_bytes) return false;
    unsigned int b[6];
    char tail = '\0';
    if (sscanf(mac_str, "%2x:%2x:%2x:%2x:%2x:%2x%c",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &tail) != 6) {
        return false;
    }
    for (int i = 0; i < 6; i++) {
        if (b[i] > 0xFFu) return false;
        out_bytes[i] = (uint8_t)b[i];
    }
    return true;
}

size_t cluster_build_garp_frame(const uint8_t vmac[6],
                                const char *vip_ip,
                                bool is_reply,
                                uint8_t out_frame[42]) {
    if (!vmac || !vip_ip || !out_frame) return 0;
    struct in_addr ip4;
    if (inet_pton(AF_INET, vip_ip, &ip4) != 1) {
        return 0;
    }

    memset(out_frame, 0, 42);
    /* Ethernet Header (14 bytes) */
    memset(&out_frame[0], 0xFF, 6);        /* Destination: Broadcast ff:ff:ff:ff:ff:ff */
    memcpy(&out_frame[6], vmac, 6);        /* Source: VRRP Virtual MAC */
    out_frame[12] = 0x08;                  /* EtherType: ARP (0x0806) */
    out_frame[13] = 0x06;

    /* ARP Payload (28 bytes) */
    out_frame[14] = 0x00;                  /* Hardware type: Ethernet (1) */
    out_frame[15] = 0x01;
    out_frame[16] = 0x08;                  /* Protocol type: IPv4 (0x0800) */
    out_frame[17] = 0x00;
    out_frame[18] = 6;                     /* Hardware size: 6 */
    out_frame[19] = 4;                     /* Protocol size: 4 */
    out_frame[20] = 0x00;                  /* Opcode: 1 (GARP Request) or 2 (GARP Reply) */
    out_frame[21] = is_reply ? 0x02 : 0x01;

    memcpy(&out_frame[22], vmac, 6);       /* Sender Hardware Address (SHA): VRRP MAC */
    memcpy(&out_frame[28], &ip4.s_addr, 4);/* Sender Protocol Address (SPA): VIP */
    if (is_reply) {
        memcpy(&out_frame[32], vmac, 6);   /* Target Hardware Address (THA): VRRP MAC */
    } else {
        memset(&out_frame[32], 0xFF, 6);   /* Target Hardware Address (THA): Broadcast */
    }
    memcpy(&out_frame[38], &ip4.s_addr, 4);/* Target Protocol Address (TPA): VIP */

    return 42;
}

const char *cluster_get_active_vmac(void) {
    return s_active_vmac;
}

const char *cluster_get_active_vip_iface(void) {
    return (s_active_vip_iface[0] != '\0') ? s_active_vip_iface : g_config.vip_interface;
}

static void resolve_active_vmac(const char *clean_vip, char *out_mac, size_t mac_sz) {
    uint8_t tmp_bytes[6];
    if (g_config.vrrp_vmac[0] != '\0' && cluster_parse_mac_bytes(g_config.vrrp_vmac, tmp_bytes)) {
        snprintf(out_mac, mac_sz, "%.31s", g_config.vrrp_vmac);
        return;
    }
    bool is_ipv6 = (clean_vip && strchr(clean_vip, ':') != NULL);
    int vrid = (g_config.vrrp_router_id >= 1 && g_config.vrrp_router_id <= 255) ? g_config.vrrp_router_id : 51;
    cluster_format_vrrp_mac(vrid, is_ipv6, out_mac, mac_sz);
}

static bool resolve_vip_interface(const char *clean_vip, char *out_iface, size_t out_sz) {
    if (!out_iface || out_sz == 0) return false;
    out_iface[0] = '\0';

    if (is_safe_iface_name(g_config.vip_interface) &&
        strncmp(g_config.vip_interface, "vrrp", 4) != 0 &&
        if_nametoindex(g_config.vip_interface) != 0) {
        snprintf(out_iface, out_sz, "%.63s", g_config.vip_interface);
        return true;
    }

    /* Do not auto-bind physical NICs for loopback VIPs in unprivileged/unit tests */
    if (g_config.vip_interface[0] == '\0' &&
        clean_vip && (strncmp(clean_vip, "127.", 4) == 0 || strcmp(clean_vip, "::1") == 0)) {
        return false;
    }

    struct in_addr vip_in;
    bool has_vip4 = (clean_vip && inet_pton(AF_INET, clean_vip, &vip_in) == 1);

    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) != 0 || !ifap) {
        return false;
    }

    char fallback_iface[64] = {0};
    char matched_iface[64] = {0};

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr) continue;
        if (!(ifa->ifa_flags & IFF_UP) || (ifa->ifa_flags & IFF_LOOPBACK)) continue;
        if (strncmp(ifa->ifa_name, "vrrp", 4) == 0 ||
            strncmp(ifa->ifa_name, "docker", 6) == 0 ||
            strncmp(ifa->ifa_name, "veth", 4) == 0 ||
            strncmp(ifa->ifa_name, "virbr", 5) == 0) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) {
            if (fallback_iface[0] == '\0') {
                snprintf(fallback_iface, sizeof(fallback_iface), "%.63s", ifa->ifa_name);
            }
            if (has_vip4 && ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET) {
                struct sockaddr_in *sin_addr = (struct sockaddr_in *)ifa->ifa_addr;
                struct sockaddr_in *sin_mask = (struct sockaddr_in *)ifa->ifa_netmask;
                if (sin_mask->sin_addr.s_addr != 0 &&
                    (sin_addr->sin_addr.s_addr & sin_mask->sin_addr.s_addr) ==
                    (vip_in.s_addr & sin_mask->sin_addr.s_addr)) {
                    snprintf(matched_iface, sizeof(matched_iface), "%.63s", ifa->ifa_name);
                    break;
                }
            }
        }
    }
    freeifaddrs(ifap);

    const char *chosen = (matched_iface[0] != '\0') ? matched_iface : fallback_iface;
    if (chosen[0] != '\0' && is_safe_iface_name(chosen)) {
        if (g_config.vip_interface[0] != '\0' && strcmp(g_config.vip_interface, chosen) != 0) {
            add_log("\033[1;33m[VRRP VIP]\033[0m Interface '%s' not found — auto-selected '%s'",
                    g_config.vip_interface, chosen);
        }
        snprintf(g_config.vip_interface, sizeof(g_config.vip_interface), "%.63s", chosen);
        snprintf(out_iface, out_sz, "%.63s", chosen);
        return true;
    }
    return false;
}

static void send_vrrp_garp_on_iface(const char *iface, const char *ip_str, const char *mac_str) {
    if (!iface || iface[0] == '\0' || !ip_str || ip_str[0] == '\0' || !mac_str || mac_str[0] == '\0') {
        return;
    }
#ifdef __linux__
    uint8_t mac_bytes[6];
    if (!cluster_parse_mac_bytes(mac_str, mac_bytes)) return;

    unsigned int if_idx = if_nametoindex(iface);
    if (if_idx == 0) return;

    uint8_t frame_req[42];
    uint8_t frame_rep[42];
    if (cluster_build_garp_frame(mac_bytes, ip_str, false, frame_req) == 42 &&
        cluster_build_garp_frame(mac_bytes, ip_str, true, frame_rep) == 42) {
        int raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (raw_fd >= 0) {
            struct sockaddr_ll sll;
            memset(&sll, 0, sizeof(sll));
            sll.sll_family   = AF_PACKET;
            sll.sll_protocol = htons(ETH_P_ARP);
            sll.sll_ifindex  = (int)if_idx;
            sll.sll_halen    = 6;
            memset(sll.sll_addr, 0xFF, 6);

            ssize_t s1 = sendto(raw_fd, frame_req, sizeof(frame_req), 0,
                                (struct sockaddr *)&sll, sizeof(sll));
            ssize_t s2 = sendto(raw_fd, frame_rep, sizeof(frame_rep), 0,
                                (struct sockaddr *)&sll, sizeof(sll));
            (void)s1;
            (void)s2;
            close(raw_fd);
        }
    }
#endif
}

static void save_original_iface_mac_and_ip(const char *iface, const char *clean_vip) {
    if (!is_safe_iface_name(iface)) return;

    /* Discover primary non-VIP IPv4 address and subnet CIDR of the parent interface */
    struct ifaddrs *ifap = NULL;
    if (getifaddrs(&ifap) == 0 && ifap) {
        for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
            if (!ifa->ifa_name || !ifa->ifa_addr) continue;
            if (strcmp(ifa->ifa_name, iface) != 0) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                char ip_buf[INET_ADDRSTRLEN] = {0};
                struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
                if (inet_ntop(AF_INET, &sin->sin_addr, ip_buf, sizeof(ip_buf))) {
                    if (!clean_vip || strcmp(ip_buf, clean_vip) != 0) {
                        snprintf(s_iface_primary_ip, sizeof(s_iface_primary_ip), "%.63s", ip_buf);
                        if (ifa->ifa_netmask && ifa->ifa_netmask->sa_family == AF_INET) {
                            struct sockaddr_in *smask = (struct sockaddr_in *)ifa->ifa_netmask;
                            uint32_t mask_h = ntohl(smask->sin_addr.s_addr);
                            int pfx = (mask_h != 0) ? __builtin_popcount(mask_h) : 24;
                            struct in_addr net_in;
                            net_in.s_addr = sin->sin_addr.s_addr & smask->sin_addr.s_addr;
                            char net_buf[INET_ADDRSTRLEN] = {0};
                            if (inet_ntop(AF_INET, &net_in, net_buf, sizeof(net_buf))) {
                                snprintf(s_iface_subnet_cidr, sizeof(s_iface_subnet_cidr), "%s/%d", net_buf, pfx);
                            }
                        }
                        break;
                    }
                }
            }
        }
        freeifaddrs(ifap);
    }

#ifdef __linux__
    /* Discover default IPv4 gateway on parent interface from /proc/net/route */
    FILE *rf = fopen("/proc/net/route", "r");
    if (rf) {
        char line[256];
        while (fgets(line, sizeof(line), rf)) {
            char r_iface[64] = {0};
            unsigned int dest_hex = 0, gw_hex = 0, flags_hex = 0;
            if (sscanf(line, "%63s %x %x %x", r_iface, &dest_hex, &gw_hex, &flags_hex) == 4) {
                if (strcmp(r_iface, iface) == 0 && dest_hex == 0 && gw_hex != 0) {
                    struct in_addr gw_in;
                    gw_in.s_addr = (in_addr_t)gw_hex;
                    char gw_buf[INET_ADDRSTRLEN] = {0};
                    if (inet_ntop(AF_INET, &gw_in, gw_buf, sizeof(gw_buf))) {
                        snprintf(s_iface_default_gw, sizeof(s_iface_default_gw), "%.63s", gw_buf);
                        break;
                    }
                }
            }
        }
        fclose(rf);
    }

    char sys_path[128];
    char persist_path[128];
    snprintf(sys_path, sizeof(sys_path), "/sys/class/net/%.31s/address", iface);
    snprintf(persist_path, sizeof(persist_path), "/tmp/adlb_orig_mac_%.31s", iface);

    char cur_mac[32] = {0};
    FILE *fp = fopen(sys_path, "r");
    if (fp) {
        if (fgets(cur_mac, sizeof(cur_mac), fp) != NULL) {
            cur_mac[strcspn(cur_mac, "\r\n ")] = '\0';
        }
        fclose(fp);
    }

    uint8_t parsed[6];
    if (cluster_parse_mac_bytes(cur_mac, parsed)) {
        if (strncasecmp(cur_mac, "00:00:5e:00:", 12) != 0) {
            snprintf(s_saved_orig_mac, sizeof(s_saved_orig_mac), "%.31s", cur_mac);
            FILE *pf = fopen(persist_path, "w");
            if (pf) {
                fprintf(pf, "%s\n", s_saved_orig_mac);
                fclose(pf);
            }
            return;
        }
    }

    /* Current MAC on parent interface is a VRRP MAC from a prior run — recover true hardware MAC */
    if (s_saved_orig_mac[0] == '\0') {
        FILE *pf = fopen(persist_path, "r");
        if (pf) {
            char saved[32] = {0};
            if (fgets(saved, sizeof(saved), pf) != NULL) {
                saved[strcspn(saved, "\r\n ")] = '\0';
                if (cluster_parse_mac_bytes(saved, parsed) &&
                    strncasecmp(saved, "00:00:5e:00:", 12) != 0) {
                    snprintf(s_saved_orig_mac, sizeof(s_saved_orig_mac), "%.31s", saved);
                }
            }
            fclose(pf);
        }
    }

    /* Permanent hardware MAC via ethtool ETHTOOL_GPERMADDR */
    if (s_saved_orig_mac[0] == '\0') {
        uint8_t perm[6];
        char cand[32];
        if (sysnet_link_get_perm_mac(iface, perm)) {
            snprintf(cand, sizeof(cand), "%02x:%02x:%02x:%02x:%02x:%02x",
                     perm[0], perm[1], perm[2], perm[3], perm[4], perm[5]);
            if (strncasecmp(cand, "00:00:5e:00:", 12) != 0) {
                snprintf(s_saved_orig_mac, sizeof(s_saved_orig_mac), "%.31s", cand);
            }
        }
    }

    /* Fallback: deterministic unique locally-administered MAC derived from primary IPv4 */
    if (s_saved_orig_mac[0] == '\0' && s_iface_primary_ip[0] != '\0') {
        struct in_addr p_in;
        if (inet_pton(AF_INET, s_iface_primary_ip, &p_in) == 1) {
            uint32_t h = ntohl(p_in.s_addr);
            snprintf(s_saved_orig_mac, sizeof(s_saved_orig_mac),
                     "02:1c:42:%02x:%02x:%02x",
                     (unsigned int)((h >> 16) & 0xFFu),
                     (unsigned int)((h >> 8) & 0xFFu),
                     (unsigned int)(h & 0xFFu));
        }
    }

    /* Self-heal parent physical interface if it was stuck on a VRRP MAC */
    if (geteuid() == 0 && s_saved_orig_mac[0] != '\0' &&
        strncasecmp(cur_mac, "00:00:5e:00:", 12) == 0) {
        uint8_t orig[6];
        if (cluster_parse_mac_bytes(s_saved_orig_mac, orig)) {
            sysnet_link_set_mac(iface, orig);
        }
        if (s_iface_primary_ip[0] != '\0') {
            send_vrrp_garp_on_iface(iface, s_iface_primary_ip, s_saved_orig_mac);
        }
        add_log("\033[1;33m[VRRP HEAL]\033[0m Restored unique MAC %s on primary interface %s",
                s_saved_orig_mac, iface);
    }
#endif
}

static void broadcast_active_vip_garp(void) {
    if (!atomic_load_explicit(&s_vip_active, memory_order_relaxed) || !s_vip_bound_kernel) return;
    char clean_vip[64] = {0};
    int prefix = 32;
    if (!parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) return;

    const char *act_iface = (s_active_vip_iface[0] != '\0') ? s_active_vip_iface : g_config.vip_interface;
    const char *mac_to_use = (g_config.vrrp_use_vmac && s_active_vmac[0] != '\0') ? s_active_vmac : s_saved_orig_mac;
    if (mac_to_use[0] == '\0') {
        mac_to_use = s_active_vmac;
    }
    if (act_iface[0] != '\0' && mac_to_use[0] != '\0') {
        send_vrrp_garp_on_iface(act_iface, clean_vip, mac_to_use);
        if (strcmp(act_iface, g_config.vip_interface) != 0 && g_config.vip_interface[0] != '\0') {
            send_vrrp_garp_on_iface(g_config.vip_interface, clean_vip, mac_to_use);
        }
    }
}

#ifdef __linux__
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/xt_tcpudp.h>

#ifndef XT_ALIGN
#define XT_ALIGN(s) (((s) + (__alignof__(struct xt_entry_match) - 1)) & ~(__alignof__(struct xt_entry_match) - 1))
#endif
#ifndef NF_INET_LOCAL_OUT
#define NF_INET_LOCAL_OUT 3
#endif
#ifndef IPT_SO_SET_REPLACE
#define IPT_SO_SET_REPLACE 64
#endif
#ifndef IPT_SO_GET_INFO
#define IPT_SO_GET_INFO 64
#endif
#ifndef IPT_SO_GET_ENTRIES
#define IPT_SO_GET_ENTRIES 65
#endif

typedef struct {
    struct ipt_entry entry;
    struct xt_entry_match match;
    struct xt_tcp tcp;
    struct xt_standard_target target;
} VrrpRstDropRule;

/* Matches any output interface: with macvlan the VIP egresses via vrrp<VRID>, not the parent NIC,
 * so an outiface-bound rule let the kernel RSTs of not-yet-restored streams escape. */
static void build_vrrp_rst_drop_rule(VrrpRstDropRule *r, const char *vip) {
    memset(r, 0, sizeof(*r));

    r->entry.ip.proto = IPPROTO_TCP;
    inet_pton(AF_INET, vip, &r->entry.ip.src);
    r->entry.ip.smsk.s_addr = 0xFFFFFFFFu;

    uint16_t match_size = (uint16_t)XT_ALIGN(sizeof(struct xt_entry_match) + sizeof(struct xt_tcp));
    uint16_t target_size = (uint16_t)XT_ALIGN(sizeof(struct xt_standard_target));

    r->entry.target_offset = (uint16_t)sizeof(struct ipt_entry) + match_size;
    r->entry.next_offset = r->entry.target_offset + target_size;

    r->match.u.user.match_size = match_size;
    snprintf(r->match.u.user.name, XT_EXTENSION_MAXNAMELEN, "tcp");
    /* Port ranges are inclusive [min, max]: left at 0 the rule would only match port 0 */
    r->tcp.spts[0] = 0;
    r->tcp.spts[1] = 0xFFFF;
    r->tcp.dpts[0] = 0;
    r->tcp.dpts[1] = 0xFFFF;
    r->tcp.flg_mask = 0x04; /* TH_RST */
    r->tcp.flg_cmp  = 0x04; /* TH_RST */

    r->target.target.u.user.target_size = target_size;
    snprintf(r->target.target.u.user.name, XT_EXTENSION_MAXNAMELEN, "%s", "");
    r->target.verdict = -1; /* -NF_DROP - 1 */
}

static bool is_matching_rst_drop_rule(const struct ipt_entry *e, const char *vip) {
    if (e->ip.proto != IPPROTO_TCP) return false;
    struct in_addr vip_in;
    if (inet_pton(AF_INET, vip, &vip_in) != 1) return false;
    if (e->ip.src.s_addr != vip_in.s_addr) return false;
    return e->ip.outiface[0] == '\0';
}

static void install_vip_rst_filter(const char *parent_iface, const char *vip) {
    if (geteuid() != 0 || !parent_iface || !vip || parent_iface[0] == '\0' || vip[0] == '\0') return;

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return;

    struct ipt_getinfo info;
    memset(&info, 0, sizeof(info));
    snprintf(info.name, sizeof(info.name), "filter");
    socklen_t in_len = sizeof(info);
    if (getsockopt(s, IPPROTO_IP, IPT_SO_GET_INFO, &info, &in_len) < 0) {
        add_log("\033[1;33m[HA RST FILTER]\033[0m IPT_SO_GET_INFO error: %s (errno %d)", strerror(errno), errno);
        close(s);
        return;
    }

    size_t get_size = sizeof(struct ipt_get_entries) + info.size;
    struct ipt_get_entries *entries = malloc(get_size);
    if (!entries) {
        close(s);
        return;
    }
    memset(entries, 0, get_size);
    snprintf(entries->name, sizeof(entries->name), "filter");
    entries->size = info.size;
    socklen_t ent_len = (socklen_t)get_size;
    if (getsockopt(s, IPPROTO_IP, IPT_SO_GET_ENTRIES, entries, &ent_len) < 0) {
        free(entries);
        close(s);
        return;
    }

    size_t offset = 0;
    while (offset < info.size) {
        struct ipt_entry *e = (struct ipt_entry *)((char *)entries->entrytable + offset);
        if (is_matching_rst_drop_rule(e, vip)) {
            free(entries);
            close(s);
            return;
        }
        if (e->next_offset == 0) break;
        offset += e->next_offset;
    }

    VrrpRstDropRule rule;
    build_vrrp_rst_drop_rule(&rule, vip);
    size_t rule_size = sizeof(rule);

    unsigned int ins_off = info.hook_entry[NF_INET_LOCAL_OUT];
    if (ins_off > info.size) ins_off = info.size;

    size_t new_size = info.size + rule_size;
    struct ipt_replace *repl = calloc(1, sizeof(struct ipt_replace) + new_size);
    if (!repl) {
        free(entries);
        close(s);
        return;
    }

    snprintf(repl->name, sizeof(repl->name), "filter");
    repl->valid_hooks = info.valid_hooks;
    repl->num_entries = info.num_entries + 1;
    repl->size = (unsigned int)new_size;

    for (int h = 0; h < NF_INET_NUMHOOKS; h++) {
        repl->hook_entry[h] = info.hook_entry[h];
        repl->underflow[h] = info.underflow[h];
        if (h > NF_INET_LOCAL_OUT && repl->hook_entry[h] >= ins_off) {
            repl->hook_entry[h] += (unsigned int)rule_size;
        }
        if (h >= NF_INET_LOCAL_OUT && repl->underflow[h] >= ins_off) {
            repl->underflow[h] += (unsigned int)rule_size;
        }
    }

    char *dst = (char *)repl->entries;
    memcpy(dst, entries->entrytable, ins_off);
    memcpy(dst + ins_off, &rule, rule_size);
    memcpy(dst + ins_off + rule_size, (char *)entries->entrytable + ins_off, info.size - ins_off);

    /* The kernel returns the old table counters here and rejects num_counters == 0 with EINVAL */
    struct xt_counters *old_counters = calloc(info.num_entries ? info.num_entries : 1, sizeof(struct xt_counters));
    repl->num_counters = info.num_entries;
    repl->counters = old_counters;
    if (!old_counters ||
        setsockopt(s, IPPROTO_IP, IPT_SO_SET_REPLACE, repl, (socklen_t)(sizeof(struct ipt_replace) + new_size)) < 0) {
        add_log("\033[1;33m[HA RST FILTER]\033[0m IPT_SO_SET_REPLACE error: %s (errno %d)", strerror(errno), errno);
    } else {
        add_log("\033[1;32m[HA RST FILTER]\033[0m Injected kernel Netfilter RST drop rule (any iface, parent %s) for %s", parent_iface, vip);
    }

    free(old_counters);
    free(repl);
    free(entries);
    close(s);
}

static void remove_vip_rst_filter(const char *parent_iface, const char *vip) {
    if (geteuid() != 0 || !parent_iface || !vip || parent_iface[0] == '\0' || vip[0] == '\0') return;

    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0) return;

    struct ipt_getinfo info;
    memset(&info, 0, sizeof(info));
    snprintf(info.name, sizeof(info.name), "filter");
    socklen_t in_len = sizeof(info);
    if (getsockopt(s, IPPROTO_IP, IPT_SO_GET_INFO, &info, &in_len) < 0) {
        add_log("\033[1;33m[HA RST FILTER]\033[0m IPT_SO_GET_INFO error: %s (errno %d)", strerror(errno), errno);
        close(s);
        return;
    }

    size_t get_size = sizeof(struct ipt_get_entries) + info.size;
    struct ipt_get_entries *entries = malloc(get_size);
    if (!entries) {
        close(s);
        return;
    }
    memset(entries, 0, get_size);
    snprintf(entries->name, sizeof(entries->name), "filter");
    entries->size = info.size;
    socklen_t ent_len = (socklen_t)get_size;
    if (getsockopt(s, IPPROTO_IP, IPT_SO_GET_ENTRIES, entries, &ent_len) < 0) {
        free(entries);
        close(s);
        return;
    }

    size_t offset = 0;
    size_t rem_off = 0;
    size_t rem_size = 0;
    bool found = false;
    while (offset < info.size) {
        struct ipt_entry *e = (struct ipt_entry *)((char *)entries->entrytable + offset);
        if (!found && is_matching_rst_drop_rule(e, vip)) {
            found = true;
            rem_off = offset;
            rem_size = e->next_offset;
        }
        if (e->next_offset == 0) break;
        offset += e->next_offset;
    }

    if (!found || rem_size == 0) {
        free(entries);
        close(s);
        return;
    }

    size_t new_size = info.size - rem_size;
    struct ipt_replace *repl = calloc(1, sizeof(struct ipt_replace) + new_size);
    if (!repl) {
        free(entries);
        close(s);
        return;
    }

    snprintf(repl->name, sizeof(repl->name), "filter");
    repl->valid_hooks = info.valid_hooks;
    repl->num_entries = info.num_entries - 1;
    repl->size = (unsigned int)new_size;

    for (int h = 0; h < NF_INET_NUMHOOKS; h++) {
        repl->hook_entry[h] = info.hook_entry[h];
        repl->underflow[h] = info.underflow[h];
        if (h > NF_INET_LOCAL_OUT && repl->hook_entry[h] > rem_off) {
            repl->hook_entry[h] -= (unsigned int)rem_size;
        }
        if (h >= NF_INET_LOCAL_OUT && repl->underflow[h] > rem_off) {
            repl->underflow[h] -= (unsigned int)rem_size;
        }
    }

    char *dst = (char *)repl->entries;
    memcpy(dst, entries->entrytable, rem_off);
    memcpy(dst + rem_off, (char *)entries->entrytable + rem_off + rem_size, info.size - (rem_off + rem_size));

    /* The kernel returns the old table counters here and rejects num_counters == 0 with EINVAL */
    struct xt_counters *old_counters = calloc(info.num_entries ? info.num_entries : 1, sizeof(struct xt_counters));
    repl->num_counters = info.num_entries;
    repl->counters = old_counters;
    if (!old_counters ||
        setsockopt(s, IPPROTO_IP, IPT_SO_SET_REPLACE, repl, (socklen_t)(sizeof(struct ipt_replace) + new_size)) < 0) {
        add_log("\033[1;33m[HA RST FILTER]\033[0m IPT_SO_SET_REPLACE error: %s (errno %d)", strerror(errno), errno);
    } else {
        add_log("\033[1;32m[HA RST FILTER]\033[0m Removed kernel Netfilter RST drop rule (%s) for %s", parent_iface, vip);
    }

    free(old_counters);
    free(repl);
    free(entries);
    close(s);
}
#else
static __attribute__((unused)) void install_vip_rst_filter(const char *parent_iface, const char *vip) {
    (void)parent_iface;
    (void)vip;
}
static __attribute__((unused)) void remove_vip_rst_filter(const char *parent_iface, const char *vip) {
    (void)parent_iface;
    (void)vip;
}
#endif

/* RST suppression only covers the takeover window (restore + late checkpoints). Afterwards a
 * stream we could not restore must get its RST, so the client reconnects at once instead of
 * hanging until its own timeout. Outside MASTER the blackhole rule already stops VIP egress. */
#define CLUSTER_RST_FILTER_GRACE_MS 3000ULL
static atomic_bool s_rst_filter_active = false;
static _Atomic uint64_t s_rst_filter_until_ms = 0;

static __attribute__((unused)) void rst_filter_arm(const char *iface, const char *vip) {
    atomic_store(&s_rst_filter_until_ms, now_monotonic_ms() + CLUSTER_RST_FILTER_GRACE_MS);
    if (!atomic_exchange(&s_rst_filter_active, true)) {
        install_vip_rst_filter(iface, vip);
    }
}

static void rst_filter_extend(void) {
    if (atomic_load(&s_rst_filter_active)) {
        atomic_store(&s_rst_filter_until_ms, now_monotonic_ms() + CLUSTER_RST_FILTER_GRACE_MS);
    }
}

static void rst_filter_disarm(void) {
    if (!atomic_exchange(&s_rst_filter_active, false)) return;
    char clean_vip[64] = {0};
    int prefix = 32;
    if (parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) {
        remove_vip_rst_filter(g_config.vip_interface, clean_vip);
    }
}

static void disarm_vip_cleanup_guard(void) {
    if (s_vip_guard_pipe[1] >= 0) {
        char q = 'Q';
        ssize_t w = write(s_vip_guard_pipe[1], &q, 1);
        (void)w;
        close(s_vip_guard_pipe[1]);
        s_vip_guard_pipe[1] = -1;
    }
    if (s_vip_guard_pipe[0] >= 0) {
        close(s_vip_guard_pipe[0]);
        s_vip_guard_pipe[0] = -1;
    }
}

static void spawn_vip_cleanup_guard(const char *clean_vip,
                                    int prefix,
                                    const char *parent_iface,
                                    const char *active_iface,
                                    bool vmac_iface_created,
                                    bool mac_switched,
                                    const char *orig_mac,
                                    const char *primary_ip) {
    disarm_vip_cleanup_guard();
    if (geteuid() != 0 || !parent_iface || parent_iface[0] == '\0') return;

    int vrid = (g_config.vrrp_router_id >= 1 && g_config.vrrp_router_id <= 255) ? g_config.vrrp_router_id : 51;
    int rtable = 100 + vrid;
    char pid_path[128];
    snprintf(pid_path, sizeof(pid_path), "/tmp/adlb_master_vrid_%d.pid", vrid);
    pid_t master_pid = getpid();
    FILE *pf = fopen(pid_path, "w");
    if (pf) {
        fprintf(pf, "%d\n", (int)master_pid);
        fclose(pf);
    }

    if (pipe(s_vip_guard_pipe) != 0) {
        s_vip_guard_pipe[0] = s_vip_guard_pipe[1] = -1;
        return;
    }

    pid_t pid1 = fork();
    if (pid1 < 0) {
        close(s_vip_guard_pipe[0]);
        close(s_vip_guard_pipe[1]);
        s_vip_guard_pipe[0] = s_vip_guard_pipe[1] = -1;
        return;
    }

    if (pid1 == 0) {
        /* Intermediate child: double-fork so the guard is reparented to init (no zombies) */
        pid_t pid2 = fork();
        if (pid2 != 0) {
            _exit(0);
        }

        int read_fd = s_vip_guard_pipe[0];
        long max_fd = sysconf(_SC_OPEN_MAX);
        if (max_fd < 256 || max_fd > 65536) max_fd = 4096;
        for (int fd = 3; fd < (int)max_fd; fd++) {
            if (fd != read_fd) close(fd);
        }

        char cmd_byte = 0;
        ssize_t n = read(read_fd, &cmd_byte, 1);
        close(read_fd);

        /* If parent wrote 'Q', it is performing a graceful release_virtual_ip() itself */
        if (n == 1 && cmd_byte == 'Q') {
            _exit(0);
        }

        /* Parent died abruptly (e.g. SIGKILL / kill -9). Verify no newer Master on same host took over */
        FILE *check_pf = fopen(pid_path, "r");
        if (check_pf) {
            int recorded_pid = 0;
            if (fscanf(check_pf, "%d", &recorded_pid) == 1 &&
                recorded_pid != (int)master_pid && recorded_pid > 0 &&
                kill((pid_t)recorded_pid, 0) == 0) {
                fclose(check_pf);
                _exit(0);
            }
            fclose(check_pf);
        }
        unlink(pid_path);

        /* Native calls only: the guard runs no external tools */
        (void)mac_switched;
        (void)orig_mac;
        (void)primary_ip;
        int host_pfx = strchr(clean_vip, ':') ? 128 : 32;
#ifdef __APPLE__
        (void)active_iface;
        (void)vmac_iface_created;
        (void)rtable;
        (void)prefix;
        sysnet_addr_del(parent_iface, clean_vip, host_pfx);
        sysnet_arp_delete(clean_vip);
#else
        if (vmac_iface_created && active_iface && active_iface[0] != '\0') {
            /* Deleting the link also drops its addresses and every table route through it */
            sysnet_rule_del(clean_vip, rtable);
            sysnet_link_del(active_iface);
        } else {
            sysnet_addr_del(parent_iface, clean_vip, host_pfx);
            sysnet_addr_del(parent_iface, clean_vip, prefix);
        }
#endif
        _exit(0);
    }

    /* Parent: reap intermediate child immediately and keep s_vip_guard_pipe[1] open */
    close(s_vip_guard_pipe[0]);
    s_vip_guard_pipe[0] = -1;
    int status = 0;
    waitpid(pid1, &status, 0);
}

#ifdef __linux__
static void set_iface_sysctl(const char *iface, const char *key, const char *val) {
    char path[128];
    snprintf(path, sizeof(path), "net/ipv4/conf/%.31s/%s", iface, key);
    sysnet_sysctl_set(path, val);
}

/* Loose RPF + strict ARP so only the vrrp interface answers for the VIP */
static void set_vip_sysctls(const char *parent_iface, const char *vip_iface) {
    const char *ifaces[] = { "all", parent_iface, vip_iface };
    for (size_t i = 0; i < sizeof(ifaces) / sizeof(ifaces[0]); i++) {
        set_iface_sysctl(ifaces[i], "rp_filter", "0");
        set_iface_sysctl(ifaces[i], "arp_ignore", "1");
        set_iface_sysctl(ifaces[i], "arp_announce", "2");
    }
    set_iface_sysctl(vip_iface, "arp_filter", "0");
    set_iface_sysctl(vip_iface, "accept_local", "1");
    sysnet_sysctl_set("net/netfilter/nf_conntrack_tcp_be_liberal", "1");
}
#endif

/* Policy blackhole so a non-owner node never egresses VIP-sourced packets (also freezes the
 * TCP state of streams being checkpointed: their ACKs cannot leave the old node) */
static void add_vip_blackhole_rule(void) {
#ifdef __linux__
    char clean_vip[64] = {0};
    int prefix = 32;
    if (parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) {
        sysnet_rule_add(clean_vip, 50, 0);
    }
#endif
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

    if (g_config.vrrp_use_vmac) {
        resolve_active_vmac(clean_vip, s_active_vmac, sizeof(s_active_vmac));
    } else {
        s_active_vmac[0] = '\0';
    }
    s_mac_switched_on_iface = false;
    s_vmac_iface_created = false;

    char iface[64] = {0};
    if (geteuid() == 0 && resolve_vip_interface(clean_vip, iface, sizeof(iface))) {
        save_original_iface_mac_and_ip(iface, clean_vip);
        snprintf(s_active_vip_iface, sizeof(s_active_vip_iface), "%.63s", iface);

        int host_pfx = strchr(clean_vip, ':') ? 128 : 32;
#ifdef __APPLE__
        (void)s_iface_subnet_cidr;
        (void)s_iface_default_gw;
        (void)host_pfx;
        s_vip_bound_kernel = (sysnet_addr_add(iface, clean_vip, 32, NULL) == 0);
        uint8_t pub_mac[6];
        if (s_vip_bound_kernel && g_config.vrrp_use_vmac && cluster_parse_mac_bytes(s_active_vmac, pub_mac)) {
            sysnet_arp_publish(clean_vip, iface, pub_mac);
        }
#else
        /* Drop kernel RSTs from the VIP before it becomes reachable: until the checkpointed
         * streams are restored, client segments would otherwise be answered with RST */
        rst_filter_arm(iface, clean_vip);

        if (strncmp(iface, "lo", 2) != 0) {
            /* Create a dedicated VRRP macvlan virtual interface (vrrp<VRID>) separate from the main interface */
            int vrid = (g_config.vrrp_router_id >= 1 && g_config.vrrp_router_id <= 255) ? g_config.vrrp_router_id : 51;
            int rtable = 100 + vrid;
            snprintf(s_active_vip_iface, sizeof(s_active_vip_iface), "vrrp%d", vrid);

            sysnet_rule_del(clean_vip, 0);
            sysnet_rule_del(clean_vip, rtable);
            sysnet_route_flush_table(rtable);
            sysnet_link_del(s_active_vip_iface);
            sysnet_addr_del(iface, clean_vip, prefix);
            sysnet_addr_del(iface, clean_vip, host_pfx);

            uint8_t vmac[6];
            const uint8_t *mac = (g_config.vrrp_use_vmac && cluster_parse_mac_bytes(s_active_vmac, vmac)) ? vmac : NULL;
            int lrc = sysnet_link_add_macvlan(iface, s_active_vip_iface, mac);
            int arc = (lrc == 0) ? sysnet_addr_add(s_active_vip_iface, clean_vip, host_pfx, NULL) : lrc;

            if (arc == 0) {
                s_vmac_iface_created = true;
                s_vip_bound_kernel = true;

                sysnet_link_set_promisc(iface, false);
                set_vip_sysctls(iface, s_active_vip_iface);

                /* Policy routing so VIP responses egress via vrrp<VRID> while node traffic uses parent iface */
                if (s_iface_subnet_cidr[0] != '\0') {
                    sysnet_route_replace(rtable, s_iface_subnet_cidr, NULL, s_active_vip_iface, clean_vip);
                }
                if (s_iface_default_gw[0] != '\0') {
                    sysnet_route_replace(rtable, NULL, s_iface_default_gw, s_active_vip_iface, clean_vip);
                }
                if (s_iface_subnet_cidr[0] != '\0' || s_iface_default_gw[0] != '\0') {
                    sysnet_rule_add(clean_vip, 100, rtable);
                }
            } else {
                add_log("\033[1;33m[VRRP VIP]\033[0m macvlan %s on %s unavailable (%s) — falling back to labeled alias",
                        s_active_vip_iface, iface, strerror(-arc));
                if (lrc == 0) sysnet_link_del(s_active_vip_iface);
                /* Fallback if macvlan is unavailable: labeled IP alias without altering parent MAC */
                char label[32]; /* sysnet truncates to IFNAMSIZ */
                snprintf(label, sizeof(label), "%.10s:vrrp%d", iface, vrid);
                snprintf(s_active_vip_iface, sizeof(s_active_vip_iface), "%.63s", iface);
                s_vip_bound_kernel = (sysnet_addr_add(iface, clean_vip, host_pfx, label) == 0);
            }
        } else {
            sysnet_rule_del(clean_vip, 0);
            s_vip_bound_kernel = (sysnet_addr_add(iface, clean_vip, prefix, NULL) == 0);
        }

        if (s_vip_bound_kernel) {
            /* Raw-socket GARP request+reply now, then a 250ms-spaced burst from the cluster loop */
            broadcast_active_vip_garp();
            s_last_garp_sent_ms = now_monotonic_ms();
            s_garp_burst_remaining = 3;
        }
#endif

        if (s_vip_bound_kernel) {
            spawn_vip_cleanup_guard(clean_vip, prefix, iface, s_active_vip_iface,
                                    s_vmac_iface_created, s_mac_switched_on_iface,
                                    s_saved_orig_mac, s_iface_primary_ip);
            if (g_config.vrrp_use_vmac) {
                add_log("\033[1;32m[VRRP VIP]\033[0m Bound VIP %s/32 on virtual interface %s (parent %s, VMAC %s) + GARP",
                        clean_vip, s_active_vip_iface, iface, s_active_vmac);
            } else {
                add_log("\033[1;32m[VRRP VIP]\033[0m Bound VIP %s/32 on virtual interface %s (parent %s) + GARP",
                        clean_vip, s_active_vip_iface, iface);
            }
        } else {
            add_log("\033[1;31m[VRRP VIP ERROR]\033[0m Failed to bind VIP %s/%d on interface %s",
                    clean_vip, prefix, iface);
        }
    } else {
        int vrid = (g_config.vrrp_router_id >= 1 && g_config.vrrp_router_id <= 255) ? g_config.vrrp_router_id : 51;
        snprintf(s_active_vip_iface, sizeof(s_active_vip_iface), "vrrp%d", vrid);
        s_vip_bound_kernel = false;
        add_log("\033[1;32m[VRRP VIP]\033[0m Virtual IP %s on %s (VMAC %s) ACTIVE on MASTER Node %08X (user-space mode)",
                clean_vip, s_active_vip_iface, s_active_vmac, s_node_id);
    }
}

static void release_virtual_ip(void) {
    if (!atomic_load_explicit(&s_vip_active, memory_order_relaxed)) return;
    atomic_store_explicit(&s_vip_active, false, memory_order_release);
    s_garp_burst_remaining = 0;

    char prev_active_iface[64];
    snprintf(prev_active_iface, sizeof(prev_active_iface), "%.63s", s_active_vip_iface);
    s_active_vmac[0] = '\0';
    s_active_vip_iface[0] = '\0';

    disarm_vip_cleanup_guard();

    int vrid = (g_config.vrrp_router_id >= 1 && g_config.vrrp_router_id <= 255) ? g_config.vrrp_router_id : 51;
    int rtable = 100 + vrid;
    char pid_path[128];
    snprintf(pid_path, sizeof(pid_path), "/tmp/adlb_master_vrid_%d.pid", vrid);
    FILE *pf = fopen(pid_path, "r");
    if (pf) {
        int rec_pid = 0;
        if (fscanf(pf, "%d", &rec_pid) == 1 && rec_pid == (int)getpid()) {
            fclose(pf);
            unlink(pid_path);
        } else {
            fclose(pf);
        }
    }

    char clean_vip[64] = {0};
    int prefix = 32;
    if (!parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) {
        return;
    }

    /* Add blackhole rule so BACKUP node never egresses stray packets with VIP as source */
    add_vip_blackhole_rule();

    if (s_vip_bound_kernel && is_safe_iface_name(g_config.vip_interface) && geteuid() == 0) {
        int host_pfx = strchr(clean_vip, ':') ? 128 : 32;
#ifdef __APPLE__
        (void)prev_active_iface;
        (void)rtable;
        (void)prefix;
        sysnet_addr_del(g_config.vip_interface, clean_vip, host_pfx);
        sysnet_arp_delete(clean_vip);
#else
        sysnet_link_set_promisc(g_config.vip_interface, false);
        if (s_vmac_iface_created && is_safe_iface_name(prev_active_iface)) {
            sysnet_rule_del(clean_vip, rtable);
            sysnet_link_del(prev_active_iface);
            sysnet_route_flush_table(rtable);
            s_vmac_iface_created = false;
        } else {
            sysnet_addr_del(g_config.vip_interface, clean_vip, host_pfx);
            sysnet_addr_del(g_config.vip_interface, clean_vip, prefix);
        }
        rst_filter_disarm();
#endif
        s_vip_bound_kernel = false;
    }

    add_log("\033[1;33m[VRRP VIP]\033[0m Released Virtual IP %s (removed virtual interface %s) from Node %08X",
            clean_vip, (prev_active_iface[0] != '\0') ? prev_active_iface : "vrrp", s_node_id);
}

static uint8_t compute_effective_priority(void) {
    int base = g_config.vrrp_priority;
    if (base < 1) base = 1;
    if (base > 254) base = 254;

    uint64_t now_ms = now_monotonic_ms();
    if (s_stepdown_until_ms > now_ms) {
        return 1;
    }

    if (s_manual_demoted) {
        bool peer_alive = false;
        bool locked = (pthread_mutex_trylock(&s_cluster_mutex) == 0);
        for (int i = 0; i < s_num_peers; i++) {
            if (s_peers[i].is_reachable) {
                peer_alive = true;
                break;
            }
        }
        if (locked) pthread_mutex_unlock(&s_cluster_mutex);

        if (peer_alive || s_is_custom_socket) {
            return 1;
        }
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
            snprintf(p->ip, sizeof(p->ip), "%.63s", host);
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

static void build_unix_sock_path(char *out_path, size_t out_sz, int vrid, int port) {
    if (vrid <= 0) vrid = 51;
    if (port <= 0) port = DEFAULT_CLUSTER_PORT;
    snprintf(out_path, out_sz, "/tmp/adlb_ha_fd_%d_%d.sock", vrid, port);
}

static ssize_t send_unix_fd_msg_to_peer_port(int peer_port,
                                             const ClusterUnixFdMsg *fd_msg,
                                             const int *fds,
                                             int nfds) {
    if (s_unix_fd < 0 || !fd_msg || peer_port <= 0) return -1;
    int vrid = (g_config.vrrp_router_id > 0) ? g_config.vrrp_router_id : 51;

    struct sockaddr_un dst;
    memset(&dst, 0, sizeof(dst));
    dst.sun_family = AF_UNIX;
    build_unix_sock_path(dst.sun_path, sizeof(dst.sun_path), vrid, peer_port);

    struct iovec iov;
    iov.iov_base = (void *)fd_msg;
    iov.iov_len = sizeof(*fd_msg);

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = &dst;
    msg.msg_namelen = sizeof(dst);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int) * 3)];
    } cmsg_un;

    if (nfds > 0 && nfds <= 3 && fds != NULL) {
        memset(&cmsg_un, 0, sizeof(cmsg_un));
        msg.msg_control = cmsg_un.control;
        msg.msg_controllen = (socklen_t)CMSG_SPACE(sizeof(int) * (size_t)nfds);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * (size_t)nfds);
        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * (size_t)nfds);
    }

    return sendmsg(s_unix_fd, &msg, MSG_DONTWAIT);
}

static void send_unix_fd_msg_on_connected_sock(int sock_fd,
                                               const ClusterUnixFdMsg *fd_msg,
                                               const int *fds,
                                               int nfds) {
    if (sock_fd < 0 || !fd_msg) return;

    struct iovec iov;
    iov.iov_base = (void *)fd_msg;
    iov.iov_len = sizeof(*fd_msg);

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    union {
        struct cmsghdr cm;
        char control[CMSG_SPACE(sizeof(int) * 3)];
    } cmsg_un;

    if (nfds > 0 && nfds <= 3 && fds != NULL) {
        memset(&cmsg_un, 0, sizeof(cmsg_un));
        msg.msg_control = cmsg_un.control;
        msg.msg_controllen = (socklen_t)CMSG_SPACE(sizeof(int) * (size_t)nfds);

        struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = (socklen_t)CMSG_LEN(sizeof(int) * (size_t)nfds);
        memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * (size_t)nfds);
    }

    (void)sendmsg(sock_fd, &msg, MSG_DONTWAIT);
}

static void broadcast_unix_fd_msg(const ClusterUnixFdMsg *fd_msg, const int *fds, int nfds) {
    if (!fd_msg) return;

    if (s_is_custom_socket && s_cluster_fd >= 0) {
        send_unix_fd_msg_on_connected_sock(s_cluster_fd, fd_msg, fds, nfds);
        return;
    }

    if (s_unix_fd < 0) return;
    int peer_ports[MAX_CLUSTER_PEERS];
    int count = 0;

    pthread_mutex_lock(&s_cluster_mutex);
    for (int i = 0; i < s_num_peers && count < MAX_CLUSTER_PEERS; i++) {
        if (s_peers[i].port > 0) {
            peer_ports[count++] = s_peers[i].port;
        }
    }
    pthread_mutex_unlock(&s_cluster_mutex);

    for (int i = 0; i < count; i++) {
        (void)send_unix_fd_msg_to_peer_port(peer_ports[i], fd_msg, fds, nfds);
    }
}

static void send_unix_heartbeat_fd_to_peers(void) {
    if (s_alive_pipe[0] < 0) return;
    ClusterUnixFdMsg m;
    memset(&m, 0, sizeof(m));
    m.magic = htonl(CLUSTER_UNIX_FD_MAGIC);
    m.op = CLUSTER_UNIX_OP_HEARTBEAT_FD;
    m.vrid = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
    m.has_alive_fd = 1;
    m.sender_node_id = htonl(s_node_id);

    int fds[1] = { s_alive_pipe[0] };
    broadcast_unix_fd_msg(&m, fds, 1);
}

/* ------------------------------------------------------------------------------------------ */
/* Reliable TCP checkpoint channel                                                            */
/* Full stream migrations (client + backend sockets, kernel queues, proxy buffers) can reach  */
/* ~200 KB: too big and too loss-sensitive for UDP. Each node listens on TCP cluster_port and */
/* keeps one outbound connection per peer. Frames are length-prefixed and HMAC-authenticated. */
/* ------------------------------------------------------------------------------------------ */
#define CLUSTER_STREAM_MAGIC          0x41444D47u /* "ADMG" */
#define CLUSTER_STREAM_TYPE_MIGRATION 1
#define CLUSTER_STREAM_MAX_PAYLOAD    (512u * 1024u)
#define CLUSTER_STREAM_SEND_TIMEOUT_MS 500
#define MAX_INBOUND_STREAMS           (MAX_CLUSTER_PEERS * 2)

typedef struct __attribute__((packed)) {
    uint32_t magic;
    uint8_t  version;
    uint8_t  type;
    uint8_t  vrid;
    uint8_t  sender_state;
    uint32_t sender_node_id;
    uint64_t timestamp_ms;
    uint32_t payload_len;
    uint8_t  hmac[CLUSTER_HMAC_LEN];
} ClusterStreamFrameHdr;

typedef struct __attribute__((packed)) {
    uint8_t  flags;              /* MIGRATED_F_* */
    uint8_t  has_backend;
    uint16_t reserved;
    uint64_t bytes_to_backend;   /* Network byte order */
    uint64_t bytes_from_backend;
    uint64_t skip_backend_bytes;
    uint32_t client_cp_len;
    uint32_t backend_cp_len;
    uint32_t c2b_len;
    uint32_t b2c_len;
} ClusterStreamMigrationHdr;

typedef struct {
    pthread_mutex_t mu;
    int fd;
    bool connected;
    uint64_t next_retry_ms;
} PeerStreamLink;

typedef struct {
    int fd;
    uint8_t *buf;
    size_t len;
    size_t cap;
} InboundStream;

static PeerStreamLink s_links[MAX_CLUSTER_PEERS];
static InboundStream s_inbound[MAX_INBOUND_STREAMS];
static int s_stream_listen_fd = -1;
static bool s_stream_initialized = false;

static void stream_channel_init_state(void) {
    if (s_stream_initialized) return;
    for (int i = 0; i < MAX_CLUSTER_PEERS; i++) {
        pthread_mutex_init(&s_links[i].mu, NULL);
        s_links[i].fd = -1;
        s_links[i].connected = false;
        s_links[i].next_retry_ms = 0;
    }
    for (int i = 0; i < MAX_INBOUND_STREAMS; i++) {
        s_inbound[i].fd = -1;
    }
    s_stream_initialized = true;
}

static void stream_link_close_locked(PeerStreamLink *l, uint64_t now_ms) {
    if (l->fd >= 0) close(l->fd);
    l->fd = -1;
    l->connected = false;
    l->next_retry_ms = now_ms + 1000;
}

static void stream_inbound_close(InboundStream *in) {
    if (in->fd >= 0) close(in->fd);
    free(in->buf);
    in->fd = -1;
    in->buf = NULL;
    in->len = in->cap = 0;
}

static bool stream_channel_open(const char *bind_ip, int port) {
    stream_channel_init_state();
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    net_set_reuse(fd, 1, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, bind_ip, &a.sin_addr) != 1) a.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 16) < 0) {
        add_log("\033[1;31m[HA STREAM]\033[0m TCP checkpoint channel bind %s:%d failed: %s", bind_ip, port, strerror(errno));
        close(fd);
        return false;
    }
    net_set_nonblocking(fd);
    s_stream_listen_fd = fd;
    return true;
}

static void stream_channel_close(void) {
    if (!s_stream_initialized) return;
    if (s_stream_listen_fd >= 0) {
        close(s_stream_listen_fd);
        s_stream_listen_fd = -1;
    }
    for (int i = 0; i < MAX_CLUSTER_PEERS; i++) {
        pthread_mutex_lock(&s_links[i].mu);
        stream_link_close_locked(&s_links[i], 0);
        s_links[i].next_retry_ms = 0;
        pthread_mutex_unlock(&s_links[i].mu);
    }
    for (int i = 0; i < MAX_INBOUND_STREAMS; i++) {
        stream_inbound_close(&s_inbound[i]);
    }
}

/* Start nonblocking connects to peers without an outbound link (cluster thread) */
static void stream_links_maintain(uint64_t now_ms) {
    if (s_stream_listen_fd < 0) return;
    pthread_mutex_lock(&s_cluster_mutex);
    int n = s_num_peers;
    struct sockaddr_storage addrs[MAX_CLUSTER_PEERS];
    socklen_t lens[MAX_CLUSTER_PEERS];
    for (int i = 0; i < n; i++) {
        addrs[i] = s_peers[i].addr;
        lens[i] = s_peers[i].addr_len;
    }
    pthread_mutex_unlock(&s_cluster_mutex);

    for (int i = 0; i < n; i++) {
        PeerStreamLink *l = &s_links[i];
        pthread_mutex_lock(&l->mu);
        if (l->fd < 0 && now_ms >= l->next_retry_ms && lens[i] > 0) {
            int fd = socket(addrs[i].ss_family, SOCK_STREAM, 0);
            if (fd >= 0) {
                net_set_nonblocking(fd);
                net_set_nodelay(fd, 1);
                int sb = 4 * 1024 * 1024;
                setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
#ifdef SO_NOSIGPIPE
                int one = 1;
                setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
                int rc = connect(fd, (struct sockaddr *)&addrs[i], lens[i]);
                if (rc == 0 || errno == EINPROGRESS) {
                    l->fd = fd;
                    l->connected = (rc == 0);
                } else {
                    close(fd);
                    l->next_retry_ms = now_ms + 1000;
                }
            } else {
                l->next_retry_ms = now_ms + 1000;
            }
        }
        pthread_mutex_unlock(&l->mu);
    }
}

static bool stream_any_link_connected(void) {
    if (!s_stream_initialized) return false;
    for (int i = 0; i < MAX_CLUSTER_PEERS; i++) {
        if (s_links[i].connected) return true;
    }
    return false;
}

static bool stream_send_all(int fd, const uint8_t *buf, size_t len) {
    uint64_t deadline = now_monotonic_ms() + CLUSTER_STREAM_SEND_TIMEOUT_MS;
    size_t off = 0;
    while (off < len) {
        ssize_t w = send(fd, buf + off, len - off, MSG_NOSIGNAL);
        if (w > 0) {
            off += (size_t)w;
            continue;
        }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            uint64_t now = now_monotonic_ms();
            if (now >= deadline) return false;
            struct pollfd p = { .fd = fd, .events = POLLOUT, .revents = 0 };
            poll(&p, 1, (int)(deadline - now));
            continue;
        }
        return false;
    }
    return true;
}

/* Send one frame to every connected peer; returns number of peers that accepted it */
static int stream_broadcast_frame(const uint8_t *frame, size_t len) {
    int delivered = 0;
    for (int i = 0; i < MAX_CLUSTER_PEERS; i++) {
        PeerStreamLink *l = &s_links[i];
        pthread_mutex_lock(&l->mu);
        if (l->connected && l->fd >= 0) {
            if (stream_send_all(l->fd, frame, len)) {
                delivered++;
                atomic_fetch_add_explicit(&s_tx_packets, 1, memory_order_relaxed);
            } else {
                add_log("\033[1;31m[HA STREAM]\033[0m Checkpoint send to peer link %d failed: %s", i, strerror(errno));
                stream_link_close_locked(l, now_monotonic_ms());
            }
        }
        pthread_mutex_unlock(&l->mu);
    }
    return delivered;
}

static void handle_stream_migration(const uint8_t *payload, size_t len, uint8_t sender_state) {
    if (len < sizeof(ClusterStreamMigrationHdr)) return;
    ClusterStreamMigrationHdr mh;
    memcpy(&mh, payload, sizeof(mh));
    uint32_t ccl = ntohl(mh.client_cp_len);
    uint32_t bcl = ntohl(mh.backend_cp_len);
    uint32_t c2l = ntohl(mh.c2b_len);
    uint32_t b2l = ntohl(mh.b2c_len);
    size_t base = offsetof(ClusterTcpCheckpointWire, queue_data);
    if (ccl < base || ccl > sizeof(ClusterTcpCheckpointWire)) return;
    if (bcl != 0 && (bcl < base || bcl > sizeof(ClusterTcpCheckpointWire))) return;
    if (c2l > BUFFER_SIZE || b2l > BUFFER_SIZE) return;
    if ((uint64_t)sizeof(mh) + ccl + bcl + c2l + b2l != len) return;

    const uint8_t *p = payload + sizeof(mh);
    ClusterTcpCheckpointWire *cw = malloc(sizeof(*cw));
    ClusterTcpCheckpointWire *bw = (bcl > 0) ? malloc(sizeof(*bw)) : NULL;
    MigratedStreamState *st = calloc(1, sizeof(*st));
    if (!cw || !st || (bcl > 0 && !bw)) {
        free(cw);
        free(bw);
        free(st);
        return;
    }
    memcpy(cw, p, ccl);
    p += ccl;
    bool ok = (tcp_checkpoint_wire_len(cw) == ccl);
    if (ok && bw) {
        memcpy(bw, p, bcl);
        p += bcl;
        ok = (tcp_checkpoint_wire_len(bw) == bcl);
        if (ok) {
            tcp_checkpoint_from_wire(bw, &st->backend, NULL, NULL, NULL, NULL, NULL, NULL);
            st->has_backend = true;
        }
    }
    if (ok && c2l > 0 && (st->c2b = malloc(c2l)) != NULL) {
        memcpy(st->c2b, p, c2l);
        st->c2b_len = c2l;
    }
    p += c2l;
    if (ok && b2l > 0 && (st->b2c = malloc(b2l)) != NULL) {
        memcpy(st->b2c, p, b2l);
        st->b2c_len = b2l;
    }
    st->bytes_to_backend = net_to_u64(mh.bytes_to_backend);
    st->bytes_from_backend = net_to_u64(mh.bytes_from_backend);
    st->skip_backend_bytes = net_to_u64(mh.skip_backend_bytes);
    st->flags = mh.flags;

    if (ok && session_table_store_stream_migration(cw, st)) {
        st = NULL; /* owned by the session table now */
        atomic_fetch_add_explicit(&s_synced_sessions, 1, memory_order_relaxed);
        VrrpState my_state = (VrrpState)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);
        if (my_state == VRRP_STATE_MASTER && sender_state != VRRP_STATE_MASTER) {
            session_table_promote_shadow_conns();
            rst_filter_extend();
        }
    }
    migrated_stream_release(st);
    free(cw);
    free(bw);
}

/* Parse complete frames from an inbound buffer; returns false if the stream must be closed */
static bool stream_inbound_process(InboundStream *in) {
    size_t off = 0;
    while (in->len - off >= sizeof(ClusterStreamFrameHdr)) {
        ClusterStreamFrameHdr *h = (ClusterStreamFrameHdr *)(in->buf + off);
        uint32_t plen = ntohl(h->payload_len);
        uint8_t expected_vrid = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
        if (ntohl(h->magic) != CLUSTER_STREAM_MAGIC || h->version != CLUSTER_PROTO_VERSION ||
            h->vrid != expected_vrid || plen > CLUSTER_STREAM_MAX_PAYLOAD) {
            return false;
        }
        size_t total = sizeof(*h) + plen;
        if (in->len - off < total) break;

        uint8_t rx_hmac[CLUSTER_HMAC_LEN];
        uint8_t calc[CLUSTER_HMAC_LEN];
        memcpy(rx_hmac, h->hmac, CLUSTER_HMAC_LEN);
        memset(h->hmac, 0, CLUSTER_HMAC_LEN);
        compute_packet_hmac(h, total, calc);
#ifndef NO_SSL
        bool auth = (CRYPTO_memcmp(rx_hmac, calc, CLUSTER_HMAC_LEN) == 0);
#else
        uint8_t diff = 0;
        for (size_t i = 0; i < CLUSTER_HMAC_LEN; i++) diff |= (uint8_t)(rx_hmac[i] ^ calc[i]);
        bool auth = (diff == 0);
#endif
        uint64_t ts = net_to_u64(h->timestamp_ms);
        uint64_t wall = now_wallclock_ms();
        uint64_t skew = (wall > ts) ? (wall - ts) : (ts - wall);
        if (!auth || skew > CLUSTER_ANTI_REPLAY_WINDOW_MS) {
            add_log("\033[1;31m[HA STREAM]\033[0m Rejected checkpoint frame (%s)", auth ? "stale timestamp" : "bad HMAC");
            return false;
        }
        atomic_fetch_add_explicit(&s_rx_packets, 1, memory_order_relaxed);
        if (ntohl(h->sender_node_id) != s_node_id && h->type == CLUSTER_STREAM_TYPE_MIGRATION) {
            handle_stream_migration((const uint8_t *)(h + 1), plen, h->sender_state);
        }
        off += total;
    }
    if (off > 0) {
        memmove(in->buf, in->buf + off, in->len - off);
        in->len -= off;
    }
    return true;
}

static void stream_inbound_read(InboundStream *in) {
    for (;;) {
        if (in->cap - in->len < 65536) {
            size_t ncap = in->cap ? in->cap * 2 : 262144;
            if (ncap > sizeof(ClusterStreamFrameHdr) + CLUSTER_STREAM_MAX_PAYLOAD + 65536) {
                ncap = sizeof(ClusterStreamFrameHdr) + CLUSTER_STREAM_MAX_PAYLOAD + 65536;
            }
            if (ncap <= in->cap) {
                stream_inbound_close(in);
                return;
            }
            uint8_t *nb = realloc(in->buf, ncap);
            if (!nb) {
                stream_inbound_close(in);
                return;
            }
            in->buf = nb;
            in->cap = ncap;
        }
        ssize_t r = recv(in->fd, in->buf + in->len, in->cap - in->len, MSG_DONTWAIT);
        if (r > 0) {
            in->len += (size_t)r;
            if (!stream_inbound_process(in)) {
                stream_inbound_close(in);
                return;
            }
            continue;
        }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        stream_inbound_close(in);
        return;
    }
}

static void stream_accept_pending(void) {
    for (;;) {
        int fd = accept(s_stream_listen_fd, NULL, NULL);
        if (fd < 0) return;
        int slot = -1;
        for (int i = 0; i < MAX_INBOUND_STREAMS; i++) {
            if (s_inbound[i].fd < 0) {
                slot = i;
                break;
            }
        }
        if (slot < 0) {
            close(fd);
            continue;
        }
        net_set_nonblocking(fd);
        int rb = 4 * 1024 * 1024;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
        s_inbound[slot].fd = fd;
        s_inbound[slot].len = 0;
    }
}

/* Poll set entries owned by the TCP channel */
typedef struct {
    int kind;   /* 0 = listen, 1 = outbound link, 2 = inbound stream */
    int index;
} StreamPollRef;

static int stream_fill_pollfds(struct pollfd *pfds, StreamPollRef *refs, int max) {
    int n = 0;
    if (s_stream_listen_fd < 0) return 0;
    if (n < max) {
        pfds[n] = (struct pollfd){ .fd = s_stream_listen_fd, .events = POLLIN };
        refs[n++] = (StreamPollRef){ 0, 0 };
    }
    for (int i = 0; i < MAX_CLUSTER_PEERS && n < max; i++) {
        int fd = s_links[i].fd;
        if (fd < 0) continue;
        pfds[n] = (struct pollfd){ .fd = fd, .events = s_links[i].connected ? POLLIN : POLLOUT };
        refs[n++] = (StreamPollRef){ 1, i };
    }
    for (int i = 0; i < MAX_INBOUND_STREAMS && n < max; i++) {
        if (s_inbound[i].fd < 0) continue;
        pfds[n] = (struct pollfd){ .fd = s_inbound[i].fd, .events = POLLIN };
        refs[n++] = (StreamPollRef){ 2, i };
    }
    return n;
}

static void stream_handle_pollfds(const struct pollfd *pfds, const StreamPollRef *refs, int n, uint64_t now_ms) {
    for (int k = 0; k < n; k++) {
        short re = pfds[k].revents;
        if (re == 0) continue;
        if (refs[k].kind == 0) {
            stream_accept_pending();
        } else if (refs[k].kind == 1) {
            PeerStreamLink *l = &s_links[refs[k].index];
            pthread_mutex_lock(&l->mu);
            if (l->fd == pfds[k].fd) {
                if (!l->connected) {
                    int err = 0;
                    socklen_t el = sizeof(err);
                    getsockopt(l->fd, SOL_SOCKET, SO_ERROR, &err, &el);
                    if (err == 0 && (re & POLLOUT)) {
                        l->connected = true;
                    } else {
                        stream_link_close_locked(l, now_ms);
                    }
                } else {
                    /* Peers never send on our outbound link: readable means closed or reset */
                    char tmp[256];
                    ssize_t r = recv(l->fd, tmp, sizeof(tmp), MSG_DONTWAIT);
                    if (r == 0 || (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
                        stream_link_close_locked(l, now_ms);
                    }
                }
            }
            pthread_mutex_unlock(&l->mu);
        } else {
            InboundStream *in = &s_inbound[refs[k].index];
            if (in->fd == pfds[k].fd) stream_inbound_read(in);
        }
    }
}

bool cluster_fd_is_vip_sourced(int fd) {
    if (fd < 0) return false;
    char clean_vip[64] = {0};
    int prefix = 32;
    if (!parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) return false;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof(ss);
    if (getsockname(fd, (struct sockaddr *)&ss, &sl) < 0) return false;
    uint8_t vip[16];
    if (ss.ss_family == AF_INET) {
        return inet_pton(AF_INET, clean_vip, vip) == 1 &&
               memcmp(&((struct sockaddr_in *)&ss)->sin_addr, vip, 4) == 0;
    }
    if (ss.ss_family == AF_INET6) {
        const struct in6_addr *a6 = &((struct sockaddr_in6 *)&ss)->sin6_addr;
        if (IN6_IS_ADDR_V4MAPPED(a6)) {
            return inet_pton(AF_INET, clean_vip, vip) == 1 && memcmp(&a6->s6_addr[12], vip, 4) == 0;
        }
        return inet_pton(AF_INET6, clean_vip, vip) == 1 && memcmp(a6, vip, 16) == 0;
    }
    return false;
}

/* Client + backend checkpoint and proxy buffers in one frame over the TCP channel */
static bool send_stream_migration(const TcpSocketCheckpoint *client_cp,
                                  int backend_idx,
                                  int backend_fd,
                                  const char *initial_req,
                                  uint16_t req_len,
                                  uint64_t bytes_to_client,
                                  const ClusterConnState *state) {
    if (!stream_any_link_connected()) return false;

    const char *b_ip = (backend_idx >= 0 && backend_idx < g_num_backends) ? g_backends[backend_idx].ip : "";
    uint16_t b_port = (backend_idx >= 0 && backend_idx < g_num_backends) ? (uint16_t)g_backends[backend_idx].port : 0;

    ClusterTcpCheckpointWire *cw = malloc(sizeof(*cw));
    ClusterTcpCheckpointWire *bw = malloc(sizeof(*bw));
    if (!cw || !bw) {
        free(cw);
        free(bw);
        return false;
    }
    tcp_checkpoint_to_wire(client_cp, backend_idx, b_ip, b_port, bytes_to_client, initial_req, req_len, cw);
    size_t ccl = tcp_checkpoint_wire_len(cw);

    size_t bcl = 0;
    TcpSocketCheckpoint bcp;
    if (backend_fd >= 0 && cluster_fd_is_vip_sourced(backend_fd) && tcp_repair_checkpoint(backend_fd, NULL, &bcp)) {
        tcp_checkpoint_to_wire(&bcp, backend_idx, b_ip, b_port, 0, NULL, 0, bw);
        bcl = tcp_checkpoint_wire_len(bw);
        tcp_checkpoint_release(&bcp);
    }
    /* Without the backend socket the buffers are meaningless on the new node */
    uint32_t c2l = bcl ? state->c2b_len : 0;
    uint32_t b2l = bcl ? state->b2c_len : 0;

    size_t plen = sizeof(ClusterStreamMigrationHdr) + ccl + bcl + c2l + b2l;
    size_t total = sizeof(ClusterStreamFrameHdr) + plen;
    uint8_t *frame = (plen <= CLUSTER_STREAM_MAX_PAYLOAD) ? malloc(total) : NULL;
    if (!frame) {
        free(cw);
        free(bw);
        return false;
    }

    ClusterStreamFrameHdr *h = (ClusterStreamFrameHdr *)frame;
    memset(h, 0, sizeof(*h));
    h->magic = htonl(CLUSTER_STREAM_MAGIC);
    h->version = CLUSTER_PROTO_VERSION;
    h->type = CLUSTER_STREAM_TYPE_MIGRATION;
    h->vrid = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
    h->sender_state = (uint8_t)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);
    h->sender_node_id = htonl(s_node_id);
    h->timestamp_ms = u64_to_net(now_wallclock_ms());
    h->payload_len = htonl((uint32_t)plen);

    ClusterStreamMigrationHdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.flags = state->flags;
    mh.has_backend = bcl ? 1 : 0;
    mh.bytes_to_backend = u64_to_net(state->bytes_to_backend);
    mh.bytes_from_backend = u64_to_net(state->bytes_from_backend);
    mh.skip_backend_bytes = u64_to_net(state->skip_backend_bytes);
    mh.client_cp_len = htonl((uint32_t)ccl);
    mh.backend_cp_len = htonl((uint32_t)bcl);
    mh.c2b_len = htonl(c2l);
    mh.b2c_len = htonl(b2l);

    uint8_t *p = frame + sizeof(*h);
    memcpy(p, &mh, sizeof(mh));
    p += sizeof(mh);
    memcpy(p, cw, ccl);
    p += ccl;
    if (bcl) {
        memcpy(p, bw, bcl);
        p += bcl;
    }
    if (c2l) {
        memcpy(p, state->c2b, c2l);
        p += c2l;
    }
    if (b2l) memcpy(p, state->b2c, b2l);
    compute_packet_hmac(frame, total, h->hmac);

    int delivered = stream_broadcast_frame(frame, total);
    add_log("\033[1;34m[HA STREAM]\033[0m Migrated stream over TCP (backend socket=%s, c2b=%u, b2c=%u, %zu bytes) to %d peer(s)",
            bcl ? "\033[1;32mYES\033[0m" : "\033[1;33mNO\033[0m", c2l, b2l, total, delivered);
    free(frame);
    free(cw);
    free(bw);
    return delivered > 0;
}

void cluster_replicate_live_conn(const struct sockaddr_storage *client_addr,
                                 int backend_idx,
                                 int client_fd,
                                 int backend_fd,
                                 const char *initial_req,
                                 uint16_t req_len,
                                 uint64_t bytes_to_client,
                                 const ClusterConnState *state) {
    if (!s_cluster_running || !client_addr || client_fd < 0) return;

    /* 1. Broadcast network TCP_REPAIR + kTLS Checkpoint: full stream over TCP, else client-only UDP */
    if (s_cluster_fd >= 0) {
        TcpSocketCheckpoint cp;
        /* ~60 KB packet: heap, not the 512 KB worker stack */
        ClusterWirePacket *pkt = malloc(sizeof(*pkt));
        bool have_cp = pkt && tcp_repair_checkpoint(client_fd, NULL, &cp);
        if (have_cp && state &&
            send_stream_migration(&cp, backend_idx, backend_fd, initial_req, req_len, bytes_to_client, state)) {
            tcp_checkpoint_release(&cp);
            have_cp = false;
        }
        if (have_cp) {
            const char *b_ip = (backend_idx >= 0 && backend_idx < g_num_backends) ? g_backends[backend_idx].ip : "";
            uint16_t b_port = (backend_idx >= 0 && backend_idx < g_num_backends) ? (uint16_t)g_backends[backend_idx].port : 0;
            tcp_checkpoint_to_wire(&cp, backend_idx, b_ip, b_port, bytes_to_client, initial_req, req_len, &pkt->tcp_cp);
            size_t total_len = prepare_tcp_checkpoint_packet(pkt, &pkt->tcp_cp);
            broadcast_cluster_packet(pkt, total_len);

            char cip[INET6_ADDRSTRLEN];
            int cport = 0;
            get_client_ip_port(client_addr, cip, sizeof(cip), &cport);
            add_log("\033[1;34m[HA SYNC]\033[0m Replicated TCP stream for %s:%d (kTLS=%s, wire_flags=0x%02x, snd_seq=%u, sndq=%u, rcvq=%u)",
                    cip, cport, cp.is_ktls ? "\033[1;32mYES\033[0m" : "\033[1;33mNO\033[0m",
                    (unsigned int)pkt->tcp_cp.flags, cp.snd_seq, cp.snd_queue_len, cp.rcv_queue_len);
            tcp_checkpoint_release(&cp);
        }
        free(pkt);
    }

    /* 2. Local UNIX domain socket replication (for single-host tests / child processes) */
    if (s_unix_fd >= 0 || (s_is_custom_socket && s_cluster_fd >= 0)) {
        ClusterUnixFdMsg m;
        memset(&m, 0, sizeof(m));
        m.magic = htonl(CLUSTER_UNIX_FD_MAGIC);
        m.op = CLUSTER_UNIX_OP_UPSERT_FDS;
        m.vrid = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
        m.sender_node_id = htonl(s_node_id);
        m.backend_idx = backend_idx;
        if (backend_idx >= 0 && backend_idx < g_num_backends) {
            strncpy(m.backend_ip, g_backends[backend_idx].ip, sizeof(m.backend_ip) - 1);
            m.backend_port = (uint16_t)g_backends[backend_idx].port;
        }
        m.client_addr = *client_addr;
        m.bytes_to_client = bytes_to_client;
        if (initial_req && req_len > 0) {
            if (req_len > sizeof(m.initial_req)) req_len = sizeof(m.initial_req);
            memcpy(m.initial_req, initial_req, req_len);
            m.req_len = req_len;
        }

        int fds[3];
        int nfds = 0;
        fds[nfds++] = client_fd;
        m.has_client_fd = 1;

        if (backend_fd >= 0) {
            fds[nfds++] = backend_fd;
            m.has_backend_fd = 1;
        }
        if (s_alive_pipe[0] >= 0) {
            fds[nfds++] = s_alive_pipe[0];
            m.has_alive_fd = 1;
        }

        broadcast_unix_fd_msg(&m, fds, nfds);
    }
}

void cluster_notify_conn_closed(const struct sockaddr_storage *client_addr, int backend_idx) {
    if (!s_cluster_running || !client_addr) return;
    session_table_remove_client(client_addr, SESSION_PROTO_TCP, true, true);

    if (s_unix_fd >= 0 || (s_is_custom_socket && s_cluster_fd >= 0)) {
        ClusterUnixFdMsg m;
        memset(&m, 0, sizeof(m));
        m.magic = htonl(CLUSTER_UNIX_FD_MAGIC);
        m.op = CLUSTER_UNIX_OP_CLOSE_FDS;
        m.vrid = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
        m.sender_node_id = htonl(s_node_id);
        m.backend_idx = backend_idx;
        m.client_addr = *client_addr;
        broadcast_unix_fd_msg(&m, NULL, 0);
    }
}

static void handle_received_unix_fd_msg(const ClusterUnixFdMsg *rx_m,
                                        size_t n,
                                        const int *rx_fds,
                                        int rx_nfds) {
    uint8_t expected_vrid = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
    if (n < sizeof(ClusterUnixFdMsg) ||
        ntohl(rx_m->magic) != CLUSTER_UNIX_FD_MAGIC ||
        rx_m->vrid != expected_vrid ||
        ntohl(rx_m->sender_node_id) == s_node_id) {
        for (int k = 0; k < rx_nfds; k++) {
            if (rx_fds[k] >= 0) close(rx_fds[k]);
        }
        return;
    }

    int idx = 0;
    int cfd = (rx_m->has_client_fd && idx < rx_nfds) ? rx_fds[idx++] : -1;
    int bfd = (rx_m->has_backend_fd && idx < rx_nfds) ? rx_fds[idx++] : -1;
    int afd = (rx_m->has_alive_fd && idx < rx_nfds) ? rx_fds[idx++] : -1;
    while (idx < rx_nfds) {
        if (rx_fds[idx] >= 0) close(rx_fds[idx]);
        idx++;
    }

    if (afd >= 0) {
        net_set_nonblocking(afd);
        if (s_master_alive_fd >= 0 && s_master_alive_fd != afd) {
            close(s_master_alive_fd);
        }
        s_master_alive_fd = afd;
    }

    struct sockaddr_storage aligned_client = rx_m->client_addr;
    if (rx_m->op == CLUSTER_UNIX_OP_UPSERT_FDS) {
        int resolved_b = rx_m->backend_idx;
        for (int b = 0; b < g_num_backends; b++) {
            if (g_backends[b].port == (int)rx_m->backend_port &&
                strcmp(g_backends[b].ip, rx_m->backend_ip) == 0) {
                resolved_b = b;
                break;
            }
        }
        session_table_store_shadow_fds(&aligned_client, SESSION_PROTO_TCP, resolved_b,
                                       cfd, bfd, rx_m->initial_req, rx_m->req_len,
                                       rx_m->bytes_to_client);
    } else if (rx_m->op == CLUSTER_UNIX_OP_CLOSE_FDS) {
        if (cfd >= 0) close(cfd);
        if (bfd >= 0) close(bfd);
        session_table_remove_client(&aligned_client, SESSION_PROTO_TCP, true, false);
    } else {
        if (cfd >= 0) close(cfd);
        if (bfd >= 0) close(bfd);
    }
}

static void process_incoming_unix_fd_messages(void) {
    if (s_unix_fd < 0) return;

    while (1) {
        ClusterUnixFdMsg rx_m;
        struct iovec iov;
        iov.iov_base = &rx_m;
        iov.iov_len = sizeof(rx_m);

        union {
            struct cmsghdr cm;
            char control[CMSG_SPACE(sizeof(int) * 3)];
        } cmsg_un;
        memset(&cmsg_un, 0, sizeof(cmsg_un));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_un.control;
        msg.msg_controllen = sizeof(cmsg_un.control);

        ssize_t n = recvmsg(s_unix_fd, &msg, MSG_DONTWAIT);
        if (n <= 0) break;

        int rx_fds[3] = {-1, -1, -1};
        int rx_nfds = 0;

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                size_t data_len = (size_t)cmsg->cmsg_len - (size_t)CMSG_LEN(0);
                int cnt = (int)(data_len / sizeof(int));
                if (cnt > 3) cnt = 3;
                if (cnt > 0) {
                    memcpy(rx_fds, CMSG_DATA(cmsg), (size_t)cnt * sizeof(int));
                    rx_nfds = cnt;
                }
            }
        }

        handle_received_unix_fd_msg(&rx_m, (size_t)n, rx_fds, rx_nfds);
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
    snprintf(pkt->hdr.virtual_ip, sizeof(pkt->hdr.virtual_ip), "%.45s", g_config.virtual_ip);
    pkt->hdr.session_count = htons(session_count);

    if (session_count > 0 && sessions != NULL) {
        memcpy(pkt->sessions, sessions, (size_t)session_count * sizeof(ClusterSessionWire));
    }

    size_t total_len = sizeof(ClusterPacketHeader) + (size_t)session_count * sizeof(ClusterSessionWire);
    compute_packet_hmac(pkt, total_len, pkt->hdr.hmac);
    return total_len;
}

static size_t prepare_tcp_checkpoint_packet(ClusterWirePacket *pkt,
                                            const ClusterTcpCheckpointWire *cp_wire) {
    memset(pkt, 0, sizeof(ClusterPacketHeader));
    pkt->hdr.magic = htonl(CLUSTER_MAGIC);
    pkt->hdr.version = CLUSTER_PROTO_VERSION;
    pkt->hdr.pkt_type = CLUSTER_PKT_TCP_CHECKPOINT;
    pkt->hdr.vrrp_router_id = (uint8_t)(g_config.vrrp_router_id > 0 ? g_config.vrrp_router_id : 51);
    pkt->hdr.sender_state = (uint8_t)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);
    pkt->hdr.base_priority = (uint8_t)(g_config.vrrp_priority > 0 ? g_config.vrrp_priority : 100);
    pkt->hdr.effective_priority = compute_effective_priority();
    uint16_t adv_ms = (uint16_t)(g_config.vrrp_advert_interval_ms > 0 ? g_config.vrrp_advert_interval_ms : 200);
    pkt->hdr.advert_interval_ms = htons(adv_ms);
    pkt->hdr.sender_node_id = htonl(s_node_id);

    uint64_t seq = atomic_fetch_add_explicit(&s_seq_counter, 1, memory_order_relaxed);
    pkt->hdr.seq_num = u64_to_net(seq);
    pkt->hdr.timestamp_ms = u64_to_net(now_wallclock_ms());
    snprintf(pkt->hdr.virtual_ip, sizeof(pkt->hdr.virtual_ip), "%.45s", g_config.virtual_ip);
    pkt->hdr.session_count = htons(1);

    if (cp_wire && cp_wire != &pkt->tcp_cp) {
        pkt->tcp_cp = *cp_wire;
    }

    size_t total_len = sizeof(ClusterPacketHeader) + tcp_checkpoint_wire_len(&pkt->tcp_cp);
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
        snprintf(found->ip, sizeof(found->ip), "%.63s", (src_ip[0] != '\0') ? src_ip : "unix-peer");
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
        if (s_master_alive_fd >= 0) {
            close(s_master_alive_fd);
            s_master_alive_fd = -1;
        }
        atomic_fetch_add_explicit(&s_failover_count, 1, memory_order_relaxed);
        acquire_virtual_ip();
        int promoted = session_table_promote_shadow_conns();
        rst_filter_extend();
        add_log("\033[1;32m[VRRP ELECTION]\033[0m Node %08X transitioned %s -> MASTER (prio %u, VRID %d, adopted %d active stream(s))",
                s_node_id, cluster_state_name(prev),
                (unsigned int)s_master_effective_prio, g_config.vrrp_router_id, promoted);

        /* Immediately broadcast MASTER advertisement + local crash-detector pipe */
        ClusterWirePacket pkt;
        size_t len = prepare_packet(&pkt, CLUSTER_PKT_VRRP_ADVERT, 0, false, NULL, 0);
        broadcast_cluster_packet(&pkt, len);
        send_unix_heartbeat_fd_to_peers();
    }
}

static void transition_to_backup(uint32_t new_master_id, uint8_t master_prio, uint64_t now_ms) {
    VrrpState prev = (VrrpState)atomic_exchange_explicit(&s_vrrp_state, VRRP_STATE_BACKUP, memory_order_acq_rel);
    atomic_store_explicit(&s_current_master_id, new_master_id, memory_order_relaxed);
    s_last_master_advert_ms = now_ms;
    s_master_effective_prio = master_prio;

    if (prev == VRRP_STATE_MASTER) {
        add_vip_blackhole_rule();
        worker_pool_handover_active_conns();
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
    size_t expected_len;
    if (pkt->hdr.pkt_type == CLUSTER_PKT_TCP_CHECKPOINT) {
        expected_len = sizeof(ClusterPacketHeader) + offsetof(ClusterTcpCheckpointWire, queue_data);
        if (bytes_read < expected_len) return;
        expected_len = sizeof(ClusterPacketHeader) + tcp_checkpoint_wire_len(&pkt->tcp_cp);
    } else {
        if (sess_count > CLUSTER_MAX_BATCH_SESSIONS) return;
        expected_len = sizeof(ClusterPacketHeader) + (size_t)sess_count * sizeof(ClusterSessionWire);
    }
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
            if (my_state != VRRP_STATE_MASTER && !s_manual_demoted) {
                transition_to_master(now_ms);
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
    } else if (pkt->hdr.pkt_type == CLUSTER_PKT_TCP_CHECKPOINT) {
        if (session_table_store_tcp_checkpoint(&pkt->tcp_cp)) {
            atomic_fetch_add_explicit(&s_synced_sessions, 1, memory_order_relaxed);
            /* Handover checkpoint arriving after our promotion (preemption, or slower than the
             * SWITCHOVER packet): adopt it now, otherwise it would sit in the table until it expires */
            if (my_state == VRRP_STATE_MASTER && sender_state != VRRP_STATE_MASTER) {
                session_table_promote_shadow_conns();
                rst_filter_extend();
            }
        }
    } else if (pkt->hdr.pkt_type == CLUSTER_PKT_SYNC_REQ) {
        /* If we are MASTER (or have active sessions), send snapshot + live FDs back to requester */
        if (my_state == VRRP_STATE_MASTER || session_table_count() > 0) {
            handle_bulk_sync_request(src_addr, src_len);
            if (my_state == VRRP_STATE_MASTER) {
                send_unix_heartbeat_fd_to_peers();
                worker_pool_resync_live_conns();
            }
        }
    } else if (pkt->hdr.pkt_type == CLUSTER_PKT_SWITCHOVER) {
        /* Priority 0 = the Master yielded to us; priority > 0 = a Backup asks us to yield.
         * Deciding on our own state alone made the duplicate copy (sent twice) undo the switch. */
        bool peer_yielded = (sender_eff_prio == 0);
        if ((peer_yielded && my_state == VRRP_STATE_MASTER) ||
            (!peer_yielded && my_state != VRRP_STATE_MASTER)) {
            return; /* duplicate or stale request */
        }
        add_log("\033[1;35m[VRRP SWITCHOVER]\033[0m Received manual switchover signal from Node %08X", sender_id);
        if (my_state == VRRP_STATE_MASTER) {
            /* Peer requested to take over Master: step down and hold standby lock */
            s_manual_demoted = true;
            s_stepdown_until_ms = 0;
            s_last_master_advert_ms = now_ms;

            add_vip_blackhole_rule();

            /* BACKUP before handover: checkpoints then carry sender_state BACKUP and are adopted
             * immediately even if they reach the peer after it already became MASTER */
            atomic_store_explicit(&s_vrrp_state, VRRP_STATE_BACKUP, memory_order_release);
            worker_pool_handover_active_conns();
            release_virtual_ip();
            atomic_store_explicit(&s_current_master_id, sender_id, memory_order_relaxed);
            if (s_alive_pipe[0] >= 0) close(s_alive_pipe[0]);
            if (s_alive_pipe[1] >= 0) close(s_alive_pipe[1]);
            if (pipe(s_alive_pipe) == 0) {
                net_set_nonblocking(s_alive_pipe[0]);
                net_set_nonblocking(s_alive_pipe[1]);
            } else {
                s_alive_pipe[0] = s_alive_pipe[1] = -1;
            }

            ClusterWirePacket rel_pkt;
            size_t len = prepare_packet(&rel_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, true, NULL, 0);
            broadcast_cluster_packet(&rel_pkt, len);
            add_log("\033[1;33m[VRRP SWITCHOVER]\033[0m Yielded MASTER to Node %08X (holding BACKUP standby lock)", sender_id);
        } else {
            /* We are BACKUP and Master has yielded leadership to us */
            s_manual_demoted = false;
            s_stepdown_until_ms = 0;
            transition_to_master(now_ms);
            add_log("\033[1;32m[VRRP SWITCHOVER]\033[0m Assumed MASTER role from Node %08X upon switch request", sender_id);
        }
        wakeup_cluster_thread();
        return;
    }
}

static void drain_cluster_socket_messages(uint64_t now_ms) {
    if (s_cluster_fd < 0) return;

    while (1) {
        union {
            ClusterWirePacket wire;
            ClusterUnixFdMsg  fd_msg;
            uint32_t          magic;
        } rx_buf;

        struct sockaddr_storage src_addr;
        memset(&src_addr, 0, sizeof(src_addr));

        struct iovec iov;
        iov.iov_base = &rx_buf;
        iov.iov_len = sizeof(rx_buf);

        union {
            struct cmsghdr cm;
            char control[CMSG_SPACE(sizeof(int) * 3)];
        } cmsg_un;
        memset(&cmsg_un, 0, sizeof(cmsg_un));

        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_name = &src_addr;
        msg.msg_namelen = sizeof(src_addr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        msg.msg_control = cmsg_un.control;
        msg.msg_controllen = sizeof(cmsg_un.control);

        ssize_t n = recvmsg(s_cluster_fd, &msg, MSG_DONTWAIT);
        if (n <= 0) break;

        int rx_fds[3] = {-1, -1, -1};
        int rx_nfds = 0;

        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
            if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                size_t data_len = (size_t)cmsg->cmsg_len - (size_t)CMSG_LEN(0);
                int cnt = (int)(data_len / sizeof(int));
                if (cnt > 3) cnt = 3;
                if (cnt > 0) {
                    memcpy(rx_fds, CMSG_DATA(cmsg), (size_t)cnt * sizeof(int));
                    rx_nfds = cnt;
                }
            }
        }

        if ((size_t)n >= sizeof(uint32_t) && ntohl(rx_buf.magic) == CLUSTER_UNIX_FD_MAGIC) {
            handle_received_unix_fd_msg(&rx_buf.fd_msg, (size_t)n, rx_fds, rx_nfds);
        } else {
            for (int k = 0; k < rx_nfds; k++) {
                if (rx_fds[k] >= 0) close(rx_fds[k]);
            }
            process_incoming_packet(&rx_buf.wire, (size_t)n, &src_addr, msg.msg_namelen, now_ms);
        }
    }
}

static void trigger_instant_master_failover(uint64_t now_ms) {
    if (s_master_alive_fd >= 0) {
        close(s_master_alive_fd);
        s_master_alive_fd = -1;
    }

    uint32_t dead_master = atomic_exchange_explicit(&s_current_master_id, 0, memory_order_relaxed);
    pthread_mutex_lock(&s_cluster_mutex);
    for (int i = 0; i < s_num_peers; i++) {
        if (s_peers[i].node_id == dead_master || s_peers[i].state == VRRP_STATE_MASTER || s_is_custom_socket) {
            s_peers[i].is_reachable = false;
            s_peers[i].state = VRRP_STATE_INIT;
        }
    }
    pthread_mutex_unlock(&s_cluster_mutex);

    s_last_master_advert_ms = 0;
    s_master_effective_prio = 0;
    add_log("\033[1;31m[VRRP FAST-FAILOVER]\033[0m Instantaneous MASTER crash/stepdown detected (<1ms) — taking over VIP and active streams");
    transition_to_master(now_ms);
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
        struct pollfd pfds[4 + 1 + MAX_CLUSTER_PEERS + MAX_INBOUND_STREAMS];
        StreamPollRef stream_refs[1 + MAX_CLUSTER_PEERS + MAX_INBOUND_STREAMS];
        int nfds = 0;

        int idx_cluster = -1;
        if (s_cluster_fd >= 0 && !s_custom_socket_hup) {
            idx_cluster = nfds++;
            pfds[idx_cluster].fd = s_cluster_fd;
            pfds[idx_cluster].events = POLLIN | POLLHUP | POLLERR;
            pfds[idx_cluster].revents = 0;
        }

        int idx_wakeup = -1;
        if (s_wakeup_pipe[0] >= 0) {
            idx_wakeup = nfds++;
            pfds[idx_wakeup].fd = s_wakeup_pipe[0];
            pfds[idx_wakeup].events = POLLIN;
            pfds[idx_wakeup].revents = 0;
        }

        int idx_unix = -1;
        if (s_unix_fd >= 0) {
            idx_unix = nfds++;
            pfds[idx_unix].fd = s_unix_fd;
            pfds[idx_unix].events = POLLIN;
            pfds[idx_unix].revents = 0;
        }

        int idx_alive = -1;
        if (s_master_alive_fd >= 0 &&
            atomic_load_explicit(&s_vrrp_state, memory_order_relaxed) != VRRP_STATE_MASTER) {
            idx_alive = nfds++;
            pfds[idx_alive].fd = s_master_alive_fd;
            pfds[idx_alive].events = POLLIN | POLLHUP | POLLERR;
            pfds[idx_alive].revents = 0;
        }

        stream_links_maintain(now_ms);
        int stream_base = nfds;
        int stream_n = stream_fill_pollfds(&pfds[stream_base], stream_refs,
                                           (int)(sizeof(stream_refs) / sizeof(stream_refs[0])));
        nfds += stream_n;

        int timeout_ms = (int)(advert_ms / 2);
        if (timeout_ms < 10) timeout_ms = 10;
        if (timeout_ms > 50) timeout_ms = 50;

        int pr = poll(pfds, (nfds_t)nfds, timeout_ms);
        now_ms = now_monotonic_ms();
        if (pr > 0 && stream_n > 0) {
            stream_handle_pollfds(&pfds[stream_base], stream_refs, stream_n, now_ms);
        }

        /* Always drain incoming SCM_RIGHTS live socket messages and cluster socket messages first */
        process_incoming_unix_fd_messages();
        drain_cluster_socket_messages(now_ms);

        if (pr > 0) {
            if (idx_wakeup >= 0 && (pfds[idx_wakeup].revents & POLLIN)) {
                char drain[64];
                while (read(s_wakeup_pipe[0], drain, sizeof(drain)) > 0) {}
            }
            if (idx_cluster >= 0 && (pfds[idx_cluster].revents & (POLLHUP | POLLERR)) && s_is_custom_socket) {
                s_custom_socket_hup = true;
                if (atomic_load_explicit(&s_vrrp_state, memory_order_relaxed) != VRRP_STATE_MASTER) {
                    trigger_instant_master_failover(now_ms);
                }
            }
            if (idx_alive >= 0 && s_master_alive_fd >= 0 &&
                (pfds[idx_alive].revents & (POLLHUP | POLLERR | POLLIN))) {
                char tmp[16];
                ssize_t r = read(s_master_alive_fd, tmp, sizeof(tmp));
                if (r == 0 || (pfds[idx_alive].revents & (POLLHUP | POLLERR))) {
                    trigger_instant_master_failover(now_ms);
                }
            }
        }

        if (s_stepdown_requested) {
            s_stepdown_requested = 0;
            cluster_trigger_stepdown();
        }

        if (s_bulk_sync_requested) {
            s_bulk_sync_requested = false;
            ClusterWirePacket sync_req;
            size_t len = prepare_packet(&sync_req, CLUSTER_PKT_SYNC_REQ, 0, false, NULL, 0);
            broadcast_cluster_packet(&sync_req, len);
        }

        if (atomic_load(&s_rst_filter_active) && now_ms >= atomic_load(&s_rst_filter_until_ms)) {
            rst_filter_disarm();
            add_log("\033[1;36m[HA RST FILTER]\033[0m Takeover window closed: kernel RSTs from the VIP re-enabled");
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
        if (s_cluster_stopping) {
            /* cluster_stop() already marked us BACKUP for the handover: never re-elect ourselves */
        } else if (cur_state != VRRP_STATE_MASTER) {
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
            if (atomic_load_explicit(&s_vrrp_state, memory_order_relaxed) == VRRP_STATE_MASTER) {
                send_unix_heartbeat_fd_to_peers();
            }
            last_advert_sent_ms = now_ms;
        }

        /* Fast post-election GARP burst (3 packets at 250ms intervals) upon transition to MASTER */
        if (atomic_load_explicit(&s_vrrp_state, memory_order_relaxed) == VRRP_STATE_MASTER && s_vip_bound_kernel) {
            if (s_garp_burst_remaining > 0 && (now_ms - s_last_garp_sent_ms) >= 250ULL) {
                broadcast_active_vip_garp();
                s_garp_burst_remaining--;
                s_last_garp_sent_ms = now_ms;
            }
        }

        /* Periodic session expiration cleanup every 5 seconds */
        if ((now_ms - last_cleanup_ms) >= 5000ULL) {
            session_table_cleanup_expired();
            last_cleanup_ms = now_ms;
        }
    }

    return NULL;
}

static void init_local_unix_fd_channel(int cport) {
    int vrid = (g_config.vrrp_router_id > 0) ? g_config.vrrp_router_id : 51;
    build_unix_sock_path(s_unix_path, sizeof(s_unix_path), vrid, cport);
    unlink(s_unix_path);

    s_unix_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (s_unix_fd >= 0) {
        net_set_nonblocking(s_unix_fd);
        int buf_sz = 262144;
        setsockopt(s_unix_fd, SOL_SOCKET, SO_RCVBUF, &buf_sz, sizeof(buf_sz));
        setsockopt(s_unix_fd, SOL_SOCKET, SO_SNDBUF, &buf_sz, sizeof(buf_sz));
        struct sockaddr_un uaddr;
        memset(&uaddr, 0, sizeof(uaddr));
        uaddr.sun_family = AF_UNIX;
        snprintf(uaddr.sun_path, sizeof(uaddr.sun_path), "%.103s", s_unix_path);
        if (bind(s_unix_fd, (struct sockaddr *)&uaddr, sizeof(uaddr)) < 0) {
            close(s_unix_fd);
            s_unix_fd = -1;
        }
    }

    if (pipe(s_alive_pipe) == 0) {
        net_set_nonblocking(s_alive_pipe[0]);
        net_set_nonblocking(s_alive_pipe[1]);
    } else {
        s_alive_pipe[0] = s_alive_pipe[1] = -1;
    }
    s_master_alive_fd = -1;
}

static void cleanup_local_unix_fd_channel(void) {
    if (s_unix_fd >= 0) {
        close(s_unix_fd);
        s_unix_fd = -1;
    }
    if (s_unix_path[0] != '\0') {
        unlink(s_unix_path);
        s_unix_path[0] = '\0';
    }
    if (s_alive_pipe[0] >= 0) {
        close(s_alive_pipe[0]);
        s_alive_pipe[0] = -1;
    }
    if (s_alive_pipe[1] >= 0) {
        close(s_alive_pipe[1]);
        s_alive_pipe[1] = -1;
    }
    if (s_master_alive_fd >= 0) {
        close(s_master_alive_fd);
        s_master_alive_fd = -1;
    }
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
    init_local_unix_fd_channel(cport);

    s_cluster_fd = custom_dgram_fd;
    s_is_custom_socket = true;
    s_custom_socket_hup = false;
    atomic_store(&s_vrrp_state, VRRP_STATE_BACKUP);
    atomic_store(&s_vip_active, false);
    atomic_store(&s_current_master_id, 0);
    s_stepdown_until_ms = 0;
    s_manual_demoted = false;
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
    s_custom_socket_hup = false;

    /* Prepare parent network interface, heal any leftover VMAC on parent NIC, and clean stale vrrp<VRID> */
    char clean_vip[64] = {0};
    int vip_prefix = 32;
    char parent_iface[64] = {0};
    if (parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &vip_prefix)) {
        if (resolve_vip_interface(clean_vip, parent_iface, sizeof(parent_iface))) {
            save_original_iface_mac_and_ip(parent_iface, clean_vip);
#ifdef __linux__
            if (geteuid() == 0 && strncmp(parent_iface, "lo", 2) != 0) {
                int vrid = (g_config.vrrp_router_id >= 1 && g_config.vrrp_router_id <= 255) ? g_config.vrrp_router_id : 51;
                int rtable = 100 + vrid;
                char vrrp_if[64];
                snprintf(vrrp_if, sizeof(vrrp_if), "vrrp%d", vrid);
                int host_pfx = strchr(clean_vip, ':') ? 128 : 32;
                sysnet_rule_del(clean_vip, rtable);
                sysnet_route_flush_table(rtable);
                sysnet_link_del(vrrp_if);
                sysnet_addr_del(parent_iface, clean_vip, vip_prefix);
                sysnet_addr_del(parent_iface, clean_vip, host_pfx);

                /* Flush any stale ARP neighbor entries for cluster peers and announce our physical MAC */
                pthread_mutex_lock(&s_cluster_mutex);
                for (int i = 0; i < s_num_peers; i++) {
                    if (net_validate_ip(s_peers[i].ip)) {
                        sysnet_neigh_del(s_peers[i].ip, parent_iface);
                    }
                }
                pthread_mutex_unlock(&s_cluster_mutex);

                if (s_iface_primary_ip[0] != '\0' && s_saved_orig_mac[0] != '\0') {
                    send_vrrp_garp_on_iface(parent_iface, s_iface_primary_ip, s_saved_orig_mac);
                }
                sysnet_rule_del(clean_vip, 0);
                sysnet_rule_add(clean_vip, 50, 0);
                /* Leftover from a crashed run: the filter is armed only during a takeover */
                remove_vip_rst_filter(parent_iface, clean_vip);
            }
#endif
        }
    }

    int cport = (g_config.cluster_port > 0) ? g_config.cluster_port : DEFAULT_CLUSTER_PORT;
    const char *bind_ip = (g_config.cluster_bind_ip[0] != '\0') ? g_config.cluster_bind_ip : "0.0.0.0";

    if (g_config.cluster_node_id != 0) {
        s_node_id = g_config.cluster_node_id;
    } else {
        struct in_addr b4;
        uint32_t ip_part = 0x7F000001u;
        if (inet_pton(AF_INET, bind_ip, &b4) == 1 && b4.s_addr != 0) {
            ip_part = ntohl(b4.s_addr);
        } else if (s_iface_primary_ip[0] != '\0' && inet_pton(AF_INET, s_iface_primary_ip, &b4) == 1 && b4.s_addr != 0) {
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
    /* A handover bursts one checkpoint datagram (up to ~60 KB) per stream */
    int cbuf = 8 * 1024 * 1024;
#ifdef SO_RCVBUFFORCE
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE, &cbuf, sizeof(cbuf)) < 0)
#endif
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &cbuf, sizeof(cbuf));
#ifdef SO_SNDBUFFORCE
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUFFORCE, &cbuf, sizeof(cbuf)) < 0)
#endif
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &cbuf, sizeof(cbuf));

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
    stream_channel_open(bind_ip, cport);

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
    init_local_unix_fd_channel(cport);

    s_cluster_fd = fd;
    atomic_store(&s_vrrp_state, VRRP_STATE_BACKUP);
    atomic_store(&s_vip_active, false);
    atomic_store(&s_current_master_id, 0);
    s_stepdown_until_ms = 0;
    s_manual_demoted = false;
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

    /* If we are MASTER, hand over active streams and send Priority-0 release packet for instant failover (<1ms) */
    s_cluster_stopping = true;
    if (atomic_load_explicit(&s_vrrp_state, memory_order_relaxed) == VRRP_STATE_MASTER) {
        add_vip_blackhole_rule();
        atomic_store_explicit(&s_vrrp_state, VRRP_STATE_BACKUP, memory_order_release);
        worker_pool_handover_active_conns();
        if (s_alive_pipe[1] >= 0) {
            close(s_alive_pipe[1]);
            s_alive_pipe[1] = -1;
        }
        ClusterWirePacket rel_pkt;
        size_t len = prepare_packet(&rel_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, true, NULL, 0);
        broadcast_cluster_packet(&rel_pkt, len);
        release_virtual_ip();
    }

    s_cluster_running = false;
    s_manual_demoted = false;
    wakeup_cluster_thread();
    pthread_join(s_cluster_thread, NULL);
    s_cluster_stopping = false;
    stream_channel_close();

    if (s_cluster_fd >= 0) {
        close(s_cluster_fd);
        s_cluster_fd = -1;
    }
    s_is_custom_socket = false;
    cleanup_local_unix_fd_channel();
    if (s_wakeup_pipe[0] >= 0) {
        close(s_wakeup_pipe[0]);
        s_wakeup_pipe[0] = -1;
    }
    if (s_wakeup_pipe[1] >= 0) {
        close(s_wakeup_pipe[1]);
        s_wakeup_pipe[1] = -1;
    }

    char clean_vip[64] = {0};
    int prefix = 32;
    if (parse_vip_cidr(g_config.virtual_ip, clean_vip, sizeof(clean_vip), &prefix)) {
        sysnet_rule_del(clean_vip, 0);
        rst_filter_disarm();
        remove_vip_rst_filter(g_config.vip_interface, clean_vip);
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
    uint64_t now_ms = now_monotonic_ms();
    VrrpState my_state = (VrrpState)atomic_load_explicit(&s_vrrp_state, memory_order_relaxed);

    if (my_state == VRRP_STATE_MASTER) {
        /* We are currently MASTER: step down and hand over to BACKUP */
        s_manual_demoted = true;
        s_stepdown_until_ms = 0;
        s_last_master_advert_ms = now_ms;

        add_vip_blackhole_rule();

        /* Hand over active connections cleanly FIRST while VIP is alive (state already BACKUP
         * so the peer adopts checkpoints that arrive after its promotion) */
        atomic_store_explicit(&s_vrrp_state, VRRP_STATE_BACKUP, memory_order_release);
        worker_pool_handover_active_conns();

        release_virtual_ip();
        atomic_store_explicit(&s_current_master_id, 0, memory_order_relaxed);

        if (s_alive_pipe[0] >= 0) close(s_alive_pipe[0]);
        if (s_alive_pipe[1] >= 0) close(s_alive_pipe[1]);
        if (pipe(s_alive_pipe) == 0) {
            net_set_nonblocking(s_alive_pipe[0]);
            net_set_nonblocking(s_alive_pipe[1]);
        } else {
            s_alive_pipe[0] = s_alive_pipe[1] = -1;
        }

        /* Broadcast switchover packet + priority-0 advert so Backup immediately takes over */
        ClusterWirePacket sw_pkt;
        size_t sw_len = prepare_packet(&sw_pkt, CLUSTER_PKT_SWITCHOVER, 0, true, NULL, 0);
        for (int b = 0; b < 2; b++) {
            broadcast_cluster_packet(&sw_pkt, sw_len);
        }

        ClusterWirePacket rel_pkt;
        size_t len = prepare_packet(&rel_pkt, CLUSTER_PKT_VRRP_ADVERT, 0, true, NULL, 0);
        broadcast_cluster_packet(&rel_pkt, len);

        add_log("\033[1;33m[VRRP SWITCHOVER]\033[0m Manual failover triggered: Node %08X stepped down to BACKUP (holding standby lock while peer is alive)", s_node_id);
    } else {
        /* We are currently BACKUP: user wants to promote this node to MASTER */
        s_manual_demoted = false;
        s_stepdown_until_ms = 0;

        uint32_t master_id = atomic_load_explicit(&s_current_master_id, memory_order_relaxed);
        if (master_id != 0 && master_id != s_node_id) {
            /* Broadcast switchover packet instructing peer Master to step down and handover active conns */
            ClusterWirePacket sw_pkt;
            size_t sw_len = prepare_packet(&sw_pkt, CLUSTER_PKT_SWITCHOVER, 0, false, NULL, 0);
            for (int b = 0; b < 2; b++) {
                broadcast_cluster_packet(&sw_pkt, sw_len);
            }
            add_log("\033[1;35m[VRRP SWITCHOVER]\033[0m Sent takeover request to Master Node %08X (awaiting connection handover)...", master_id);
            s_last_master_advert_ms = now_ms;
        } else {
            /* No remote Master active: promote immediately */
            transition_to_master(now_ms);
            add_log("\033[1;32m[VRRP SWITCHOVER]\033[0m Node %08X promoted to MASTER upon manual switch request", s_node_id);
        }
    }
    wakeup_cluster_thread();
}

void cluster_request_stepdown_async(void) {
    s_stepdown_requested = 1;
    if (s_wakeup_pipe[1] >= 0) {
        char c = 's';
        ssize_t w = write(s_wakeup_pipe[1], &c, 1);
        (void)w;
    }
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
