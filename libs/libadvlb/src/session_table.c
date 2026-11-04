#define _GNU_SOURCE
#include "advlb/session_table.h"
#include "advlb/cluster.h"
#include "advlb/balancer.h"
#include "advlb/config.h"
#include "advlb/log.h"
#include "advlb/proxy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <stdatomic.h>

#define SESSION_SHARDS 16
#define SESSION_BUCKETS_PER_SHARD 128
#define MAX_SESSIONS_PER_SHARD (MAX_CLUSTER_SESSIONS / SESSION_SHARDS)

#define WIRE_FAMILY_IPV4  4
#define WIRE_FAMILY_IPV6  6
#define WIRE_FAMILY_TOKEN 10

typedef struct SessionNode {
    bool in_use;
    uint8_t family;           /* WIRE_FAMILY_IPV4 or WIRE_FAMILY_IPV6 */
    uint8_t proto;            /* SESSION_PROTO_TCP or SESSION_PROTO_UDP */
    uint16_t client_port;     /* Network byte order (0 for IP-only sticky) */
    uint8_t client_ip[16];
    char backend_ip[46];
    uint16_t backend_port;    /* Host byte order */
    int backend_idx;
    time_t last_seen;
    time_t last_replicated;
    uint32_t ttl_sec;
    uint64_t version;
    int shadow_client_fd;
    int shadow_backend_fd;
    bool has_tcp_checkpoint;
    TcpSocketCheckpoint checkpoint;
    uint64_t bytes_to_client;
    uint16_t req_len;
    char initial_req[512];
    struct SessionNode *hash_next;
} SessionNode;

typedef struct {
    pthread_mutex_t mutex;
    SessionNode nodes[MAX_SESSIONS_PER_SHARD];
    SessionNode *buckets[SESSION_BUCKETS_PER_SHARD];
    int active_count;
} SessionShard;

static SessionShard s_shards[SESSION_SHARDS];
static bool s_initialized = false;
static atomic_int s_total_sessions = 0;
static _Atomic uint64_t s_version_counter = 1;

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

static bool extract_client_key(const struct sockaddr_storage *client_addr,
                               bool use_port,
                               uint8_t *out_family,
                               uint8_t out_ip[16],
                               uint16_t *out_port) {
    if (!client_addr) return false;
    memset(out_ip, 0, 16);
    *out_port = 0;

    if (client_addr->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)client_addr;
        *out_family = WIRE_FAMILY_IPV4;
        memcpy(out_ip, &s4->sin_addr.s_addr, 4);
        if (use_port) {
            *out_port = s4->sin_port;
        }
        return true;
    } else if (client_addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)client_addr;
        *out_family = WIRE_FAMILY_IPV6;
        memcpy(out_ip, &s6->sin6_addr, 16);
        if (use_port) {
            *out_port = s6->sin6_port;
        }
        return true;
    }
    return false;
}

static inline uint32_t compute_key_hash(uint8_t family,
                                        uint8_t proto,
                                        const uint8_t ip[16],
                                        uint16_t port) {
    uint32_t h = 2166136261u;
    h ^= family;
    h *= 16777619u;
    h ^= proto;
    h *= 16777619u;
    size_t ip_len = (family == WIRE_FAMILY_IPV4) ? 4 : 16;
    for (size_t i = 0; i < ip_len; i++) {
        h ^= ip[i];
        h *= 16777619u;
    }
    h ^= (uint8_t)(port & 0xFF);
    h *= 16777619u;
    h ^= (uint8_t)((port >> 8) & 0xFF);
    h *= 16777619u;
    return h;
}

static void extract_token_key(const char *token, size_t token_len, uint8_t out_ip[16]) {
    uint64_t h1 = 14695981039346656037ULL;
    uint64_t h2 = 1099511628211ULL ^ 0x9e3779b97f4a7c15ULL;
    for (size_t i = 0; i < token_len; i++) {
        uint8_t b = (uint8_t)token[i];
        h1 ^= b;
        h1 *= 1099511628211ULL;
        h2 ^= (uint64_t)b << ((i & 7) * 8);
        h2 = (h2 << 13) | (h2 >> 51);
        h2 *= 0xff51afd7ed558ccdULL;
    }
    memcpy(out_ip, &h1, 8);
    memcpy(out_ip + 8, &h2, 8);
}

static void shard_bucket_remove(SessionShard *shard, uint32_t bucket_idx, SessionNode *target) {
    SessionNode **curr = &shard->buckets[bucket_idx];
    while (*curr) {
        if (*curr == target) {
            *curr = target->hash_next;
            target->hash_next = NULL;
            return;
        }
        curr = &((*curr)->hash_next);
    }
}

static SessionNode *shard_find_locked(SessionShard *shard,
                                      uint32_t bucket_idx,
                                      uint8_t family,
                                      uint8_t proto,
                                      const uint8_t ip[16],
                                      uint16_t port) {
    size_t ip_len = (family == WIRE_FAMILY_IPV4) ? 4 : 16;
    SessionNode *curr = shard->buckets[bucket_idx];
    while (curr) {
        if (curr->in_use &&
            curr->family == family &&
            curr->proto == proto &&
            curr->client_port == port &&
            memcmp(curr->client_ip, ip, ip_len) == 0) {
            return curr;
        }
        curr = curr->hash_next;
    }
    return NULL;
}

static int resolve_backend_index(const char *backend_ip, uint16_t backend_port, int hint_idx) {
    int num_b = g_num_backends;
    if (backend_ip && backend_ip[0] != '\0' && backend_port > 0) {
        for (int i = 0; i < num_b; i++) {
            if (g_backends[i].port == (int)backend_port &&
                strcmp(g_backends[i].ip, backend_ip) == 0) {
                return i;
            }
        }
    }
    if (hint_idx >= 0 && hint_idx < num_b) {
        return hint_idx;
    }
    return -1;
}

static void close_node_shadow_fds(SessionNode *node) {
    if (!node) return;
    if (node->shadow_client_fd >= 0) {
        close(node->shadow_client_fd);
        node->shadow_client_fd = -1;
    }
    if (node->shadow_backend_fd >= 0) {
        close(node->shadow_backend_fd);
        node->shadow_backend_fd = -1;
    }
}

void session_table_init(void) {
    if (s_initialized) return;
    for (int s = 0; s < SESSION_SHARDS; s++) {
        pthread_mutex_init(&s_shards[s].mutex, NULL);
        memset(s_shards[s].nodes, 0, sizeof(s_shards[s].nodes));
        for (int i = 0; i < MAX_SESSIONS_PER_SHARD; i++) {
            s_shards[s].nodes[i].shadow_client_fd = -1;
            s_shards[s].nodes[i].shadow_backend_fd = -1;
        }
        memset(s_shards[s].buckets, 0, sizeof(s_shards[s].buckets));
        s_shards[s].active_count = 0;
    }
    atomic_store(&s_total_sessions, 0);
    s_initialized = true;
}

void session_table_clear(void) {
    if (!s_initialized) session_table_init();
    for (int s = 0; s < SESSION_SHARDS; s++) {
        pthread_mutex_lock(&s_shards[s].mutex);
        for (int i = 0; i < MAX_SESSIONS_PER_SHARD; i++) {
            if (s_shards[s].nodes[i].in_use) {
                close_node_shadow_fds(&s_shards[s].nodes[i]);
            }
        }
        memset(s_shards[s].nodes, 0, sizeof(s_shards[s].nodes));
        for (int i = 0; i < MAX_SESSIONS_PER_SHARD; i++) {
            s_shards[s].nodes[i].shadow_client_fd = -1;
            s_shards[s].nodes[i].shadow_backend_fd = -1;
        }
        memset(s_shards[s].buckets, 0, sizeof(s_shards[s].buckets));
        s_shards[s].active_count = 0;
        pthread_mutex_unlock(&s_shards[s].mutex);
    }
    atomic_store(&s_total_sessions, 0);
}

bool session_table_fill_wire(ClusterSessionWire *wire,
                             const struct sockaddr_storage *client_addr,
                             uint8_t proto,
                             bool use_port,
                             int backend_idx,
                             uint32_t remaining_ttl,
                             uint64_t version) {
    if (!wire || !client_addr || backend_idx < 0 || backend_idx >= g_num_backends) {
        return false;
    }
    uint8_t family = 0;
    uint8_t ip[16];
    uint16_t port = 0;
    if (!extract_client_key(client_addr, use_port, &family, ip, &port)) {
        return false;
    }

    memset(wire, 0, sizeof(*wire));
    wire->family = family;
    wire->proto = proto;
    wire->client_port = port;
    memcpy(wire->client_ip, ip, 16);
    strncpy(wire->backend_ip, g_backends[backend_idx].ip, sizeof(wire->backend_ip) - 1);
    wire->backend_port = htons((uint16_t)g_backends[backend_idx].port);
    wire->backend_idx = htons((uint16_t)backend_idx);
    wire->remaining_ttl = htonl(remaining_ttl > 0 ? remaining_ttl : DEFAULT_SESSION_TTL_SEC);
    wire->version = u64_to_net(version);
    return true;
}

static void fill_wire_from_node(ClusterSessionWire *wire, const SessionNode *node, time_t now) {
    memset(wire, 0, sizeof(*wire));
    wire->family = node->family;
    wire->proto = node->proto;
    wire->client_port = node->client_port;
    memcpy(wire->client_ip, node->client_ip, 16);
    memcpy(wire->backend_ip, node->backend_ip, sizeof(wire->backend_ip) - 1);
    wire->backend_ip[sizeof(wire->backend_ip) - 1] = '\0';
    wire->backend_port = htons(node->backend_port);
    wire->backend_idx = htons((uint16_t)(node->backend_idx >= 0 ? node->backend_idx : 0));

    uint32_t elapsed = (now > node->last_seen) ? (uint32_t)(now - node->last_seen) : 0;
    uint32_t rem = (node->ttl_sec > elapsed) ? (node->ttl_sec - elapsed) : 1;
    wire->remaining_ttl = htonl(rem);
    wire->version = u64_to_net(node->version);
}

static int lookup_raw_key(uint8_t family, uint8_t proto, const uint8_t ip[16], uint16_t port) {
    if (!s_initialized) session_table_init();

    uint32_t h = compute_key_hash(family, proto, ip, port);
    uint32_t shard_idx = h % SESSION_SHARDS;
    uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;

    SessionShard *shard = &s_shards[shard_idx];
    pthread_mutex_lock(&shard->mutex);

    SessionNode *node = shard_find_locked(shard, bucket_idx, family, proto, ip, port);
    if (!node) {
        pthread_mutex_unlock(&shard->mutex);
        return -1;
    }

    time_t now = time(NULL);
    if ((uint32_t)(now - node->last_seen) >= node->ttl_sec && node->shadow_client_fd < 0) {
        close_node_shadow_fds(node);
        shard_bucket_remove(shard, bucket_idx, node);
        node->in_use = false;
        shard->active_count--;
        atomic_fetch_sub_explicit(&s_total_sessions, 1, memory_order_relaxed);
        pthread_mutex_unlock(&shard->mutex);
        return -1;
    }

    int b_idx = node->backend_idx;
    if (b_idx < 0 || b_idx >= g_num_backends ||
        strcmp(g_backends[b_idx].ip, node->backend_ip) != 0 ||
        g_backends[b_idx].port != (int)node->backend_port) {
        b_idx = resolve_backend_index(node->backend_ip, node->backend_port, b_idx);
        node->backend_idx = b_idx;
    }

    if (b_idx < 0 || b_idx >= g_num_backends ||
        !atomic_load_explicit(&g_backends[b_idx].is_alive, memory_order_relaxed)) {
        close_node_shadow_fds(node);
        shard_bucket_remove(shard, bucket_idx, node);
        node->in_use = false;
        shard->active_count--;
        atomic_fetch_sub_explicit(&s_total_sessions, 1, memory_order_relaxed);
        pthread_mutex_unlock(&shard->mutex);
        return -1;
    }

    node->last_seen = now;
    bool need_refresh_sync = false;
    ClusterSessionWire refresh_wire;
    if (g_config.enable_cluster && (now - node->last_replicated) >= 5) {
        node->last_replicated = now;
        node->version = atomic_fetch_add_explicit(&s_version_counter, 1, memory_order_relaxed);
        fill_wire_from_node(&refresh_wire, node, now);
        need_refresh_sync = true;
    }

    pthread_mutex_unlock(&shard->mutex);

    if (need_refresh_sync) {
        cluster_queue_session_upsert(&refresh_wire);
    }
    return b_idx;
}

int session_table_lookup(const struct sockaddr_storage *client_addr, uint8_t proto, bool use_port) {
    uint8_t family = 0;
    uint8_t ip[16];
    uint16_t port = 0;
    if (!extract_client_key(client_addr, use_port, &family, ip, &port)) {
        return -1;
    }
    return lookup_raw_key(family, proto, ip, port);
}

int session_table_lookup_token(const char *token, size_t token_len) {
    if (!token || token_len == 0) return -1;
    uint8_t ip[16];
    extract_token_key(token, token_len, ip);
    return lookup_raw_key(WIRE_FAMILY_TOKEN, SESSION_PROTO_TCP, ip, 0);
}

static SessionNode *shard_alloc_slot_locked(SessionShard *shard, time_t now) {
    int free_idx = -1;
    int expired_idx = -1;
    int oldest_idx = 0;
    time_t oldest_seen = now + 1;

    for (int i = 0; i < MAX_SESSIONS_PER_SHARD; i++) {
        if (!shard->nodes[i].in_use) {
            free_idx = i;
            break;
        }
        if ((uint32_t)(now - shard->nodes[i].last_seen) >= shard->nodes[i].ttl_sec) {
            if (expired_idx == -1) expired_idx = i;
        }
        if (shard->nodes[i].last_seen < oldest_seen) {
            oldest_seen = shard->nodes[i].last_seen;
            oldest_idx = i;
        }
    }

    int chosen = (free_idx != -1) ? free_idx : ((expired_idx != -1) ? expired_idx : oldest_idx);
    SessionNode *slot = &shard->nodes[chosen];
    if (slot->in_use) {
        close_node_shadow_fds(slot);
        uint32_t old_h = compute_key_hash(slot->family, slot->proto, slot->client_ip, slot->client_port);
        uint32_t old_bucket = (old_h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;
        shard_bucket_remove(shard, old_bucket, slot);
        slot->in_use = false;
        shard->active_count--;
        atomic_fetch_sub_explicit(&s_total_sessions, 1, memory_order_relaxed);
    }
    return slot;
}

static void upsert_raw_key(uint8_t family,
                           uint8_t proto,
                           const uint8_t ip[16],
                           uint16_t port,
                           int backend_idx,
                           uint32_t ttl_sec,
                           bool replicate) {
    if (!s_initialized) session_table_init();
    if (backend_idx < 0 || backend_idx >= g_num_backends) return;

    if (ttl_sec == 0) {
        ttl_sec = (g_config.session_ttl_sec > 0) ? (uint32_t)g_config.session_ttl_sec : DEFAULT_SESSION_TTL_SEC;
    }

    uint32_t h = compute_key_hash(family, proto, ip, port);
    uint32_t shard_idx = h % SESSION_SHARDS;
    uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;

    SessionShard *shard = &s_shards[shard_idx];
    time_t now = time(NULL);
    ClusterSessionWire wire_to_send;
    bool do_send = false;

    pthread_mutex_lock(&shard->mutex);

    SessionNode *node = shard_find_locked(shard, bucket_idx, family, proto, ip, port);
    bool is_new_or_changed = false;

    if (!node) {
        node = shard_alloc_slot_locked(shard, now);
        memset(node, 0, sizeof(*node));
        node->shadow_client_fd = -1;
        node->shadow_backend_fd = -1;
        node->in_use = true;
        node->family = family;
        node->proto = proto;
        node->client_port = port;
        memcpy(node->client_ip, ip, 16);
        node->hash_next = shard->buckets[bucket_idx];
        shard->buckets[bucket_idx] = node;
        shard->active_count++;
        atomic_fetch_add_explicit(&s_total_sessions, 1, memory_order_relaxed);
        is_new_or_changed = true;
    } else if (node->backend_idx != backend_idx ||
               node->backend_port != (uint16_t)g_backends[backend_idx].port ||
               strcmp(node->backend_ip, g_backends[backend_idx].ip) != 0) {
        is_new_or_changed = true;
    }

    strncpy(node->backend_ip, g_backends[backend_idx].ip, sizeof(node->backend_ip) - 1);
    node->backend_ip[sizeof(node->backend_ip) - 1] = '\0';
    node->backend_port = (uint16_t)g_backends[backend_idx].port;
    node->backend_idx = backend_idx;
    node->last_seen = now;
    node->ttl_sec = ttl_sec;

    if (replicate && g_config.enable_cluster &&
        (is_new_or_changed || (now - node->last_replicated) >= 5)) {
        node->last_replicated = now;
        node->version = atomic_fetch_add_explicit(&s_version_counter, 1, memory_order_relaxed);
        fill_wire_from_node(&wire_to_send, node, now);
        do_send = true;
    }

    pthread_mutex_unlock(&shard->mutex);

    if (do_send) {
        cluster_queue_session_upsert(&wire_to_send);
    }
}

void session_table_upsert_local(const struct sockaddr_storage *client_addr,
                                uint8_t proto,
                                bool use_port,
                                int backend_idx,
                                uint32_t ttl_sec,
                                bool replicate) {
    if (!client_addr) return;
    uint8_t family = 0;
    uint8_t ip[16];
    uint16_t port = 0;
    if (!extract_client_key(client_addr, use_port, &family, ip, &port)) return;
    upsert_raw_key(family, proto, ip, port, backend_idx, ttl_sec, replicate);
}

void session_table_upsert_token(const char *token,
                                size_t token_len,
                                int backend_idx,
                                uint32_t ttl_sec,
                                bool replicate) {
    if (!token || token_len == 0) return;
    uint8_t ip[16];
    extract_token_key(token, token_len, ip);
    upsert_raw_key(WIRE_FAMILY_TOKEN, SESSION_PROTO_TCP, ip, 0, backend_idx, ttl_sec, replicate);
}

void session_table_remove_client(const struct sockaddr_storage *client_addr,
                                 uint8_t proto,
                                 bool use_port,
                                 bool replicate) {
    if (!s_initialized) session_table_init();
    uint8_t family = 0;
    uint8_t ip[16];
    uint16_t port = 0;
    if (!extract_client_key(client_addr, use_port, &family, ip, &port)) return;

    uint32_t h = compute_key_hash(family, proto, ip, port);
    uint32_t shard_idx = h % SESSION_SHARDS;
    uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;

    SessionShard *shard = &s_shards[shard_idx];
    ClusterSessionWire wire_del;
    bool found = false;

    pthread_mutex_lock(&shard->mutex);
    SessionNode *node = shard_find_locked(shard, bucket_idx, family, proto, ip, port);
    if (node) {
        fill_wire_from_node(&wire_del, node, time(NULL));
        close_node_shadow_fds(node);
        shard_bucket_remove(shard, bucket_idx, node);
        node->in_use = false;
        shard->active_count--;
        atomic_fetch_sub_explicit(&s_total_sessions, 1, memory_order_relaxed);
        found = true;
    }
    pthread_mutex_unlock(&shard->mutex);

    if (found && replicate && g_config.enable_cluster) {
        cluster_queue_session_delete(&wire_del);
    }
}

bool session_table_apply_remote(const ClusterSessionWire *wire) {
    if (!s_initialized) session_table_init();
    if (!wire) return false;

    uint8_t family = wire->family;
    if (family != WIRE_FAMILY_IPV4 && family != WIRE_FAMILY_IPV6 && family != WIRE_FAMILY_TOKEN) return false;
    uint8_t proto = wire->proto;
    uint16_t port = wire->client_port;

    uint16_t b_port = ntohs(wire->backend_port);
    int hint_idx = (int)ntohs(wire->backend_idx);
    uint32_t rem_ttl = ntohl(wire->remaining_ttl);
    if (rem_ttl == 0) rem_ttl = DEFAULT_SESSION_TTL_SEC;
    if (rem_ttl > 86400) rem_ttl = 86400;
    uint64_t ver = net_to_u64(wire->version);

    char safe_bip[46];
    memcpy(safe_bip, wire->backend_ip, sizeof(safe_bip) - 1);
    safe_bip[sizeof(safe_bip) - 1] = '\0';

    int resolved_idx = resolve_backend_index(safe_bip, b_port, hint_idx);

    uint32_t h = compute_key_hash(family, proto, wire->client_ip, port);
    uint32_t shard_idx = h % SESSION_SHARDS;
    uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;

    SessionShard *shard = &s_shards[shard_idx];
    time_t now = time(NULL);

    pthread_mutex_lock(&shard->mutex);
    SessionNode *node = shard_find_locked(shard, bucket_idx, family, proto, wire->client_ip, port);
    if (!node) {
        node = shard_alloc_slot_locked(shard, now);
        memset(node, 0, sizeof(*node));
        node->shadow_client_fd = -1;
        node->shadow_backend_fd = -1;
        node->in_use = true;
        node->family = family;
        node->proto = proto;
        node->client_port = port;
        memcpy(node->client_ip, wire->client_ip, 16);
        node->hash_next = shard->buckets[bucket_idx];
        shard->buckets[bucket_idx] = node;
        shard->active_count++;
        atomic_fetch_add_explicit(&s_total_sessions, 1, memory_order_relaxed);
    }

    strncpy(node->backend_ip, safe_bip, sizeof(node->backend_ip) - 1);
    node->backend_ip[sizeof(node->backend_ip) - 1] = '\0';
    node->backend_port = b_port;
    node->backend_idx = resolved_idx;
    node->last_seen = now;
    node->last_replicated = now;
    node->ttl_sec = rem_ttl;
    node->version = ver;

    pthread_mutex_unlock(&shard->mutex);
    return true;
}

bool session_table_delete_remote(const ClusterSessionWire *wire) {
    if (!s_initialized) session_table_init();
    if (!wire) return false;

    uint8_t family = wire->family;
    if (family != WIRE_FAMILY_IPV4 && family != WIRE_FAMILY_IPV6 && family != WIRE_FAMILY_TOKEN) return false;

    uint32_t h = compute_key_hash(family, wire->proto, wire->client_ip, wire->client_port);
    uint32_t shard_idx = h % SESSION_SHARDS;
    uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;

    SessionShard *shard = &s_shards[shard_idx];
    bool deleted = false;

    pthread_mutex_lock(&shard->mutex);
    SessionNode *node = shard_find_locked(shard, bucket_idx, family, wire->proto, wire->client_ip, wire->client_port);
    if (node) {
        close_node_shadow_fds(node);
        shard_bucket_remove(shard, bucket_idx, node);
        node->in_use = false;
        shard->active_count--;
        atomic_fetch_sub_explicit(&s_total_sessions, 1, memory_order_relaxed);
        deleted = true;
    }
    pthread_mutex_unlock(&shard->mutex);
    return deleted;
}

static bool is_shadow_fd_closed(int fd) {
    if (fd < 0) return true;
    char probe = 0;
    ssize_t r = recv(fd, &probe, 1, MSG_PEEK | MSG_DONTWAIT);
    if (r == 0) return true;
    if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        return true;
    }
    return false;
}

int session_table_cleanup_expired(void) {
    if (!s_initialized) return 0;
    time_t now = time(NULL);
    int purged = 0;

    for (int s = 0; s < SESSION_SHARDS; s++) {
        SessionShard *shard = &s_shards[s];
        pthread_mutex_lock(&shard->mutex);
        for (int i = 0; i < MAX_SESSIONS_PER_SHARD; i++) {
            SessionNode *node = &shard->nodes[i];
            if (!node->in_use) continue;
            bool expired = ((uint32_t)(now - node->last_seen) >= node->ttl_sec);
            bool dead_shadow = (node->shadow_client_fd >= 0 && is_shadow_fd_closed(node->shadow_client_fd));
            if (expired || dead_shadow) {
                close_node_shadow_fds(node);
                uint32_t h = compute_key_hash(node->family, node->proto, node->client_ip, node->client_port);
                uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;
                shard_bucket_remove(shard, bucket_idx, node);
                node->in_use = false;
                shard->active_count--;
                atomic_fetch_sub_explicit(&s_total_sessions, 1, memory_order_relaxed);
                purged++;
            }
        }
        pthread_mutex_unlock(&shard->mutex);
    }
    return purged;
}

bool session_table_store_shadow_fds(const struct sockaddr_storage *client_addr,
                                    uint8_t proto,
                                    int backend_idx,
                                    int shadow_client_fd,
                                    int shadow_backend_fd,
                                    const char *initial_req,
                                    uint16_t req_len,
                                    uint64_t bytes_to_client) {
    if (!s_initialized) session_table_init();
    if (!client_addr) {
        if (shadow_client_fd >= 0) close(shadow_client_fd);
        if (shadow_backend_fd >= 0) close(shadow_backend_fd);
        return false;
    }

    if (cluster_get_state() == VRRP_STATE_MASTER && shadow_client_fd >= 0) {
        worker_pool_adopt_migrated_conn(shadow_client_fd, shadow_backend_fd, backend_idx,
                                        client_addr, initial_req, req_len, bytes_to_client);
        return true;
    }

    uint8_t family = 0;
    uint8_t ip[16];
    uint16_t port = 0;
    if (!extract_client_key(client_addr, true, &family, ip, &port)) {
        if (shadow_client_fd >= 0) close(shadow_client_fd);
        if (shadow_backend_fd >= 0) close(shadow_backend_fd);
        return false;
    }

    uint32_t h = compute_key_hash(family, proto, ip, port);
    uint32_t shard_idx = h % SESSION_SHARDS;
    uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;

    SessionShard *shard = &s_shards[shard_idx];
    time_t now = time(NULL);

    pthread_mutex_lock(&shard->mutex);
    SessionNode *node = shard_find_locked(shard, bucket_idx, family, proto, ip, port);
    if (!node) {
        node = shard_alloc_slot_locked(shard, now);
        memset(node, 0, sizeof(*node));
        node->shadow_client_fd = -1;
        node->shadow_backend_fd = -1;
        node->in_use = true;
        node->family = family;
        node->proto = proto;
        node->client_port = port;
        memcpy(node->client_ip, ip, 16);
        node->hash_next = shard->buckets[bucket_idx];
        shard->buckets[bucket_idx] = node;
        shard->active_count++;
        atomic_fetch_add_explicit(&s_total_sessions, 1, memory_order_relaxed);
    }

    if (shadow_client_fd >= 0) {
        if (node->shadow_client_fd >= 0 && node->shadow_client_fd != shadow_client_fd) {
            close(node->shadow_client_fd);
        }
        node->shadow_client_fd = shadow_client_fd;
    }
    if (shadow_backend_fd >= 0) {
        if (node->shadow_backend_fd >= 0 && node->shadow_backend_fd != shadow_backend_fd) {
            close(node->shadow_backend_fd);
        }
        node->shadow_backend_fd = shadow_backend_fd;
    }

    if (backend_idx >= 0 && backend_idx < g_num_backends) {
        node->backend_idx = backend_idx;
        strncpy(node->backend_ip, g_backends[backend_idx].ip, sizeof(node->backend_ip) - 1);
        node->backend_port = (uint16_t)g_backends[backend_idx].port;
    }
    node->bytes_to_client = bytes_to_client;
    if (initial_req && req_len > 0) {
        if (req_len > sizeof(node->initial_req)) req_len = sizeof(node->initial_req);
        memcpy(node->initial_req, initial_req, req_len);
        node->req_len = req_len;
    }
    node->last_seen = now;
    node->ttl_sec = (g_config.session_ttl_sec > 0) ? (uint32_t)g_config.session_ttl_sec : DEFAULT_SESSION_TTL_SEC;

    pthread_mutex_unlock(&shard->mutex);
    return true;
}

bool session_table_store_tcp_checkpoint(const ClusterTcpCheckpointWire *wire) {
    if (!s_initialized) session_table_init();
    if (!wire) return false;

    TcpSocketCheckpoint cp;
    int b_idx = -1;
    char b_ip[46];
    uint16_t b_port = 0;
    uint64_t bytes_to_client = 0;
    char initial_req[512];
    uint16_t req_len = 0;

    tcp_checkpoint_from_wire(wire, &cp, &b_idx, b_ip, &b_port, &bytes_to_client, initial_req, &req_len);

    uint8_t family = (wire->family == AF_INET6) ? WIRE_FAMILY_IPV6 : WIRE_FAMILY_IPV4;
    uint8_t proto = SESSION_PROTO_TCP;
    uint16_t port = wire->client_port;

    uint32_t h = compute_key_hash(family, proto, wire->client_ip, port);
    uint32_t shard_idx = h % SESSION_SHARDS;
    uint32_t bucket_idx = (h / SESSION_SHARDS) % SESSION_BUCKETS_PER_SHARD;

    SessionShard *shard = &s_shards[shard_idx];
    time_t now = time(NULL);

    pthread_mutex_lock(&shard->mutex);
    SessionNode *node = shard_find_locked(shard, bucket_idx, family, proto, wire->client_ip, port);
    if (!node) {
        node = shard_alloc_slot_locked(shard, now);
        memset(node, 0, sizeof(*node));
        node->shadow_client_fd = -1;
        node->shadow_backend_fd = -1;
        node->in_use = true;
        node->family = family;
        node->proto = proto;
        node->client_port = port;
        memcpy(node->client_ip, wire->client_ip, 16);
        node->hash_next = shard->buckets[bucket_idx];
        shard->buckets[bucket_idx] = node;
        shard->active_count++;
        atomic_fetch_add_explicit(&s_total_sessions, 1, memory_order_relaxed);
    }

    int resolved_idx = resolve_backend_index(b_ip, b_port, b_idx);
    node->backend_idx = resolved_idx;
    snprintf(node->backend_ip, sizeof(node->backend_ip), "%s", b_ip);
    node->backend_port = b_port;
    node->has_tcp_checkpoint = true;
    node->checkpoint = cp;
    node->bytes_to_client = bytes_to_client;
    if (req_len > 0) {
        if (req_len > sizeof(node->initial_req)) req_len = sizeof(node->initial_req);
        memcpy(node->initial_req, initial_req, req_len);
        node->req_len = req_len;
    }
    node->last_seen = now;
    node->ttl_sec = (g_config.session_ttl_sec > 0) ? (uint32_t)g_config.session_ttl_sec : DEFAULT_SESSION_TTL_SEC;

    pthread_mutex_unlock(&shard->mutex);

    char cip[INET6_ADDRSTRLEN] = {0};
    int af = (wire->family == AF_INET6) ? AF_INET6 : AF_INET;
    inet_ntop(af, wire->client_ip, cip, sizeof(cip));
    uint16_t cport = ntohs(wire->client_port);
    add_log("\033[1;36m[HA CHECKPOINT RX]\033[0m Stored TCP checkpoint for %s:%u (kTLS=%s, snd_seq=%u)",
            cip, (unsigned int)cport, cp.is_ktls ? "\033[1;32mYES\033[0m" : "\033[1;33mNO\033[0m", cp.snd_seq);

    return true;
}

int session_table_promote_shadow_conns(void) {
    if (!s_initialized) return 0;
    int promoted = 0;

    for (int s = 0; s < SESSION_SHARDS; s++) {
        SessionShard *shard = &s_shards[s];
        for (int i = 0; i < MAX_SESSIONS_PER_SHARD; i++) {
            int cfd = -1;
            int bfd = -1;
            int b_idx = -1;
            uint64_t bytes_sent = 0;
            uint16_t req_len = 0;
            char req_copy[512];
            struct sockaddr_storage client_addr;

            pthread_mutex_lock(&shard->mutex);
            SessionNode *node = &shard->nodes[i];
            if (node->in_use) {
                if (node->shadow_client_fd >= 0) {
                    cfd = node->shadow_client_fd;
                    bfd = node->shadow_backend_fd;
                    node->shadow_client_fd = -1;
                    node->shadow_backend_fd = -1;
                } else if (node->has_tcp_checkpoint) {
                    bool was_ktls = node->checkpoint.is_ktls;
                    cfd = tcp_repair_restore(&node->checkpoint);
                    bfd = -1;
                    node->has_tcp_checkpoint = false;
                    add_log("\033[1;34m[HA RESTORE]\033[0m Restored live stream (fd=%d, kTLS=%s)",
                            cfd, was_ktls ? "\033[1;32mYES\033[0m" : "\033[1;33mNO\033[0m");
                }

                if (cfd >= 0) {
                    b_idx = node->backend_idx;
                    if (b_idx < 0 || b_idx >= g_num_backends) {
                        b_idx = resolve_backend_index(node->backend_ip, node->backend_port, b_idx);
                        node->backend_idx = b_idx;
                    }
                    bytes_sent = node->bytes_to_client;
                    req_len = node->req_len;
                    if (req_len > sizeof(req_copy)) req_len = sizeof(req_copy);
                    if (req_len > 0) {
                        memcpy(req_copy, node->initial_req, req_len);
                    }

                    memset(&client_addr, 0, sizeof(client_addr));
                    if (node->family == WIRE_FAMILY_IPV6) {
                        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&client_addr;
                        s6->sin6_family = AF_INET6;
                        s6->sin6_port = node->client_port;
                        memcpy(&s6->sin6_addr, node->client_ip, 16);
                    } else {
                        struct sockaddr_in *s4 = (struct sockaddr_in *)&client_addr;
                        s4->sin_family = AF_INET;
                        s4->sin_port = node->client_port;
                        memcpy(&s4->sin_addr.s_addr, node->client_ip, 4);
                    }
                }
            }
            pthread_mutex_unlock(&shard->mutex);

            if (cfd >= 0) {
                if (is_shadow_fd_closed(cfd)) {
                    close(cfd);
                    if (bfd >= 0) close(bfd);
                } else {
                    worker_pool_adopt_migrated_conn(cfd, bfd, b_idx, &client_addr,
                                                    req_copy, req_len, bytes_sent);
                    promoted++;
                }
            }
        }
    }
    return promoted;
}

int session_table_count(void) {
    int c = atomic_load_explicit(&s_total_sessions, memory_order_relaxed);
    return (c >= 0) ? c : 0;
}

int session_table_export_snapshot(ClusterSessionWire *out_array, int max_entries) {
    if (!s_initialized || !out_array || max_entries <= 0) return 0;
    time_t now = time(NULL);
    int count = 0;

    for (int s = 0; s < SESSION_SHARDS && count < max_entries; s++) {
        SessionShard *shard = &s_shards[s];
        pthread_mutex_lock(&shard->mutex);
        for (int i = 0; i < MAX_SESSIONS_PER_SHARD && count < max_entries; i++) {
            SessionNode *node = &shard->nodes[i];
            if (node->in_use && (uint32_t)(now - node->last_seen) < node->ttl_sec) {
                fill_wire_from_node(&out_array[count++], node, now);
            }
        }
        pthread_mutex_unlock(&shard->mutex);
    }
    return count;
}

