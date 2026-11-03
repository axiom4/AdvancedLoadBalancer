#ifndef ADVLB_SESSION_TABLE_H
#define ADVLB_SESSION_TABLE_H

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SESSION_PROTO_TCP 6
#define SESSION_PROTO_UDP 17

#define MAX_CLUSTER_SESSIONS 16384
#define DEFAULT_SESSION_TTL_SEC 300

/* Wire format for network replication of a single session (packed, endian-safe) */
typedef struct __attribute__((packed)) {
    uint8_t  family;          /* AF_INET (2) or AF_INET6 (10/30 normalized to 4/6 on wire) */
    uint8_t  proto;           /* SESSION_PROTO_TCP (6) or SESSION_PROTO_UDP (17) */
    uint16_t client_port;     /* Network byte order (0 for IP-level sticky session) */
    uint8_t  client_ip[16];   /* IPv4 in bytes [0..3], IPv6 in [0..15] */
    char     backend_ip[46];  /* Null-terminated IPv4/IPv6 string of target backend */
    uint16_t backend_port;    /* Network byte order */
    uint16_t backend_idx;     /* Network byte order hint */
    uint32_t remaining_ttl;   /* Network byte order (seconds remaining) */
    uint64_t version;         /* Network byte order monotonic version */
} ClusterSessionWire;

void session_table_init(void);
void session_table_clear(void);

/* Lookup active session for a client. Returns backend_idx (>= 0) if found and backend is alive, else -1 */
int session_table_lookup(const struct sockaddr_storage *client_addr, uint8_t proto, bool use_port);

/* Lookup active L7 session by token (e.g. Cookie or X-Session-ID). Returns backend_idx (>= 0) or -1 */
int session_table_lookup_token(const char *token, size_t token_len);

/* Create or update an L7 token session locally and optionally replicate it to cluster peers */
void session_table_upsert_token(const char *token,
                                size_t token_len,
                                int backend_idx,
                                uint32_t ttl_sec,
                                bool replicate);

/* Create or update a session locally and optionally queue it for cluster replication */
void session_table_upsert_local(const struct sockaddr_storage *client_addr,
                                uint8_t proto,
                                bool use_port,
                                int backend_idx,
                                uint32_t ttl_sec,
                                bool replicate);

/* Remove a session locally and optionally replicate the deletion */
void session_table_remove_client(const struct sockaddr_storage *client_addr,
                                 uint8_t proto,
                                 bool use_port,
                                 bool replicate);

/* Apply a replicated session update received from another cluster node */
bool session_table_apply_remote(const ClusterSessionWire *wire);

/* Apply a replicated session deletion received from another cluster node */
bool session_table_delete_remote(const ClusterSessionWire *wire);

/* Purge expired sessions across all shards; returns number of purged sessions */
int session_table_cleanup_expired(void);

/* Return total number of active sessions in the table */
int session_table_count(void);

/* Export active sessions into wire format for bulk synchronization */
int session_table_export_snapshot(ClusterSessionWire *out_array, int max_entries);

/* Encode a single client+backend into wire format */
bool session_table_fill_wire(ClusterSessionWire *wire,
                             const struct sockaddr_storage *client_addr,
                             uint8_t proto,
                             bool use_port,
                             int backend_idx,
                             uint32_t remaining_ttl,
                             uint64_t version);

/* Store replicated live shadow sockets (SCM_RIGHTS) on a BACKUP node for zero-drop failover */
bool session_table_store_shadow_fds(const struct sockaddr_storage *client_addr,
                                    uint8_t proto,
                                    int backend_idx,
                                    int shadow_client_fd,
                                    int shadow_backend_fd,
                                    const char *initial_req,
                                    uint16_t req_len,
                                    uint64_t bytes_to_client);

/* Promote all passive shadow sockets into the active worker pool upon becoming VRRP MASTER */
int session_table_promote_shadow_conns(void);

#ifdef __cplusplus
}
#endif

#endif /* ADVLB_SESSION_TABLE_H */

