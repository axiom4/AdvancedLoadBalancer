#ifndef ADVLB_CLUSTER_H
#define ADVLB_CLUSTER_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "advlb/session_table.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_CLUSTER_PEERS 16
#define DEFAULT_CLUSTER_PORT 9550
#define VRRP_MULTICAST_GROUP "224.0.0.18"
#define CLUSTER_MAX_BATCH_SESSIONS 16
#define CLUSTER_HMAC_LEN 32

typedef enum {
    VRRP_STATE_DISABLED = 0,
    VRRP_STATE_INIT     = 1,
    VRRP_STATE_BACKUP   = 2,
    VRRP_STATE_MASTER   = 3
} VrrpState;

typedef struct {
    char ip[64];
    int port;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uint32_t node_id;
    uint8_t state;
    uint8_t base_priority;
    uint8_t effective_priority;
    uint64_t last_seen_ms;
    uint64_t last_seq;
    bool is_reachable;
} ClusterPeer;

/* Initialize cluster subsystem state */
void cluster_init(void);

/* Add a unicast peer ("IP:PORT" or "IP") to the cluster mesh */
bool cluster_add_peer(const char *ip_port);

/* Clear all configured cluster peers */
void cluster_clear_peers(void);

/* Start the VRRP & Session Replication background engine */
bool cluster_start(void);
bool cluster_start_with_socket(int custom_dgram_fd);

/* Stop the cluster engine, send priority-0 release if MASTER, and remove VIP */
void cluster_stop(void);

/* Query current VRRP state of this node */
VrrpState cluster_get_state(void);
const char *cluster_state_name(VrrpState state);

/* Return true if the Virtual IP is currently bound on this node */
bool cluster_is_vip_active(void);

/* Get count of currently reachable peers (and optionally total configured/discovered peers) */
int cluster_get_alive_peers(int *out_total_peers);

/* Get unique 32-bit node ID of this instance and of the current elected Master */
uint32_t cluster_get_node_id(void);
uint32_t cluster_get_current_master_id(void);

/* Manually trigger a graceful stepdown from MASTER to BACKUP (for maintenance or TUI '[C]' test) */
void cluster_trigger_stepdown(void);

/* Queue an asynchronous session upsert or delete for real-time broadcast to peers */
void cluster_queue_session_upsert(const ClusterSessionWire *wire);
void cluster_queue_session_delete(const ClusterSessionWire *wire);

/* Request an immediate bulk session synchronization from current cluster peers */
void cluster_request_bulk_sync(void);

/* Replicate live active TCP connection descriptors and stream offset to cluster peers */
void cluster_replicate_live_conn(const struct sockaddr_storage *client_addr,
                                 int backend_idx,
                                 int client_fd,
                                 int backend_fd,
                                 const char *initial_req,
                                 uint16_t req_len,
                                 uint64_t bytes_to_client);

/* Notify cluster peers that an active TCP connection closed normally */
void cluster_notify_conn_closed(const struct sockaddr_storage *client_addr, int backend_idx);

/* Telemetry counters */
uint64_t cluster_get_tx_packets(void);
uint64_t cluster_get_rx_packets(void);
uint64_t cluster_get_synced_sessions_count(void);
uint64_t cluster_get_failover_count(void);

#ifdef __cplusplus
}
#endif

#endif /* ADVLB_CLUSTER_H */
