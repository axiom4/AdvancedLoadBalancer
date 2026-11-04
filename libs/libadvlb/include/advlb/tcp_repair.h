#ifndef ADVLB_TCP_REPAIR_H
#define ADVLB_TCP_REPAIR_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

#define KTLS_CIPHER_NONE        0
#define KTLS_CIPHER_AES_GCM_128 51
#define KTLS_CIPHER_AES_GCM_256 52

#define KTLS_VERSION_1_2 0x0303
#define KTLS_VERSION_1_3 0x0304

typedef struct {
    uint16_t tls_version;     /* KTLS_VERSION_1_2 or KTLS_VERSION_1_3 */
    uint16_t cipher_type;     /* KTLS_CIPHER_AES_GCM_128 or 256 */
    uint8_t  tx_iv[8];
    uint8_t  tx_key[32];
    uint8_t  tx_salt[4];
    uint8_t  tx_rec_seq[8];
    uint8_t  rx_iv[8];
    uint8_t  rx_key[32];
    uint8_t  rx_salt[4];
    uint8_t  rx_rec_seq[8];
} KtlsCryptoCheckpoint;

typedef struct {
    struct sockaddr_storage local_addr;
    struct sockaddr_storage remote_addr;
    uint32_t snd_seq;
    uint32_t rcv_seq;
    uint32_t snd_wnd;
    uint32_t rcv_wnd;
    uint32_t mss_clamp;
    uint8_t  snd_wscale;
    uint8_t  rcv_wscale;
    bool     has_timestamps;
    uint32_t ts_val;
    uint32_t ts_ecr;
    bool     is_ktls;
    KtlsCryptoCheckpoint ktls;
} TcpSocketCheckpoint;

/* Wire format for cross-node replication over UDP cluster mesh */
typedef struct __attribute__((packed)) {
    uint8_t  family;          /* AF_INET or AF_INET6 */
    uint8_t  proto;           /* IPPROTO_TCP (6) */
    uint16_t client_port;     /* Network byte order */
    uint8_t  client_ip[16];   /* IPv4 in [0..3], IPv6 in [0..15] */
    uint16_t local_port;      /* Network byte order */
    uint8_t  local_ip[16];    /* VIP in bytes */
    
    char     backend_ip[46];  /* Null-terminated target backend IP */
    uint16_t backend_port;    /* Network byte order */
    uint16_t backend_idx;     /* Network byte order hint */

    uint32_t snd_seq;         /* Network byte order */
    uint32_t rcv_seq;         /* Network byte order */
    uint32_t snd_wnd;         /* Network byte order */
    uint32_t rcv_wnd;         /* Network byte order */
    uint32_t mss_clamp;       /* Network byte order */
    uint8_t  snd_wscale;
    uint8_t  rcv_wscale;
    uint8_t  flags;           /* Bit 0: has_ts, Bit 1: is_ktls */
    uint8_t  reserved;
    uint32_t ts_val;          /* Network byte order */
    uint32_t ts_ecr;          /* Network byte order */

    uint64_t bytes_to_client; /* Network byte order */
    uint16_t initial_req_len; /* Network byte order */
    char     initial_req[512];

    /* kTLS payload */
    uint16_t tls_version;     /* Network byte order */
    uint16_t cipher_type;     /* Network byte order */
    uint8_t  tx_iv[8];
    uint8_t  tx_key[32];
    uint8_t  tx_salt[4];
    uint8_t  tx_rec_seq[8];
    uint8_t  rx_iv[8];
    uint8_t  rx_key[32];
    uint8_t  rx_salt[4];
    uint8_t  rx_rec_seq[8];
} ClusterTcpCheckpointWire;

/* Check if TCP_REPAIR and/or kTLS are supported by current kernel */
bool tcp_repair_is_supported(void);
bool ktls_is_supported(void);

/* Capture in-flight TCP (and optional kTLS) state from an active established socket */
bool tcp_repair_checkpoint(int sock_fd, void *ssl_ptr, TcpSocketCheckpoint *out_cp);

/* Recreate and restore an established socket on the destination machine */
int tcp_repair_restore(const TcpSocketCheckpoint *cp);

/* Send TLS close_notify alert over kTLS socket */
bool ktls_send_close_notify(int fd);

/* Encode/Decode wire format */
void tcp_checkpoint_to_wire(const TcpSocketCheckpoint *cp,
                            int backend_idx,
                            const char *backend_ip,
                            uint16_t backend_port,
                            uint64_t bytes_to_client,
                            const char *initial_req,
                            uint16_t req_len,
                            ClusterTcpCheckpointWire *wire);

void tcp_checkpoint_from_wire(const ClusterTcpCheckpointWire *wire,
                              TcpSocketCheckpoint *out_cp,
                              int *out_backend_idx,
                              char *out_backend_ip,
                              uint16_t *out_backend_port,
                              uint64_t *out_bytes_to_client,
                              char *out_initial_req,
                              uint16_t *out_req_len);

#ifdef __cplusplus
}
#endif

#endif /* ADVLB_TCP_REPAIR_H */

