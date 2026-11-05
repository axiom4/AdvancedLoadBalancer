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
    uint32_t max_window;
    uint32_t snd_wl1;
    uint32_t rcv_wup;
    uint32_t mss_clamp;
    uint8_t  snd_wscale;
    uint8_t  rcv_wscale;
    bool     has_timestamps;
    bool     is_ktls;
    uint32_t ts_val;
    uint32_t ts_ecr;
    KtlsCryptoCheckpoint ktls;
    /* Kernel queues: without them, ACKed-but-unread client bytes and unACKed response bytes are lost */
    uint32_t snd_queue_len;   /* write_seq - snd_una: bytes the peer has not ACKed yet */
    uint32_t snd_unsent_len;  /* tail of the send queue never transmitted */
    uint32_t rcv_queue_len;   /* received and ACKed, not yet read by the proxy */
    uint8_t *queue_data;      /* heap: send queue bytes then receive queue bytes */
} TcpSocketCheckpoint;

/* Max queue payload carried by one checkpoint datagram (fits a 64 KB UDP datagram with headers) */
#define TCP_CHECKPOINT_QUEUE_MAX 60000

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
    uint32_t max_window;      /* Network byte order */
    uint32_t snd_wl1;         /* Network byte order */
    uint32_t rcv_wup;         /* Network byte order */
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

    uint32_t snd_queue_len;   /* Network byte order */
    uint32_t snd_unsent_len;  /* Network byte order */
    uint32_t rcv_queue_len;   /* Network byte order */
    uint8_t  queue_data[TCP_CHECKPOINT_QUEUE_MAX]; /* Only snd_queue_len + rcv_queue_len bytes are sent */
} ClusterTcpCheckpointWire;

/* Bytes of the wire struct actually used (variable-length queue tail) */
size_t tcp_checkpoint_wire_len(const ClusterTcpCheckpointWire *wire);

/* Free heap queue data owned by a checkpoint */
void tcp_checkpoint_release(TcpSocketCheckpoint *cp);

/* Proxy-level state of a stream migrated together with its backend socket (heap, single owner) */
#define MIGRATED_F_KEEPALIVE      0x01
#define MIGRATED_F_CLIENT_SHUT_WR 0x02
#define MIGRATED_F_BACKEND_SHUT_WR 0x04
#define MIGRATED_F_CLIENT_CLOSED  0x08
#define MIGRATED_F_BACKEND_CLOSED 0x10

typedef struct {
    bool     has_backend;
    TcpSocketCheckpoint backend;  /* owns backend.queue_data */
    uint8_t *c2b;                 /* client bytes read by the proxy, not yet written to the backend */
    uint32_t c2b_len;
    uint8_t *b2c;                 /* backend bytes read by the proxy, not yet written to the client */
    uint32_t b2c_len;
    uint64_t bytes_to_backend;
    uint64_t bytes_from_backend;
    uint64_t skip_backend_bytes;
    uint8_t  flags;               /* MIGRATED_F_* */
} MigratedStreamState;

/* Free a MigratedStreamState and everything it owns (NULL-safe) */
void migrated_stream_release(MigratedStreamState *st);

/* Check if TCP_REPAIR and/or kTLS are supported by current kernel */
bool tcp_repair_is_supported(void);
bool ktls_is_supported(void);

/* Capture in-flight TCP (and optional kTLS) state from an active established socket */
/* A kTLS socket is only captured when final (handover): toggling TCP_REPAIR on a live kTLS socket
 * desynchronises its RX record parser (EMSGSIZE / "packet length too long"). */
bool tcp_repair_checkpoint(int sock_fd, void *ssl_ptr, TcpSocketCheckpoint *out_cp, bool final);

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

