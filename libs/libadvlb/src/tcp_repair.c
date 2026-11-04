#include "advlb/tcp_repair.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>

#ifdef __linux__
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/types.h>

#ifndef TCP_REPAIR
#define TCP_REPAIR 19
#endif
#ifndef TCP_REPAIR_QUEUE
#define TCP_REPAIR_QUEUE 20
#endif
#ifndef TCP_QUEUE_SEQ
#define TCP_QUEUE_SEQ 21
#endif
#ifndef TCP_REPAIR_OPTIONS
#define TCP_REPAIR_OPTIONS 22
#endif
#ifndef TCP_REPAIR_WINDOW
#define TCP_REPAIR_WINDOW 29
#endif
#ifndef TCP_NO_QUEUE
#define TCP_NO_QUEUE 0
#endif
#ifndef TCP_RECV_QUEUE
#define TCP_RECV_QUEUE 1
#endif
#ifndef TCP_SEND_QUEUE
#define TCP_SEND_QUEUE 2
#endif

#ifndef SOL_TCP
#define SOL_TCP 6
#endif

#ifndef SOL_TLS
#define SOL_TLS 282
#endif
#ifndef TLS_TX
#define TLS_TX 1
#endif
#ifndef TLS_RX
#define TLS_RX 2
#endif

struct adlb_tcp_repair_opt {
    uint32_t opt_code;
    uint32_t opt_val;
};

struct adlb_tls_crypto_info {
    uint16_t version;
    uint16_t cipher_type;
};

struct adlb_tls12_crypto_info_aes_gcm_128 {
    struct adlb_tls_crypto_info info;
    unsigned char iv[8];
    unsigned char key[16];
    unsigned char salt[4];
    unsigned char rec_seq[8];
};

struct adlb_tls12_crypto_info_aes_gcm_256 {
    struct adlb_tls_crypto_info info;
    unsigned char iv[8];
    unsigned char key[32];
    unsigned char salt[4];
    unsigned char rec_seq[8];
};
#endif /* __linux__ */

bool tcp_repair_is_supported(void) {
#ifdef __linux__
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return false;
    int val = 1;
    int res = setsockopt(s, SOL_TCP, TCP_REPAIR, &val, sizeof(val));
    if (res == 0) {
        val = 0;
        setsockopt(s, SOL_TCP, TCP_REPAIR, &val, sizeof(val));
        close(s);
        return true;
    }
    close(s);
    return false;
#else
    return false;
#endif
}

bool ktls_is_supported(void) {
#ifdef __linux__
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return false;
    int res = setsockopt(s, SOL_TCP, 31 /* TCP_ULP */, "tls", sizeof("tls"));
    close(s);
    return (res == 0 || errno == EEXIST || errno == ENOPROTOOPT);
#else
    return false;
#endif
}

bool tcp_repair_checkpoint(int sock_fd, void *ssl_ptr, TcpSocketCheckpoint *out_cp) {
    if (sock_fd < 0 || !out_cp) return false;
    (void)ssl_ptr;
    memset(out_cp, 0, sizeof(*out_cp));

    socklen_t loc_len = sizeof(out_cp->local_addr);
    if (getsockname(sock_fd, (struct sockaddr *)&out_cp->local_addr, &loc_len) < 0) {
        return false;
    }
    socklen_t rem_len = sizeof(out_cp->remote_addr);
    if (getpeername(sock_fd, (struct sockaddr *)&out_cp->remote_addr, &rem_len) < 0) {
        return false;
    }

#ifdef __linux__
    struct tcp_info ti;
    socklen_t ti_len = sizeof(ti);
    if (getsockopt(sock_fd, IPPROTO_TCP, TCP_INFO, &ti, &ti_len) == 0) {
        out_cp->snd_wscale = ti.tcpi_snd_wscale;
        out_cp->rcv_wscale = ti.tcpi_rcv_wscale;
        out_cp->mss_clamp = ti.tcpi_snd_mss;
        out_cp->snd_wnd = ti.tcpi_snd_cwnd;
        out_cp->rcv_wnd = ti.tcpi_rcv_space;
    }

    int on = 1;
    if (setsockopt(sock_fd, SOL_TCP, TCP_REPAIR, &on, sizeof(on)) == 0) {
        int q = TCP_SEND_QUEUE;
        setsockopt(sock_fd, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
        socklen_t slen = sizeof(out_cp->snd_seq);
        getsockopt(sock_fd, SOL_TCP, TCP_QUEUE_SEQ, &out_cp->snd_seq, &slen);

        q = TCP_RECV_QUEUE;
        setsockopt(sock_fd, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
        slen = sizeof(out_cp->rcv_seq);
        getsockopt(sock_fd, SOL_TCP, TCP_QUEUE_SEQ, &out_cp->rcv_seq, &slen);

        int off = 0;
        setsockopt(sock_fd, SOL_TCP, TCP_REPAIR, &off, sizeof(off));
    }

    /* Check kTLS state */
    struct adlb_tls12_crypto_info_aes_gcm_128 tx128;
    socklen_t klen = sizeof(tx128);
    if (getsockopt(sock_fd, SOL_TLS, TLS_TX, &tx128, &klen) == 0) {
        out_cp->is_ktls = true;
        out_cp->ktls.tls_version = tx128.info.version;
        out_cp->ktls.cipher_type = tx128.info.cipher_type;
        memcpy(out_cp->ktls.tx_iv, tx128.iv, 8);
        memcpy(out_cp->ktls.tx_key, tx128.key, 16);
        memcpy(out_cp->ktls.tx_salt, tx128.salt, 4);
        memcpy(out_cp->ktls.tx_rec_seq, tx128.rec_seq, 8);

        struct adlb_tls12_crypto_info_aes_gcm_128 rx128;
        klen = sizeof(rx128);
        if (getsockopt(sock_fd, SOL_TLS, TLS_RX, &rx128, &klen) == 0) {
            memcpy(out_cp->ktls.rx_iv, rx128.iv, 8);
            memcpy(out_cp->ktls.rx_key, rx128.key, 16);
            memcpy(out_cp->ktls.rx_salt, rx128.salt, 4);
            memcpy(out_cp->ktls.rx_rec_seq, rx128.rec_seq, 8);
        }
    }
    return true;
#else
    return true;
#endif
}

int tcp_repair_restore(const TcpSocketCheckpoint *cp) {
    if (!cp) return -1;

#ifdef __linux__
    int domain = cp->remote_addr.ss_family;
    if (domain != AF_INET && domain != AF_INET6) domain = AF_INET;

    int s = socket(domain, SOCK_STREAM, 0);
    if (s < 0) return -1;

    int on = 1;
    if (setsockopt(s, SOL_TCP, TCP_REPAIR, &on, sizeof(on)) < 0) {
        close(s);
        return -1;
    }

    /* Set TCP options in repair mode */
    struct adlb_tcp_repair_opt opts[4];
    int nopts = 0;
    if (cp->mss_clamp > 0) {
        opts[nopts].opt_code = 2; /* TCPOPT_MAXSEG */
        opts[nopts].opt_val = cp->mss_clamp;
        nopts++;
    }
    if (cp->snd_wscale > 0 || cp->rcv_wscale > 0) {
        opts[nopts].opt_code = 3; /* TCPOPT_WINDOW */
        opts[nopts].opt_val = ((uint32_t)cp->snd_wscale << 16) | (uint32_t)cp->rcv_wscale;
        nopts++;
    }
    if (cp->has_timestamps) {
        opts[nopts].opt_code = 8; /* TCPOPT_TIMESTAMP */
        opts[nopts].opt_val = 0;
        nopts++;
    }
    for (int i = 0; i < nopts; i++) {
        setsockopt(s, SOL_TCP, TCP_REPAIR_OPTIONS, &opts[i], sizeof(opts[i]));
    }

    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
#ifdef IP_TRANSPARENT
    int one = 1;
    setsockopt(s, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
#endif

    socklen_t loc_len = (cp->local_addr.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    (void)bind(s, (const struct sockaddr *)&cp->local_addr, loc_len);

    socklen_t rem_len = (cp->remote_addr.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (connect(s, (const struct sockaddr *)&cp->remote_addr, rem_len) < 0 && errno != EINPROGRESS) {
        /* Repair connect marks peer */
    }

    /* Set Sequence numbers */
    int q = TCP_SEND_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
    setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &cp->snd_seq, sizeof(cp->snd_seq));

    q = TCP_RECV_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
    setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &cp->rcv_seq, sizeof(cp->rcv_seq));

    /* kTLS restore */
    if (cp->is_ktls) {
        setsockopt(s, SOL_TCP, 31 /* TCP_ULP */, "tls", sizeof("tls"));
        if (cp->ktls.cipher_type == KTLS_CIPHER_AES_GCM_256) {
            struct adlb_tls12_crypto_info_aes_gcm_256 tx;
            memset(&tx, 0, sizeof(tx));
            tx.info.version = cp->ktls.tls_version;
            tx.info.cipher_type = cp->ktls.cipher_type;
            memcpy(tx.iv, cp->ktls.tx_iv, 8);
            memcpy(tx.key, cp->ktls.tx_key, 32);
            memcpy(tx.salt, cp->ktls.tx_salt, 4);
            memcpy(tx.rec_seq, cp->ktls.tx_rec_seq, 8);
            setsockopt(s, SOL_TLS, TLS_TX, &tx, sizeof(tx));

            struct adlb_tls12_crypto_info_aes_gcm_256 rx;
            memset(&rx, 0, sizeof(rx));
            rx.info.version = cp->ktls.tls_version;
            rx.info.cipher_type = cp->ktls.cipher_type;
            memcpy(rx.iv, cp->ktls.rx_iv, 8);
            memcpy(rx.key, cp->ktls.rx_key, 32);
            memcpy(rx.salt, cp->ktls.rx_salt, 4);
            memcpy(rx.rec_seq, cp->ktls.rx_rec_seq, 8);
            setsockopt(s, SOL_TLS, TLS_RX, &rx, sizeof(rx));
        } else {
            struct adlb_tls12_crypto_info_aes_gcm_128 tx;
            memset(&tx, 0, sizeof(tx));
            tx.info.version = cp->ktls.tls_version;
            tx.info.cipher_type = cp->ktls.cipher_type ? cp->ktls.cipher_type : KTLS_CIPHER_AES_GCM_128;
            memcpy(tx.iv, cp->ktls.tx_iv, 8);
            memcpy(tx.key, cp->ktls.tx_key, 16);
            memcpy(tx.salt, cp->ktls.tx_salt, 4);
            memcpy(tx.rec_seq, cp->ktls.tx_rec_seq, 8);
            setsockopt(s, SOL_TLS, TLS_TX, &tx, sizeof(tx));

            struct adlb_tls12_crypto_info_aes_gcm_128 rx;
            memset(&rx, 0, sizeof(rx));
            rx.info.version = cp->ktls.tls_version;
            rx.info.cipher_type = cp->ktls.cipher_type ? cp->ktls.cipher_type : KTLS_CIPHER_AES_GCM_128;
            memcpy(rx.iv, cp->ktls.rx_iv, 8);
            memcpy(rx.key, cp->ktls.rx_key, 16);
            memcpy(rx.salt, cp->ktls.rx_salt, 4);
            memcpy(rx.rec_seq, cp->ktls.rx_rec_seq, 8);
            setsockopt(s, SOL_TLS, TLS_RX, &rx, sizeof(rx));
        }
    }

    int off = 0;
    setsockopt(s, SOL_TCP, TCP_REPAIR, &off, sizeof(off));
    return s;
#else
    return -1;
#endif
}

void tcp_checkpoint_to_wire(const TcpSocketCheckpoint *cp,
                            int backend_idx,
                            const char *backend_ip,
                            uint16_t backend_port,
                            uint64_t bytes_to_client,
                            const char *initial_req,
                            uint16_t req_len,
                            ClusterTcpCheckpointWire *wire) {
    if (!cp || !wire) return;
    memset(wire, 0, sizeof(*wire));

    wire->family = (cp->remote_addr.ss_family == AF_INET6) ? AF_INET6 : AF_INET;
    wire->proto = IPPROTO_TCP;

    if (wire->family == AF_INET6) {
        const struct sockaddr_in6 *r6 = (const struct sockaddr_in6 *)&cp->remote_addr;
        const struct sockaddr_in6 *l6 = (const struct sockaddr_in6 *)&cp->local_addr;
        wire->client_port = r6->sin6_port;
        memcpy(wire->client_ip, &r6->sin6_addr, 16);
        wire->local_port = l6->sin6_port;
        memcpy(wire->local_ip, &l6->sin6_addr, 16);
    } else {
        const struct sockaddr_in *r4 = (const struct sockaddr_in *)&cp->remote_addr;
        const struct sockaddr_in *l4 = (const struct sockaddr_in *)&cp->local_addr;
        wire->client_port = r4->sin_port;
        memcpy(wire->client_ip, &r4->sin_addr.s_addr, 4);
        wire->local_port = l4->sin_port;
        memcpy(wire->local_ip, &l4->sin_addr.s_addr, 4);
    }

    if (backend_ip) {
        strncpy(wire->backend_ip, backend_ip, sizeof(wire->backend_ip) - 1);
    }
    wire->backend_port = htons(backend_port);
    wire->backend_idx = htons((uint16_t)backend_idx);

    wire->snd_seq = htonl(cp->snd_seq);
    wire->rcv_seq = htonl(cp->rcv_seq);
    wire->snd_wnd = htonl(cp->snd_wnd);
    wire->rcv_wnd = htonl(cp->rcv_wnd);
    wire->mss_clamp = htonl(cp->mss_clamp);
    wire->snd_wscale = cp->snd_wscale;
    wire->rcv_wscale = cp->rcv_wscale;

    wire->flags = 0;
    if (cp->has_timestamps) wire->flags |= 0x01;
    if (cp->is_ktls) wire->flags |= 0x02;

    wire->ts_val = htonl(cp->ts_val);
    wire->ts_ecr = htonl(cp->ts_ecr);

    wire->bytes_to_client = (uint64_t)htonl((uint32_t)(bytes_to_client >> 32)) << 32 |
                            (uint64_t)htonl((uint32_t)(bytes_to_client & 0xFFFFFFFFULL));
    wire->initial_req_len = htons(req_len);
    if (initial_req && req_len > 0) {
        if (req_len > sizeof(wire->initial_req)) req_len = sizeof(wire->initial_req);
        memcpy(wire->initial_req, initial_req, req_len);
    }

    if (cp->is_ktls) {
        wire->tls_version = htons(cp->ktls.tls_version);
        wire->cipher_type = htons(cp->ktls.cipher_type);
        memcpy(wire->tx_iv, cp->ktls.tx_iv, 8);
        memcpy(wire->tx_key, cp->ktls.tx_key, 32);
        memcpy(wire->tx_salt, cp->ktls.tx_salt, 4);
        memcpy(wire->tx_rec_seq, cp->ktls.tx_rec_seq, 8);
        memcpy(wire->rx_iv, cp->ktls.rx_iv, 8);
        memcpy(wire->rx_key, cp->ktls.rx_key, 32);
        memcpy(wire->rx_salt, cp->ktls.rx_salt, 4);
        memcpy(wire->rx_rec_seq, cp->ktls.rx_rec_seq, 8);
    }
}

void tcp_checkpoint_from_wire(const ClusterTcpCheckpointWire *wire,
                              TcpSocketCheckpoint *out_cp,
                              int *out_backend_idx,
                              char *out_backend_ip,
                              uint16_t *out_backend_port,
                              uint64_t *out_bytes_to_client,
                              char *out_initial_req,
                              uint16_t *out_req_len) {
    if (!wire || !out_cp) return;
    memset(out_cp, 0, sizeof(*out_cp));

    if (wire->family == AF_INET6) {
        struct sockaddr_in6 *r6 = (struct sockaddr_in6 *)&out_cp->remote_addr;
        struct sockaddr_in6 *l6 = (struct sockaddr_in6 *)&out_cp->local_addr;
        r6->sin6_family = AF_INET6;
        r6->sin6_port = wire->client_port;
        memcpy(&r6->sin6_addr, wire->client_ip, 16);
        l6->sin6_family = AF_INET6;
        l6->sin6_port = wire->local_port;
        memcpy(&l6->sin6_addr, wire->local_ip, 16);
    } else {
        struct sockaddr_in *r4 = (struct sockaddr_in *)&out_cp->remote_addr;
        struct sockaddr_in *l4 = (struct sockaddr_in *)&out_cp->local_addr;
        r4->sin_family = AF_INET;
        r4->sin_port = wire->client_port;
        memcpy(&r4->sin_addr.s_addr, wire->client_ip, 4);
        l4->sin_family = AF_INET;
        l4->sin_port = wire->local_port;
        memcpy(&l4->sin_addr.s_addr, wire->local_ip, 4);
    }

    if (out_backend_idx) *out_backend_idx = (int)ntohs(wire->backend_idx);
    if (out_backend_port) *out_backend_port = ntohs(wire->backend_port);
    if (out_backend_ip) {
        strncpy(out_backend_ip, wire->backend_ip, 46);
        out_backend_ip[45] = '\0';
    }

    out_cp->snd_seq = ntohl(wire->snd_seq);
    out_cp->rcv_seq = ntohl(wire->rcv_seq);
    out_cp->snd_wnd = ntohl(wire->snd_wnd);
    out_cp->rcv_wnd = ntohl(wire->rcv_wnd);
    out_cp->mss_clamp = ntohl(wire->mss_clamp);
    out_cp->snd_wscale = wire->snd_wscale;
    out_cp->rcv_wscale = wire->rcv_wscale;
    out_cp->has_timestamps = (wire->flags & 0x01) != 0;
    out_cp->is_ktls = (wire->flags & 0x02) != 0;
    out_cp->ts_val = ntohl(wire->ts_val);
    out_cp->ts_ecr = ntohl(wire->ts_ecr);

    if (out_bytes_to_client) {
        *out_bytes_to_client = (uint64_t)ntohl((uint32_t)(wire->bytes_to_client >> 32)) << 32 |
                               (uint64_t)ntohl((uint32_t)(wire->bytes_to_client & 0xFFFFFFFFULL));
    }
    uint16_t rlen = ntohs(wire->initial_req_len);
    if (out_req_len) *out_req_len = rlen;
    if (out_initial_req && rlen > 0) {
        if (rlen > 512) rlen = 512;
        memcpy(out_initial_req, wire->initial_req, rlen);
    }

    if (out_cp->is_ktls) {
        out_cp->ktls.tls_version = ntohs(wire->tls_version);
        out_cp->ktls.cipher_type = ntohs(wire->cipher_type);
        memcpy(out_cp->ktls.tx_iv, wire->tx_iv, 8);
        memcpy(out_cp->ktls.tx_key, wire->tx_key, 32);
        memcpy(out_cp->ktls.tx_salt, wire->tx_salt, 4);
        memcpy(out_cp->ktls.tx_rec_seq, wire->tx_rec_seq, 8);
        memcpy(out_cp->ktls.rx_iv, wire->rx_iv, 8);
        memcpy(out_cp->ktls.rx_key, wire->rx_key, 32);
        memcpy(out_cp->ktls.rx_salt, wire->rx_salt, 4);
        memcpy(out_cp->ktls.rx_rec_seq, wire->rx_rec_seq, 8);
    }
}

