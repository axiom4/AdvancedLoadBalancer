#include "advlb/tcp_repair.h"
#include "advlb/net_utils.h"
#include "advlb/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
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
#ifndef TLS_SET_RECORD_TYPE
#define TLS_SET_RECORD_TYPE 1
#endif
#ifndef IP_FREEBIND
#define IP_FREEBIND 15
#endif
#ifndef IPV6_FREEBIND
#define IPV6_FREEBIND 78
#endif
#ifndef IP_TRANSPARENT
#define IP_TRANSPARENT 19
#endif
#ifndef IPV6_TRANSPARENT
#define IPV6_TRANSPARENT 75
#endif

struct adlb_tcp_repair_opt {
    uint32_t opt_code;
    uint32_t opt_val;
};

struct adlb_tcp_repair_window {
    uint32_t snd_wl1;
    uint32_t snd_wnd;
    uint32_t max_window;
    uint32_t rcv_wnd;
    uint32_t rcv_wup;
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

bool ktls_send_close_notify(int fd) {
#ifdef __linux__
    if (fd < 0) return false;
    unsigned char alert[2] = { 1, 0 }; /* Warning (1), close_notify (0) */
    unsigned char record_type = 21;    /* TLS Alert record */

    char cbuf[CMSG_SPACE(sizeof(record_type))];
    memset(cbuf, 0, sizeof(cbuf));

    struct msghdr msg;
    memset(&msg, 0, sizeof(msg));
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (!cmsg) return false;
    cmsg->cmsg_level = SOL_TLS;
    cmsg->cmsg_type = TLS_SET_RECORD_TYPE;
    cmsg->cmsg_len = CMSG_LEN(sizeof(record_type));
    memcpy(CMSG_DATA(cmsg), &record_type, sizeof(record_type));

    struct iovec iov;
    iov.iov_base = alert;
    iov.iov_len = sizeof(alert);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    ssize_t sent = sendmsg(fd, &msg, MSG_NOSIGNAL);
    add_log("\033[1;33m[HA CLOSE]\033[0m ktls_send_close_notify fd=%d sent=%zd (errno=%d: %s)",
            fd, sent, (sent < 0 ? errno : 0), strerror(sent < 0 ? errno : 0));
    return sent > 0;
#else
    (void)fd;
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

        struct adlb_tcp_repair_window wnd;
        socklen_t wlen = sizeof(wnd);
        if (getsockopt(sock_fd, SOL_TCP, TCP_REPAIR_WINDOW, &wnd, &wlen) == 0) {
            out_cp->snd_wl1 = wnd.snd_wl1;
            out_cp->snd_wnd = wnd.snd_wnd;
            out_cp->max_window = wnd.max_window;
            out_cp->rcv_wnd = wnd.rcv_wnd;
            out_cp->rcv_wup = wnd.rcv_wup;
        }

        int no_q = TCP_NO_QUEUE;
        setsockopt(sock_fd, SOL_TCP, TCP_REPAIR_QUEUE, &no_q, sizeof(no_q));

        int off = 0;
        setsockopt(sock_fd, SOL_TCP, TCP_REPAIR, &off, sizeof(off));
    }

    /* Check kTLS state (supports both AES-128 and AES-256 GCM) */
    union {
        struct adlb_tls_crypto_info info;
        struct adlb_tls12_crypto_info_aes_gcm_128 gcm128;
        struct adlb_tls12_crypto_info_aes_gcm_256 gcm256;
    } tx_u;
    socklen_t klen = sizeof(tx_u);
    if (getsockopt(sock_fd, SOL_TLS, TLS_TX, &tx_u, &klen) == 0) {
        out_cp->is_ktls = true;
        out_cp->ktls.tls_version = tx_u.info.version;
        out_cp->ktls.cipher_type = tx_u.info.cipher_type;
        if (tx_u.info.cipher_type == KTLS_CIPHER_AES_GCM_256) {
            memcpy(out_cp->ktls.tx_iv, tx_u.gcm256.iv, 8);
            memcpy(out_cp->ktls.tx_key, tx_u.gcm256.key, 32);
            memcpy(out_cp->ktls.tx_salt, tx_u.gcm256.salt, 4);
            memcpy(out_cp->ktls.tx_rec_seq, tx_u.gcm256.rec_seq, 8);
        } else {
            memcpy(out_cp->ktls.tx_iv, tx_u.gcm128.iv, 8);
            memcpy(out_cp->ktls.tx_key, tx_u.gcm128.key, 16);
            memcpy(out_cp->ktls.tx_salt, tx_u.gcm128.salt, 4);
            memcpy(out_cp->ktls.tx_rec_seq, tx_u.gcm128.rec_seq, 8);
        }

        union {
            struct adlb_tls_crypto_info info;
            struct adlb_tls12_crypto_info_aes_gcm_128 gcm128;
            struct adlb_tls12_crypto_info_aes_gcm_256 gcm256;
        } rx_u;
        klen = sizeof(rx_u);
        if (getsockopt(sock_fd, SOL_TLS, TLS_RX, &rx_u, &klen) == 0) {
            if (rx_u.info.cipher_type == KTLS_CIPHER_AES_GCM_256) {
                memcpy(out_cp->ktls.rx_iv, rx_u.gcm256.iv, 8);
                memcpy(out_cp->ktls.rx_key, rx_u.gcm256.key, 32);
                memcpy(out_cp->ktls.rx_salt, rx_u.gcm256.salt, 4);
                memcpy(out_cp->ktls.rx_rec_seq, rx_u.gcm256.rec_seq, 8);
            } else {
                memcpy(out_cp->ktls.rx_iv, rx_u.gcm128.iv, 8);
                memcpy(out_cp->ktls.rx_key, rx_u.gcm128.key, 16);
                memcpy(out_cp->ktls.rx_salt, rx_u.gcm128.salt, 4);
                memcpy(out_cp->ktls.rx_rec_seq, rx_u.gcm128.rec_seq, 8);
            }
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
        /* Linux kernel tcp_repair_options_est:
         * u16 snd_wscale = opt.opt_val & 0xFFFF;
         * u16 rcv_wscale = opt.opt_val >> 16;
         * Therefore lower 16 bits MUST be snd_wscale, upper 16 bits rcv_wscale */
        opts[nopts].opt_val = ((uint32_t)cp->rcv_wscale << 16) | (uint32_t)cp->snd_wscale;
        nopts++;
    }
    if (cp->has_timestamps) {
        opts[nopts].opt_code = 8; /* TCPOPT_TIMESTAMP */
        opts[nopts].opt_val = 0;
        nopts++;
    }
    for (int i = 0; i < nopts; i++) {
        if (setsockopt(s, SOL_TCP, TCP_REPAIR_OPTIONS, &opts[i], sizeof(opts[i])) < 0) {
            add_log("\033[1;31m[HA RESTORE ERR]\033[0m TCP_REPAIR_OPTIONS (%d) failed: %s (errno %d)",
                    opts[i].opt_code, strerror(errno), errno);
        }
    }

    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif
    int one = 1;
    setsockopt(s, SOL_IP, IP_FREEBIND, &one, sizeof(one));
    setsockopt(s, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
    setsockopt(s, SOL_IPV6, IPV6_FREEBIND, &one, sizeof(one));
    setsockopt(s, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one));

    socklen_t loc_len = (cp->local_addr.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (bind(s, (const struct sockaddr *)&cp->local_addr, loc_len) < 0) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m bind failed: %s (errno %d)", strerror(errno), errno);
    }

    /* Set Sequence numbers while socket is in TCP_CLOSE (mandatory for Linux TCP_REPAIR) */
    int q = TCP_SEND_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
    if (setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &cp->snd_seq, sizeof(cp->snd_seq)) < 0) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m set snd_seq failed: %s (errno %d)", strerror(errno), errno);
    }

    q = TCP_RECV_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
    if (setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &cp->rcv_seq, sizeof(cp->rcv_seq)) < 0) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m set rcv_seq failed: %s (errno %d)", strerror(errno), errno);
    }

    /* Connect in repair mode transitions TCP_CLOSE -> TCP_ESTABLISHED */
    socklen_t rem_len = (cp->remote_addr.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (connect(s, (const struct sockaddr *)&cp->remote_addr, rem_len) < 0 && errno != EINPROGRESS) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m connect failed: %s (errno %d)", strerror(errno), errno);
    }

    /* Restore TCP sliding window parameters */
    struct adlb_tcp_repair_window wnd;
    memset(&wnd, 0, sizeof(wnd));
    wnd.snd_wnd = (cp->snd_wnd > 0) ? cp->snd_wnd : 65535;
    wnd.max_window = (cp->max_window >= wnd.snd_wnd) ? cp->max_window : wnd.snd_wnd;
    wnd.rcv_wnd = (cp->rcv_wnd > 0) ? cp->rcv_wnd : 65535;
    wnd.snd_wl1 = (cp->snd_wl1 != 0) ? cp->snd_wl1 : cp->rcv_seq;
    wnd.rcv_wup = (cp->rcv_wup != 0) ? cp->rcv_wup : cp->rcv_seq;

    if (wnd.max_window < wnd.snd_wnd) wnd.max_window = wnd.snd_wnd;
    if ((int32_t)(wnd.snd_wl1 - (cp->rcv_seq + wnd.rcv_wnd)) > 0) wnd.snd_wl1 = cp->rcv_seq;
    if ((int32_t)(wnd.rcv_wup - cp->rcv_seq) > 0) wnd.rcv_wup = cp->rcv_seq;

    if (setsockopt(s, SOL_TCP, TCP_REPAIR_WINDOW, &wnd, sizeof(wnd)) < 0) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m TCP_REPAIR_WINDOW failed: %s (errno %d)", strerror(errno), errno);
    }

    /* kTLS restore */
    if (cp->is_ktls) {
        if (setsockopt(s, SOL_TCP, 31 /* TCP_ULP */, "tls", sizeof("tls")) < 0) {
            add_log("\033[1;31m[HA RESTORE ERR]\033[0m TCP_ULP tls failed: %s (errno %d)", strerror(errno), errno);
        }
        if (cp->ktls.cipher_type == KTLS_CIPHER_AES_GCM_256) {
            struct adlb_tls12_crypto_info_aes_gcm_256 tx;
            memset(&tx, 0, sizeof(tx));
            tx.info.version = cp->ktls.tls_version;
            tx.info.cipher_type = cp->ktls.cipher_type;
            memcpy(tx.iv, cp->ktls.tx_iv, 8);
            memcpy(tx.key, cp->ktls.tx_key, 32);
            memcpy(tx.salt, cp->ktls.tx_salt, 4);
            memcpy(tx.rec_seq, cp->ktls.tx_rec_seq, 8);
            if (setsockopt(s, SOL_TLS, TLS_TX, &tx, sizeof(tx)) < 0) {
                add_log("\033[1;31m[HA RESTORE ERR]\033[0m TLS_TX failed: %s (errno %d)", strerror(errno), errno);
            }

            struct adlb_tls12_crypto_info_aes_gcm_256 rx;
            memset(&rx, 0, sizeof(rx));
            rx.info.version = cp->ktls.tls_version;
            rx.info.cipher_type = cp->ktls.cipher_type;
            memcpy(rx.iv, cp->ktls.rx_iv, 8);
            memcpy(rx.key, cp->ktls.rx_key, 32);
            memcpy(rx.salt, cp->ktls.rx_salt, 4);
            memcpy(rx.rec_seq, cp->ktls.rx_rec_seq, 8);
            if (setsockopt(s, SOL_TLS, TLS_RX, &rx, sizeof(rx)) < 0) {
                add_log("\033[1;31m[HA RESTORE ERR]\033[0m TLS_RX failed: %s (errno %d)", strerror(errno), errno);
            }
        } else {
            struct adlb_tls12_crypto_info_aes_gcm_128 tx;
            memset(&tx, 0, sizeof(tx));
            tx.info.version = cp->ktls.tls_version;
            tx.info.cipher_type = cp->ktls.cipher_type ? cp->ktls.cipher_type : KTLS_CIPHER_AES_GCM_128;
            memcpy(tx.iv, cp->ktls.tx_iv, 8);
            memcpy(tx.key, cp->ktls.tx_key, 16);
            memcpy(tx.salt, cp->ktls.tx_salt, 4);
            memcpy(tx.rec_seq, cp->ktls.tx_rec_seq, 8);
            if (setsockopt(s, SOL_TLS, TLS_TX, &tx, sizeof(tx)) < 0) {
                add_log("\033[1;31m[HA RESTORE ERR]\033[0m TLS_TX failed: %s (errno %d)", strerror(errno), errno);
            }

            struct adlb_tls12_crypto_info_aes_gcm_128 rx;
            memset(&rx, 0, sizeof(rx));
            rx.info.version = cp->ktls.tls_version;
            rx.info.cipher_type = cp->ktls.cipher_type ? cp->ktls.cipher_type : KTLS_CIPHER_AES_GCM_128;
            memcpy(rx.iv, cp->ktls.rx_iv, 8);
            memcpy(rx.key, cp->ktls.rx_key, 16);
            memcpy(rx.salt, cp->ktls.rx_salt, 4);
            memcpy(rx.rec_seq, cp->ktls.rx_rec_seq, 8);
            if (setsockopt(s, SOL_TLS, TLS_RX, &rx, sizeof(rx)) < 0) {
                add_log("\033[1;31m[HA RESTORE ERR]\033[0m TLS_RX failed: %s (errno %d)", strerror(errno), errno);
            }
        }
    }

    int no_q = TCP_NO_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &no_q, sizeof(no_q));

    int off = 0;
    if (setsockopt(s, SOL_TCP, TCP_REPAIR, &off, sizeof(off)) < 0) {
        int err = errno;
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m disable TCP_REPAIR failed: %s (errno %d)", strerror(err), err);
    }

    /* Enable TCP_NODELAY and TCP_QUICKACK to avoid Nagle and delayed ACK delays */
    int one_flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &one_flag, sizeof(one_flag));
#ifdef TCP_QUICKACK
    setsockopt(s, IPPROTO_TCP, TCP_QUICKACK, &one_flag, sizeof(one_flag));
#endif
    set_nonblocking(s);
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
    wire->max_window = htonl(cp->max_window);
    wire->snd_wl1 = htonl(cp->snd_wl1);
    wire->rcv_wup = htonl(cp->rcv_wup);
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
    out_cp->max_window = ntohl(wire->max_window);
    out_cp->snd_wl1 = ntohl(wire->snd_wl1);
    out_cp->rcv_wup = ntohl(wire->rcv_wup);
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

