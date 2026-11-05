#include "advlb/tcp_repair.h"
#include "advlb/cluster.h"
#include "advlb/net_utils.h"
#include "advlb/log.h"
#include <stddef.h>
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
#include <sys/ioctl.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include "advlb/sysnet.h"

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

void tcp_checkpoint_release(TcpSocketCheckpoint *cp) {
    if (!cp) return;
    free(cp->queue_data);
    cp->queue_data = NULL;
    cp->snd_queue_len = cp->snd_unsent_len = cp->rcv_queue_len = 0;
}

void migrated_stream_release(MigratedStreamState *st) {
    if (!st) return;
    tcp_checkpoint_release(&st->backend);
    free(st->c2b);
    free(st->b2c);
    free(st);
}

#ifdef __linux__
/* Peek one repair queue (socket must already be in TCP_REPAIR). Returns bytes copied or -1. */
static ssize_t peek_repair_queue(int sock_fd, int queue, uint8_t *buf, size_t len) {
    if (len == 0) return 0;
    setsockopt(sock_fd, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    return recv(sock_fd, buf, len, MSG_PEEK | MSG_DONTWAIT);
}

/* CRIU-style capture of the kernel send/receive queues while the socket is in repair mode */
static void capture_tcp_queues(int sock_fd, TcpSocketCheckpoint *cp) {
    int outq = 0, unsent = 0, inq = 0;
    if (ioctl(sock_fd, SIOCOUTQ, &outq) < 0) outq = 0;
    if (ioctl(sock_fd, SIOCOUTQNSD, &unsent) < 0) unsent = 0;
    if (ioctl(sock_fd, SIOCINQ, &inq) < 0) inq = 0;
    if (outq <= 0 && inq <= 0) return;

    if ((size_t)outq + (size_t)inq > TCP_CHECKPOINT_QUEUE_MAX) {
        add_log("\033[1;31m[HA CHECKPOINT ERR]\033[0m Queues too large to replicate (sndq=%d rcvq=%d, max %d) fd=%d",
                outq, inq, TCP_CHECKPOINT_QUEUE_MAX, sock_fd);
        return;
    }
    uint8_t *buf = malloc((size_t)outq + (size_t)inq);
    if (!buf) return;

    /* The send queue only shrinks under us (ACKs), so the peeked length is authoritative */
    ssize_t sq = peek_repair_queue(sock_fd, TCP_SEND_QUEUE, buf, (size_t)outq);
    ssize_t rq = peek_repair_queue(sock_fd, TCP_RECV_QUEUE, buf + (sq > 0 ? sq : 0), (size_t)inq);
    if (sq < 0 || rq < 0) {
        add_log("\033[1;31m[HA CHECKPOINT ERR]\033[0m Peek repair queues failed: %s (fd=%d)", strerror(errno), sock_fd);
        free(buf);
        return;
    }
    cp->queue_data = buf;
    cp->snd_queue_len = (uint32_t)sq;
    cp->snd_unsent_len = (unsent > 0 && (uint32_t)unsent <= (uint32_t)sq) ? (uint32_t)unsent : 0;
    cp->rcv_queue_len = (uint32_t)rq;
}
#endif

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
        /* Do NOT enable TCPOPT_TIMESTAMP (opt_code 8) on restored socket:
         * Linux TCP_REPAIR API cannot restore the sender/receiver timestamp counters (tsval/tsecr).
         * Restoring timestamps with uninitialized tsecr=0 triggers immediate PAWS (Protection Against Wrapped Sequence)
         * failure on the client (e.g. macOS), which causes the client to send TCP RST (errno 104).
         * Omitting timestamps allows standard sequence-number-based validation without PAWS rejection. */
        out_cp->has_timestamps = false;
    }

    /* 1. Query kTLS state while socket is in clean operational state (before TCP_REPAIR) */
    union {
        struct adlb_tls_crypto_info info;
        struct adlb_tls12_crypto_info_aes_gcm_128 gcm128;
        struct adlb_tls12_crypto_info_aes_gcm_256 gcm256;
    } tx_u;
    memset(&tx_u, 0, sizeof(tx_u));
    socklen_t klen = sizeof(struct adlb_tls12_crypto_info_aes_gcm_256);
    int res = getsockopt(sock_fd, SOL_TLS, TLS_TX, &tx_u, &klen);
    if (res < 0 && (errno == EINVAL || errno == EFAULT)) {
        klen = sizeof(struct adlb_tls12_crypto_info_aes_gcm_128);
        res = getsockopt(sock_fd, SOL_TLS, TLS_TX, &tx_u, &klen);
    }
    if (res == 0) {
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
        memset(&rx_u, 0, sizeof(rx_u));
        klen = sizeof(struct adlb_tls12_crypto_info_aes_gcm_256);
        res = getsockopt(sock_fd, SOL_TLS, TLS_RX, &rx_u, &klen);
        if (res < 0 && (errno == EINVAL || errno == EFAULT)) {
            klen = sizeof(struct adlb_tls12_crypto_info_aes_gcm_128);
            res = getsockopt(sock_fd, SOL_TLS, TLS_RX, &rx_u, &klen);
        }
        if (res == 0) {
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
            add_log("\033[1;32m[HA CHECKPOINT OK]\033[0m Captured kTLS state (cipher=%u, ver=0x%04x, fd=%d)",
                    tx_u.info.cipher_type, tx_u.info.version, sock_fd);
        } else {
            out_cp->is_ktls = false;
            add_log("\033[1;31m[HA CHECKPOINT ERR]\033[0m getsockopt SOL_TLS TLS_RX failed: %s (errno %d, fd=%d)",
                    strerror(errno), errno, sock_fd);
        }
    } else {
        out_cp->is_ktls = false;
        add_log("\033[1;33m[HA CHECKPOINT]\033[0m getsockopt SOL_TLS TLS_TX: %s (errno %d, fd=%d)",
                strerror(errno), errno, sock_fd);
    }

    /* 2. Query TCP sequence numbers and sliding window in TCP_REPAIR mode */
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

        /* kTLS replaces the socket recvmsg path, so queues cannot be peeked: only plain TCP carries them */
        if (!out_cp->is_ktls) {
            capture_tcp_queues(sock_fd, out_cp);
        }

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

        int off = -1; /* TCP_REPAIR_OFF_NO_WP (-1) disables repair without transmitting spurious window probe */
        if (setsockopt(sock_fd, SOL_TCP, TCP_REPAIR, &off, sizeof(off)) < 0) {
            off = 0;
            if (setsockopt(sock_fd, SOL_TCP, TCP_REPAIR, &off, sizeof(off)) < 0) {
                add_log("\033[1;31m[HA CHECKPOINT ERR]\033[0m disable TCP_REPAIR failed: %s (errno %d)",
                        strerror(errno), errno);
            }
        }
    } else {
        add_log("\033[1;31m[HA CHECKPOINT ERR]\033[0m enable TCP_REPAIR failed: %s (errno %d)",
                strerror(errno), errno);
    }

    add_log("\033[1;32m[HA CHECKPOINT DONE]\033[0m fd=%d is_ktls=%s snd_seq=%u sndq=%u (unsent %u) rcvq=%u",
            sock_fd, out_cp->is_ktls ? "\033[1;32mYES\033[0m" : "\033[1;33mNO\033[0m", out_cp->snd_seq,
            out_cp->snd_queue_len, out_cp->snd_unsent_len, out_cp->rcv_queue_len);
    return true;
#else
    return true;
#endif
}

#ifdef __linux__
/* Raw address bytes as conntrack tracks them: IPv4-mapped IPv6 (::ffff:a.b.c.d) is unwrapped to IPv4 */
static int sockaddr_to_ct_addr(const struct sockaddr_storage *ss, const void **out_addr, uint16_t *out_port) {
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s4 = (const struct sockaddr_in *)ss;
        *out_addr = &s4->sin_addr;
        *out_port = s4->sin_port;
        return AF_INET;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)ss;
        *out_port = s6->sin6_port;
        if (IN6_IS_ADDR_V4MAPPED(&s6->sin6_addr)) {
            *out_addr = &s6->sin6_addr.s6_addr[12];
            return AF_INET;
        }
        *out_addr = &s6->sin6_addr;
        return AF_INET6;
    }
    return 0;
}

/* Drop any stale netfilter conntrack entry for this 4-tuple left over from a previous
 * ownership period of this node. The stale entry has outdated seq/ack windows: packets of the
 * restored stream would be classified INVALID (and dropped/rejected by typical firewall rules). */
static void flush_stale_conntrack_entry(const TcpSocketCheckpoint *cp) {
    if (geteuid() != 0) return;
    const void *caddr = NULL, *laddr = NULL;
    uint16_t cport = 0, lport = 0;
    int cfam = sockaddr_to_ct_addr(&cp->remote_addr, &caddr, &cport);
    int lfam = sockaddr_to_ct_addr(&cp->local_addr, &laddr, &lport);
    if (cfam == 0 || cfam != lfam || cport == 0 || lport == 0) return;
    /* Original direction is peer->us for client streams, us->peer for backend streams */
    sysnet_conntrack_del_tcp(cfam, caddr, cport, laddr, lport);
    sysnet_conntrack_del_tcp(cfam, laddr, lport, caddr, cport);
}

/* Write repair-mode data into the selected queue; returns false on short write */
static bool fill_repair_queue(int s, int queue, const uint8_t *data, uint32_t len) {
    if (len == 0) return true;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &queue, sizeof(queue));
    uint32_t done = 0;
    while (done < len) {
        ssize_t w = send(s, data + done, len - done, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            add_log("\033[1;31m[HA RESTORE ERR]\033[0m refill %s queue failed at %u/%u: %s (errno %d)",
                    queue == TCP_SEND_QUEUE ? "send" : "recv", done, len, strerror(errno), errno);
            return false;
        }
        done += (uint32_t)w;
    }
    return true;
}
#endif

int tcp_repair_restore(const TcpSocketCheckpoint *cp) {
    if (!cp) return -1;

#ifdef __linux__
    flush_stale_conntrack_entry(cp);

    int domain = cp->remote_addr.ss_family;
    if (domain != AF_INET && domain != AF_INET6) domain = AF_INET;

    int s = socket(domain, SOCK_STREAM, 0);
    if (s < 0) return -1;

    int reuse = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    /* TCP_REPAIR must come AFTER SO_REUSEADDR: it sets sk_reuse = SK_FORCE_REUSE, which
     * SO_REUSEADDR would downgrade, making bind() to VIP:port fail against our own listener */
    int on = 1;
    if (setsockopt(s, SOL_TCP, TCP_REPAIR, &on, sizeof(on)) < 0) {
        close(s);
        return -1;
    }
    /* No SO_BINDTODEVICE: with VMAC disabled peers reach the VIP through the parent NIC, and a
     * device-bound socket never matches segments arriving there (silently lost). Egress from the
     * VIP is already steered to vrrp<VRID> by the "from VIP lookup 100+VRID" policy rule. */
    int one = 1;
    setsockopt(s, SOL_IP, IP_FREEBIND, &one, sizeof(one));
    setsockopt(s, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
    setsockopt(s, SOL_IPV6, IPV6_FREEBIND, &one, sizeof(one));
    setsockopt(s, SOL_IPV6, IPV6_TRANSPARENT, &one, sizeof(one));

    socklen_t loc_len = (cp->local_addr.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (bind(s, (const struct sockaddr *)&cp->local_addr, loc_len) < 0) {
        /* connect() would autobind an ephemeral port: wrong 4-tuple, the client answers with RST */
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m bind failed: %s (errno %d)", strerror(errno), errno);
        close(s);
        return -1;
    }

    /* Set Sequence numbers while socket is in TCP_CLOSE (mandatory for Linux TCP_REPAIR).
     * Queues are refilled later, so start each sequence at the head of its captured queue. */
    const uint8_t *snd_data = cp->queue_data;
    const uint8_t *rcv_data = cp->queue_data ? cp->queue_data + cp->snd_queue_len : NULL;
    uint32_t snd_len = cp->queue_data ? cp->snd_queue_len : 0;
    uint32_t rcv_len = cp->queue_data ? cp->rcv_queue_len : 0;
    uint32_t unsent_len = (cp->snd_unsent_len <= snd_len) ? cp->snd_unsent_len : 0;
    uint32_t snd_start = cp->snd_seq - snd_len;
    uint32_t rcv_start = cp->rcv_seq - rcv_len;

    int q = TCP_SEND_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
    if (setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &snd_start, sizeof(snd_start)) < 0) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m set snd_seq failed: %s (errno %d)", strerror(errno), errno);
    }

    q = TCP_RECV_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &q, sizeof(q));
    if (setsockopt(s, SOL_TCP, TCP_QUEUE_SEQ, &rcv_start, sizeof(rcv_start)) < 0) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m set rcv_seq failed: %s (errno %d)", strerror(errno), errno);
    }

    /* Connect in repair mode transitions TCP_CLOSE -> TCP_ESTABLISHED */
    socklen_t rem_len = (cp->remote_addr.ss_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    if (connect(s, (const struct sockaddr *)&cp->remote_addr, rem_len) < 0 && errno != EINPROGRESS) {
        add_log("\033[1;31m[HA RESTORE ERR]\033[0m connect failed: %s (errno %d)", strerror(errno), errno);
    }

    /* Set TCP options in repair mode (MUST be executed after connect, when socket is TCP_ESTABLISHED) */
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
    /* Note: TCPOPT_TIMESTAMP (8) intentionally omitted to avoid PAWS rejection on peer */
    for (int i = 0; i < nopts; i++) {
        if (setsockopt(s, SOL_TCP, TCP_REPAIR_OPTIONS, &opts[i], sizeof(opts[i])) < 0) {
            add_log("\033[1;31m[HA RESTORE ERR]\033[0m TCP_REPAIR_OPTIONS (%d) failed: %s (errno %d)",
                    opts[i].opt_code, strerror(errno), errno);
        }
    }

    /* Refill queues before the window: the kernel validates rcv_wup against the restored rcv_nxt.
     * Receive queue = bytes the old node ACKed but the proxy never read; send queue (already
     * transmitted part) = bytes the client has not ACKed yet, retransmitted by the kernel on RTO. */
    fill_repair_queue(s, TCP_RECV_QUEUE, rcv_data, rcv_len);
    fill_repair_queue(s, TCP_SEND_QUEUE, snd_data, snd_len - unsent_len);

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

    /* Disable TCP_REPAIR mode now that TCP stack state is fully reconstructed */
    int no_q = TCP_NO_QUEUE;
    setsockopt(s, SOL_TCP, TCP_REPAIR_QUEUE, &no_q, sizeof(no_q));

    int off = -1; /* TCP_REPAIR_OFF_NO_WP */
    if (setsockopt(s, SOL_TCP, TCP_REPAIR, &off, sizeof(off)) < 0) {
        off = 0;
        if (setsockopt(s, SOL_TCP, TCP_REPAIR, &off, sizeof(off)) < 0) {
            int err = errno;
            add_log("\033[1;31m[HA RESTORE ERR]\033[0m disable TCP_REPAIR failed: %s (errno %d)", strerror(err), err);
        }
    }

    /* Never-transmitted tail goes out as ordinary data now that repair mode is off */
    if (unsent_len > 0) {
        ssize_t w = send(s, snd_data + (snd_len - unsent_len), unsent_len, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w != (ssize_t)unsent_len) {
            add_log("\033[1;31m[HA RESTORE ERR]\033[0m unsent tail short write %zd/%u: %s",
                    w, unsent_len, strerror(errno));
        }
    }

    /* kTLS restore on healthy established TCP socket */
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
    /* queue_data is a large variable-length tail: only the used part is ever read or sent */
    memset(wire, 0, offsetof(ClusterTcpCheckpointWire, queue_data));

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

    uint32_t qlen = cp->queue_data ? cp->snd_queue_len + cp->rcv_queue_len : 0;
    if (qlen > 0 && qlen <= TCP_CHECKPOINT_QUEUE_MAX) {
        wire->snd_queue_len = htonl(cp->snd_queue_len);
        wire->snd_unsent_len = htonl(cp->snd_unsent_len);
        wire->rcv_queue_len = htonl(cp->rcv_queue_len);
        memcpy(wire->queue_data, cp->queue_data, qlen);
    }
}

size_t tcp_checkpoint_wire_len(const ClusterTcpCheckpointWire *wire) {
    size_t base = offsetof(ClusterTcpCheckpointWire, queue_data);
    if (!wire) return base;
    uint64_t qlen = (uint64_t)ntohl(wire->snd_queue_len) + (uint64_t)ntohl(wire->rcv_queue_len);
    return (qlen <= TCP_CHECKPOINT_QUEUE_MAX) ? base + (size_t)qlen : base;
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

    uint32_t sq = ntohl(wire->snd_queue_len);
    uint32_t rq = ntohl(wire->rcv_queue_len);
    uint32_t us = ntohl(wire->snd_unsent_len);
    if ((uint64_t)sq + rq > 0 && (uint64_t)sq + rq <= TCP_CHECKPOINT_QUEUE_MAX) {
        out_cp->queue_data = malloc((size_t)sq + rq);
        if (out_cp->queue_data) {
            memcpy(out_cp->queue_data, wire->queue_data, (size_t)sq + rq);
            out_cp->snd_queue_len = sq;
            out_cp->snd_unsent_len = (us <= sq) ? us : 0;
            out_cp->rcv_queue_len = rq;
        }
    }
}

