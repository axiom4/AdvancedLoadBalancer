#define _GNU_SOURCE
#include "advlb/sysnet.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

static atomic_uint s_seq = 1;

/* Parse IPv4/IPv6 literal into raw bytes; returns address family or 0 */
static __attribute__((unused)) int parse_ip(const char *ip, uint8_t out[16]) {
    if (!ip) return 0;
    if (inet_pton(AF_INET, ip, out) == 1) return AF_INET;
    if (inet_pton(AF_INET6, ip, out) == 1) return AF_INET6;
    return 0;
}

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/fib_rules.h>
#include <linux/neighbour.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <net/if_arp.h>

typedef struct {
    struct nlmsghdr n;
    char buf[1024];
} NlMsg;

static void *nl_init(NlMsg *m, uint16_t type, uint16_t flags, size_t hdr_len) {
    memset(m, 0, sizeof(*m));
    m->n.nlmsg_len = (uint32_t)NLMSG_LENGTH(hdr_len);
    m->n.nlmsg_type = type;
    m->n.nlmsg_flags = flags;
    return NLMSG_DATA(&m->n);
}

static struct rtattr *nl_attr(NlMsg *m, unsigned short type, const void *data, size_t len) {
    size_t off = NLMSG_ALIGN(m->n.nlmsg_len);
    size_t alen = RTA_LENGTH(len);
    if (off + RTA_ALIGN(alen) > sizeof(*m)) return NULL;
    struct rtattr *rta = (struct rtattr *)((char *)m + off);
    rta->rta_type = type;
    rta->rta_len = (unsigned short)alen;
    if (len > 0) memcpy(RTA_DATA(rta), data, len);
    m->n.nlmsg_len = (uint32_t)(off + RTA_ALIGN(alen));
    return rta;
}

static void nl_nest_end(NlMsg *m, struct rtattr *nest) {
    if (nest) nest->rta_len = (unsigned short)((char *)m + m->n.nlmsg_len - (char *)nest);
}

/* Send one request and wait for its ACK. Stack-only (safe in a forked child of a threaded process). */
static int nl_transact(int proto, struct nlmsghdr *n) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, proto);
    if (fd < 0) return -errno;
    struct timeval tv = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    n->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
    n->nlmsg_seq = atomic_fetch_add_explicit(&s_seq, 1, memory_order_relaxed);

    if (sendto(fd, n, n->nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    char buf[4096] __attribute__((aligned(NLMSG_ALIGNTO)));
    int ret = -ETIMEDOUT;
    for (;;) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            ret = -errno;
            break;
        }
        int rem = (int)len;
        bool done = false;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
            if (h->nlmsg_seq != n->nlmsg_seq) continue;
            if (h->nlmsg_type == NLMSG_ERROR) {
                ret = ((struct nlmsgerr *)NLMSG_DATA(h))->error;
                done = true;
                break;
            }
            if (h->nlmsg_type == NLMSG_DONE) {
                ret = 0;
                done = true;
                break;
            }
        }
        if (done) break;
    }
    close(fd);
    return ret;
}

static int ifreq_ioctl(unsigned long req, struct ifreq *ifr) {
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -errno;
    int ret = (ioctl(s, req, ifr) < 0) ? -errno : 0;
    close(s);
    return ret;
}

int sysnet_link_add_macvlan(const char *parent, const char *name, const uint8_t *mac) {
    unsigned int pidx = if_nametoindex(parent);
    if (pidx == 0) return -ENODEV;

    NlMsg m;
    struct ifinfomsg *ifi = nl_init(&m, RTM_NEWLINK, NLM_F_CREATE | NLM_F_EXCL, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_flags = IFF_UP;
    ifi->ifi_change = IFF_UP;

    uint32_t link = pidx;
    nl_attr(&m, IFLA_LINK, &link, sizeof(link));
    nl_attr(&m, IFLA_IFNAME, name, strlen(name) + 1);
    if (mac) nl_attr(&m, IFLA_ADDRESS, mac, 6);

    struct rtattr *linkinfo = nl_attr(&m, IFLA_LINKINFO, NULL, 0);
    nl_attr(&m, IFLA_INFO_KIND, "macvlan", strlen("macvlan"));
    struct rtattr *data = nl_attr(&m, IFLA_INFO_DATA, NULL, 0);
    uint32_t mode = MACVLAN_MODE_BRIDGE;
    nl_attr(&m, IFLA_MACVLAN_MODE, &mode, sizeof(mode));
    nl_nest_end(&m, data);
    nl_nest_end(&m, linkinfo);

    /* Kernel autoloads the macvlan module (rtnl-link-macvlan) on demand */
    return nl_transact(NETLINK_ROUTE, &m.n);
}

int sysnet_link_del(const char *name) {
    unsigned int idx = if_nametoindex(name);
    if (idx == 0) return -ENODEV;
    NlMsg m;
    struct ifinfomsg *ifi = nl_init(&m, RTM_DELLINK, 0, sizeof(*ifi));
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_index = (int)idx;
    return nl_transact(NETLINK_ROUTE, &m.n);
}

int sysnet_link_set_promisc(const char *name, bool on) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    int ret = ifreq_ioctl(SIOCGIFFLAGS, &ifr);
    if (ret != 0) return ret;
    short flags = on ? (short)(ifr.ifr_flags | IFF_PROMISC) : (short)(ifr.ifr_flags & ~IFF_PROMISC);
    if (flags == ifr.ifr_flags) return 0;
    ifr.ifr_flags = flags;
    return ifreq_ioctl(SIOCSIFFLAGS, &ifr);
}

int sysnet_link_set_mac(const char *name, const uint8_t mac[6]) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
    return ifreq_ioctl(SIOCSIFHWADDR, &ifr);
}

bool sysnet_link_get_perm_mac(const char *name, uint8_t out_mac[6]) {
    union {
        struct ethtool_perm_addr epa;
        uint8_t raw[sizeof(struct ethtool_perm_addr) + 32];
    } req;
    memset(&req, 0, sizeof(req));
    req.epa.cmd = ETHTOOL_GPERMADDR;
    req.epa.size = 32;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", name);
    ifr.ifr_data = (char *)&req;
    if (ifreq_ioctl(SIOCETHTOOL, &ifr) != 0 || req.epa.size != 6) return false;

    static const uint8_t zero[6] = {0};
    if (memcmp(req.epa.data, zero, 6) == 0) return false;
    memcpy(out_mac, req.epa.data, 6);
    return true;
}

static int addr_msg(uint16_t type, uint16_t flags, const char *ifname, const char *ip, int prefix, const char *label) {
    unsigned int idx = if_nametoindex(ifname);
    if (idx == 0) return -ENODEV;
    uint8_t a[16];
    int fam = parse_ip(ip, a);
    if (fam == 0) return -EINVAL;
    size_t alen = (fam == AF_INET) ? 4 : 16;

    NlMsg m;
    struct ifaddrmsg *ifa = nl_init(&m, type, flags, sizeof(*ifa));
    ifa->ifa_family = (uint8_t)fam;
    ifa->ifa_prefixlen = (uint8_t)prefix;
    ifa->ifa_index = idx;
    ifa->ifa_scope = (fam == AF_INET && a[0] == 127) ? RT_SCOPE_HOST : RT_SCOPE_UNIVERSE;
    nl_attr(&m, IFA_LOCAL, a, alen);
    if (type == RTM_NEWADDR) nl_attr(&m, IFA_ADDRESS, a, alen);
    if (label && label[0] != '\0' && fam == AF_INET) {
        char lbl[IFNAMSIZ];
        snprintf(lbl, sizeof(lbl), "%s", label);
        nl_attr(&m, IFA_LABEL, lbl, strlen(lbl) + 1);
    }
    return nl_transact(NETLINK_ROUTE, &m.n);
}

int sysnet_addr_add(const char *ifname, const char *ip, int prefix, const char *label) {
    return addr_msg(RTM_NEWADDR, NLM_F_CREATE | NLM_F_REPLACE, ifname, ip, prefix, label);
}

int sysnet_addr_del(const char *ifname, const char *ip, int prefix) {
    return addr_msg(RTM_DELADDR, 0, ifname, ip, prefix, NULL);
}

int sysnet_route_replace(int table, const char *dst_cidr, const char *gw, const char *dev, const char *src) {
    unsigned int oif = if_nametoindex(dev);
    if (oif == 0) return -ENODEV;

    NlMsg m;
    struct rtmsg *rt = nl_init(&m, RTM_NEWROUTE, NLM_F_CREATE | NLM_F_REPLACE, sizeof(*rt));
    rt->rtm_family = AF_INET;
    rt->rtm_table = (table < 256) ? (uint8_t)table : RT_TABLE_UNSPEC;
    rt->rtm_protocol = RTPROT_BOOT;
    rt->rtm_type = RTN_UNICAST;
    rt->rtm_scope = gw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    uint32_t t = (uint32_t)table;
    nl_attr(&m, RTA_TABLE, &t, sizeof(t));

    if (dst_cidr) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "%s", dst_cidr);
        char *slash = strchr(tmp, '/');
        int pfx = 32;
        if (slash) {
            *slash = '\0';
            pfx = atoi(slash + 1);
        }
        struct in_addr d;
        if (inet_pton(AF_INET, tmp, &d) != 1 || pfx < 0 || pfx > 32) return -EINVAL;
        rt->rtm_dst_len = (uint8_t)pfx;
        nl_attr(&m, RTA_DST, &d, sizeof(d));
    }
    if (gw) {
        struct in_addr g;
        if (inet_pton(AF_INET, gw, &g) != 1) return -EINVAL;
        nl_attr(&m, RTA_GATEWAY, &g, sizeof(g));
        rt->rtm_flags |= RTNH_F_ONLINK;
    }
    uint32_t o = oif;
    nl_attr(&m, RTA_OIF, &o, sizeof(o));
    if (src) {
        struct in_addr s;
        if (inet_pton(AF_INET, src, &s) != 1) return -EINVAL;
        nl_attr(&m, RTA_PREFSRC, &s, sizeof(s));
    }
    return nl_transact(NETLINK_ROUTE, &m.n);
}

int sysnet_route_flush_table(int table) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -errno;
    struct timeval tv = {1, 0};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    NlMsg m;
    struct rtmsg *rt = nl_init(&m, RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sizeof(*rt));
    rt->rtm_family = AF_INET;
    m.n.nlmsg_seq = atomic_fetch_add_explicit(&s_seq, 1, memory_order_relaxed);
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (sendto(fd, &m.n, m.n.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int err = -errno;
        close(fd);
        return err;
    }

    /* Collect matching routes first: deleting while the dump is in progress corrupts it */
    char *dels = NULL;
    size_t dels_len = 0;
    char buf[16384] __attribute__((aligned(NLMSG_ALIGNTO)));
    bool done = false;
    while (!done) {
        ssize_t len = recv(fd, buf, sizeof(buf), 0);
        if (len < 0) {
            if (errno == EINTR) continue;
            break;
        }
        int rem = (int)len;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, rem); h = NLMSG_NEXT(h, rem)) {
            if (h->nlmsg_type == NLMSG_DONE || h->nlmsg_type == NLMSG_ERROR) {
                done = true;
                break;
            }
            if (h->nlmsg_type != RTM_NEWROUTE) continue;
            struct rtmsg *r = NLMSG_DATA(h);
            uint32_t rtable = r->rtm_table;
            int alen = (int)RTM_PAYLOAD(h);
            for (struct rtattr *a = RTM_RTA(r); RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
                if (a->rta_type == RTA_TABLE) memcpy(&rtable, RTA_DATA(a), sizeof(rtable));
            }
            if (rtable != (uint32_t)table) continue;
            size_t sz = NLMSG_ALIGN(h->nlmsg_len);
            char *grown = realloc(dels, dels_len + sz);
            if (!grown) continue;
            dels = grown;
            memcpy(dels + dels_len, h, h->nlmsg_len);
            dels_len += sz;
        }
    }
    close(fd);

    int deleted = 0;
    for (size_t off = 0; off < dels_len;) {
        struct nlmsghdr *h = (struct nlmsghdr *)(dels + off);
        off += NLMSG_ALIGN(h->nlmsg_len);
        h->nlmsg_type = RTM_DELROUTE;
        h->nlmsg_flags = 0;
        if (nl_transact(NETLINK_ROUTE, h) == 0) deleted++;
    }
    free(dels);
    return deleted;
}

static int rule_msg(uint16_t type, uint16_t flags, const char *src_ip, int pref, int table) {
    uint8_t a[16];
    int fam = parse_ip(src_ip, a);
    if (fam == 0) return -EINVAL;

    NlMsg m;
    struct fib_rule_hdr *fr = nl_init(&m, type, flags, sizeof(*fr));
    fr->family = (uint8_t)fam;
    fr->src_len = (fam == AF_INET) ? 32 : 128;
    if (table > 0) {
        fr->action = FR_ACT_TO_TBL;
        fr->table = (table < 256) ? (uint8_t)table : RT_TABLE_UNSPEC;
        uint32_t t = (uint32_t)table;
        nl_attr(&m, FRA_TABLE, &t, sizeof(t));
    } else {
        fr->action = FR_ACT_BLACKHOLE;
    }
    nl_attr(&m, FRA_SRC, a, (fam == AF_INET) ? 4 : 16);
    if (pref >= 0) {
        uint32_t p = (uint32_t)pref;
        nl_attr(&m, FRA_PRIORITY, &p, sizeof(p));
    }
    return nl_transact(NETLINK_ROUTE, &m.n);
}

int sysnet_rule_add(const char *src_ip, int pref, int table) {
    int ret = rule_msg(RTM_NEWRULE, NLM_F_CREATE | NLM_F_EXCL, src_ip, pref, table);
    return (ret == -EEXIST) ? 0 : ret;
}

int sysnet_rule_del(const char *src_ip, int table) {
    int ret = 0;
    int n = 0;
    while (n < 64 && (ret = rule_msg(RTM_DELRULE, 0, src_ip, -1, table)) == 0) n++;
    return (n > 0) ? 0 : ret;
}

int sysnet_neigh_del(const char *ip, const char *dev) {
    unsigned int idx = if_nametoindex(dev);
    if (idx == 0) return -ENODEV;
    uint8_t a[16];
    int fam = parse_ip(ip, a);
    if (fam == 0) return -EINVAL;

    NlMsg m;
    struct ndmsg *nd = nl_init(&m, RTM_DELNEIGH, 0, sizeof(*nd));
    nd->ndm_family = (uint8_t)fam;
    nd->ndm_ifindex = (int)idx;
    nl_attr(&m, NDA_DST, a, (fam == AF_INET) ? 4 : 16);
    return nl_transact(NETLINK_ROUTE, &m.n);
}

int sysnet_sysctl_set(const char *key, const char *val) {
    if (!key || !val || strstr(key, "..")) return -EINVAL;
    char path[256];
    snprintf(path, sizeof(path), "/proc/sys/%s", key);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -errno;
    size_t len = strlen(val);
    ssize_t w = write(fd, val, len);
    int ret = (w == (ssize_t)len) ? 0 : ((w < 0) ? -errno : -EIO);
    close(fd);
    return ret;
}

int sysnet_conntrack_del_tcp(int family, const void *src, uint16_t sport, const void *dst, uint16_t dport) {
    if (family != AF_INET && family != AF_INET6) return -EAFNOSUPPORT;
    size_t alen = (family == AF_INET) ? 4 : 16;

    NlMsg m;
    struct nfgenmsg *nfg = nl_init(&m, (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_DELETE, 0, sizeof(*nfg));
    nfg->nfgen_family = (uint8_t)family;
    nfg->version = NFNETLINK_V0;

    struct rtattr *orig = nl_attr(&m, CTA_TUPLE_ORIG | NLA_F_NESTED, NULL, 0);
    struct rtattr *ipn = nl_attr(&m, CTA_TUPLE_IP | NLA_F_NESTED, NULL, 0);
    nl_attr(&m, (family == AF_INET) ? CTA_IP_V4_SRC : CTA_IP_V6_SRC, src, alen);
    nl_attr(&m, (family == AF_INET) ? CTA_IP_V4_DST : CTA_IP_V6_DST, dst, alen);
    nl_nest_end(&m, ipn);
    struct rtattr *pn = nl_attr(&m, CTA_TUPLE_PROTO | NLA_F_NESTED, NULL, 0);
    uint8_t proto = IPPROTO_TCP;
    nl_attr(&m, CTA_PROTO_NUM, &proto, sizeof(proto));
    nl_attr(&m, CTA_PROTO_SRC_PORT, &sport, sizeof(sport));
    nl_attr(&m, CTA_PROTO_DST_PORT, &dport, sizeof(dport));
    nl_nest_end(&m, pn);
    nl_nest_end(&m, orig);

    int ret = nl_transact(NETLINK_NETFILTER, &m.n);
    return (ret == -ENOENT) ? 0 : ret;
}

int sysnet_arp_delete(const char *ip) { (void)ip; return -ENOTSUP; }
int sysnet_arp_publish(const char *ip, const char *ifname, const uint8_t mac[6]) {
    (void)ip; (void)ifname; (void)mac;
    return -ENOTSUP;
}

#elif defined(__APPLE__)
#include <sys/sockio.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#define SA_ROUNDUP(a) ((a) > 0 ? (1 + (((a) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))

int sysnet_addr_add(const char *ifname, const char *ip, int prefix, const char *label) {
    (void)label;
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return -EAFNOSUPPORT;
    if (prefix < 0 || prefix > 32) prefix = 32;

    struct ifaliasreq ifra;
    memset(&ifra, 0, sizeof(ifra));
    snprintf(ifra.ifra_name, sizeof(ifra.ifra_name), "%s", ifname);
    struct sockaddr_in *sa = (struct sockaddr_in *)&ifra.ifra_addr;
    sa->sin_len = sizeof(*sa);
    sa->sin_family = AF_INET;
    sa->sin_addr = a;
    struct sockaddr_in *sm = (struct sockaddr_in *)&ifra.ifra_mask;
    sm->sin_len = sizeof(*sm);
    sm->sin_family = AF_INET;
    sm->sin_addr.s_addr = (prefix == 0) ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -errno;
    int ret = (ioctl(s, SIOCAIFADDR, &ifra) < 0) ? -errno : 0;
    close(s);
    return ret;
}

int sysnet_addr_del(const char *ifname, const char *ip, int prefix) {
    (void)prefix;
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) return -EAFNOSUPPORT;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    struct sockaddr_in *sa = (struct sockaddr_in *)&ifr.ifr_addr;
    sa->sin_len = sizeof(*sa);
    sa->sin_family = AF_INET;
    sa->sin_addr = a;

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -errno;
    int ret = (ioctl(s, SIOCDIFADDR, &ifr) < 0) ? -errno : 0;
    close(s);
    return ret;
}

typedef struct {
    struct rt_msghdr rtm;
    char space[512];
} RtSockMsg;

static void rtsock_append(RtSockMsg *m, char **cp, const void *sa, size_t sa_len) {
    if ((size_t)(*cp - (char *)m) + SA_ROUNDUP(sa_len) > sizeof(*m)) return;
    memcpy(*cp, sa, sa_len);
    *cp += SA_ROUNDUP(sa_len);
}

/* Mirrors arp(8) delete: RTM_GET the entry, then send the returned message back as RTM_DELETE */
int sysnet_arp_delete(const char *ip) {
    struct sockaddr_inarp dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_len = sizeof(dst);
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) return -EINVAL;

    int s = socket(PF_ROUTE, SOCK_RAW, 0);
    if (s < 0) return -errno;
    struct timeval tv = {1, 0};
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    RtSockMsg m;
    memset(&m, 0, sizeof(m));
    char *cp = m.space;
    rtsock_append(&m, &cp, &dst, sizeof(dst));
    int seq = (int)atomic_fetch_add_explicit(&s_seq, 1, memory_order_relaxed);
    m.rtm.rtm_msglen = (u_short)(cp - (char *)&m);
    m.rtm.rtm_version = RTM_VERSION;
    m.rtm.rtm_type = RTM_GET;
    m.rtm.rtm_addrs = RTA_DST;
    m.rtm.rtm_seq = seq;

    int ret = 0;
    if (write(s, &m, m.rtm.rtm_msglen) < 0) {
        ret = -errno;
        close(s);
        return ret;
    }
    pid_t pid = getpid();
    ssize_t n;
    do {
        n = read(s, &m, sizeof(m));
    } while (n > 0 && (m.rtm.rtm_seq != seq || m.rtm.rtm_pid != pid));
    if (n <= 0) {
        close(s);
        return (n < 0) ? -errno : -EIO;
    }
    if (!(m.rtm.rtm_flags & RTF_LLINFO) || (m.rtm.rtm_flags & RTF_GATEWAY)) {
        close(s);
        return -ENOENT;
    }
    m.rtm.rtm_type = RTM_DELETE;
    m.rtm.rtm_seq = (int)atomic_fetch_add_explicit(&s_seq, 1, memory_order_relaxed);
    ret = (write(s, &m, m.rtm.rtm_msglen) < 0) ? -errno : 0;
    close(s);
    return ret;
}

/* Equivalent of `arp -S <ip> <mac> pub`: permanent published entry */
int sysnet_arp_publish(const char *ip, const char *ifname, const uint8_t mac[6]) {
    unsigned int idx = if_nametoindex(ifname);
    if (idx == 0) return -ENODEV;

    struct sockaddr_inarp dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_len = sizeof(dst);
    dst.sin_family = AF_INET;
    if (inet_pton(AF_INET, ip, &dst.sin_addr) != 1) return -EINVAL;

    sysnet_arp_delete(ip);

    struct sockaddr_dl gw;
    memset(&gw, 0, sizeof(gw));
    gw.sdl_len = sizeof(gw);
    gw.sdl_family = AF_LINK;
    gw.sdl_index = (u_short)idx;
    gw.sdl_type = IFT_ETHER;
    gw.sdl_alen = 6;
    memcpy(LLADDR(&gw), mac, 6);

    struct sockaddr_in mask;
    memset(&mask, 0, sizeof(mask));
    mask.sin_len = 8;
    mask.sin_addr.s_addr = 0xFFFFFFFFu;

    RtSockMsg m;
    memset(&m, 0, sizeof(m));
    char *cp = m.space;
    rtsock_append(&m, &cp, &dst, sizeof(dst));
    rtsock_append(&m, &cp, &gw, sizeof(gw));
    rtsock_append(&m, &cp, &mask, mask.sin_len);
    m.rtm.rtm_msglen = (u_short)(cp - (char *)&m);
    m.rtm.rtm_version = RTM_VERSION;
    m.rtm.rtm_type = RTM_ADD;
    m.rtm.rtm_flags = RTF_STATIC | RTF_ANNOUNCE;
    m.rtm.rtm_addrs = RTA_DST | RTA_GATEWAY | RTA_NETMASK;
    m.rtm.rtm_seq = (int)atomic_fetch_add_explicit(&s_seq, 1, memory_order_relaxed);

    int s = socket(PF_ROUTE, SOCK_RAW, 0);
    if (s < 0) return -errno;
    int ret = (write(s, &m, m.rtm.rtm_msglen) < 0) ? -errno : 0;
    close(s);
    return ret;
}
#endif

#if !defined(__linux__)
int sysnet_link_add_macvlan(const char *parent, const char *name, const uint8_t *mac) {
    (void)parent; (void)name; (void)mac;
    return -ENOTSUP;
}
int sysnet_link_del(const char *name) { (void)name; return -ENOTSUP; }
int sysnet_link_set_promisc(const char *name, bool on) { (void)name; (void)on; return -ENOTSUP; }
int sysnet_link_set_mac(const char *name, const uint8_t mac[6]) { (void)name; (void)mac; return -ENOTSUP; }
bool sysnet_link_get_perm_mac(const char *name, uint8_t out_mac[6]) { (void)name; (void)out_mac; return false; }
int sysnet_route_replace(int table, const char *dst_cidr, const char *gw, const char *dev, const char *src) {
    (void)table; (void)dst_cidr; (void)gw; (void)dev; (void)src;
    return -ENOTSUP;
}
int sysnet_route_flush_table(int table) { (void)table; return -ENOTSUP; }
int sysnet_rule_add(const char *src_ip, int pref, int table) { (void)src_ip; (void)pref; (void)table; return -ENOTSUP; }
int sysnet_rule_del(const char *src_ip, int table) { (void)src_ip; (void)table; return -ENOTSUP; }
int sysnet_neigh_del(const char *ip, const char *dev) { (void)ip; (void)dev; return -ENOTSUP; }
int sysnet_sysctl_set(const char *key, const char *val) { (void)key; (void)val; return -ENOTSUP; }
int sysnet_conntrack_del_tcp(int family, const void *src, uint16_t sport, const void *dst, uint16_t dport) {
    (void)family; (void)src; (void)sport; (void)dst; (void)dport;
    return -ENOTSUP;
}
#endif

#if !defined(__linux__) && !defined(__APPLE__)
int sysnet_addr_add(const char *ifname, const char *ip, int prefix, const char *label) {
    (void)ifname; (void)ip; (void)prefix; (void)label;
    return -ENOTSUP;
}
int sysnet_addr_del(const char *ifname, const char *ip, int prefix) { (void)ifname; (void)ip; (void)prefix; return -ENOTSUP; }
int sysnet_arp_delete(const char *ip) { (void)ip; return -ENOTSUP; }
int sysnet_arp_publish(const char *ip, const char *ifname, const uint8_t mac[6]) {
    (void)ip; (void)ifname; (void)mac;
    return -ENOTSUP;
}
#endif
