#ifndef ADVLB_SYSNET_H
#define ADVLB_SYSNET_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Native OS network configuration used by the VRRP/HA layer.
 * Linux: rtnetlink, ctnetlink, ioctl and /proc/sys. macOS: ioctl and PF_ROUTE.
 * No external command is ever executed. All functions return 0 on success or -errno;
 * functions not available on the current platform return -ENOTSUP.
 */

/* Links (Linux) */
int  sysnet_link_add_macvlan(const char *parent, const char *name, const uint8_t *mac /* NULL = random */);
int  sysnet_link_del(const char *name);
int  sysnet_link_set_promisc(const char *name, bool on);
int  sysnet_link_set_mac(const char *name, const uint8_t mac[6]);
bool sysnet_link_get_perm_mac(const char *name, uint8_t out_mac[6]);

/* Addresses (Linux: IPv4/IPv6, macOS: IPv4 alias) */
int  sysnet_addr_add(const char *ifname, const char *ip, int prefix, const char *label /* NULL = none */);
int  sysnet_addr_del(const char *ifname, const char *ip, int prefix);

/* IPv4 routes in a policy table (Linux). dst_cidr NULL = default route; gw NULL = scope link */
int  sysnet_route_replace(int table, const char *dst_cidr, const char *gw, const char *dev, const char *src);
int  sysnet_route_flush_table(int table);

/* Source policy rules (Linux). table 0 = blackhole action. Delete removes every duplicate. */
int  sysnet_rule_add(const char *src_ip, int pref, int table);
int  sysnet_rule_del(const char *src_ip, int table);

/* Neighbour cache (Linux) */
int  sysnet_neigh_del(const char *ip, const char *dev);

/* Write /proc/sys/<key>, key in slash form, e.g. "net/ipv4/conf/all/rp_filter" (Linux) */
int  sysnet_sysctl_set(const char *key, const char *val);

/* Delete a TCP conntrack entry by original tuple; addresses raw, ports network order (Linux) */
int  sysnet_conntrack_del_tcp(int family, const void *src, uint16_t sport, const void *dst, uint16_t dport);

/* ARP table (macOS) */
int  sysnet_arp_delete(const char *ip);
int  sysnet_arp_publish(const char *ip, const char *ifname, const uint8_t mac[6]);

#ifdef __cplusplus
}
#endif

#endif /* ADVLB_SYSNET_H */
