#define _GNU_SOURCE
#include "advlb/proxy_proto.h"
#include "advnet/advnet.h"

// The functions build_proxy_protocol_v1_header and parse_proxy_protocol_v1
// are defined inline in advlb/proxy_proto.h as wrappers around net_build_proxy_v1_header and net_parse_proxy_v1_header.
// This source file provides exported symbols if non-inline linking is required.
int build_proxy_protocol_v1_header_export(char *out_buf, size_t max_len,
                                          const struct sockaddr_in *client_addr,
                                          const struct sockaddr_in *lb_addr) {
    return net_build_proxy_v1_header(out_buf, max_len, client_addr, lb_addr);
}

bool parse_proxy_protocol_v1_export(int fd, struct sockaddr_in *out_client_addr) {
    return net_parse_proxy_v1_header(fd, out_client_addr);
}
