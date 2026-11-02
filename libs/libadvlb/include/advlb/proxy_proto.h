#ifndef ADVLB_PROXY_PROTO_H
#define ADVLB_PROXY_PROTO_H

#include "advnet/advnet.h"

static inline int build_proxy_protocol_v1_header(char *out_buf, size_t max_len,
                                                 const struct sockaddr_in *client_addr,
                                                 const struct sockaddr_in *lb_addr) {
    return net_build_proxy_v1_header(out_buf, max_len, client_addr, lb_addr);
}

static inline bool parse_proxy_protocol_v1(int fd, struct sockaddr_in *out_client_addr) {
    return net_parse_proxy_v1_header(fd, out_client_addr);
}

#endif /* ADVLB_PROXY_PROTO_H */
