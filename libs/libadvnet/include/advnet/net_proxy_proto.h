#ifndef ADVNET_PROXY_PROTO_H
#define ADVNET_PROXY_PROTO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <netinet/in.h>

#define PPV1_MAX_HEADER_LEN 107

int net_build_proxy_v1_header(char *out_buf, size_t max_len,
                              const struct sockaddr_in *client_addr,
                              const struct sockaddr_in *lb_addr);

int net_build_proxy_v1_header_storage(char *out_buf, size_t max_len,
                                      const struct sockaddr_storage *client_addr,
                                      const struct sockaddr_storage *lb_addr);

bool net_parse_proxy_v1_header(int fd, struct sockaddr_in *out_client_addr);
bool net_try_parse_proxy_v1_header(int fd, struct sockaddr_storage *out_client_addr, bool *out_need_more_data);

#ifdef __cplusplus
}
#endif

#endif /* ADVNET_PROXY_PROTO_H */

