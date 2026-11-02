#define _GNU_SOURCE
#include "advnet/net_proxy_proto.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <arpa/inet.h>
#include <sys/socket.h>

int net_build_proxy_v1_header(char *out_buf, size_t max_len,
                              const struct sockaddr_in *client_addr,
                              const struct sockaddr_in *lb_addr) {
    char client_ip[INET_ADDRSTRLEN] = "UNKNOWN";
    char lb_ip[INET_ADDRSTRLEN] = "UNKNOWN";
    int client_port = 0;
    int lb_port = 0;

    if (client_addr != NULL) {
        inet_ntop(AF_INET, &(client_addr->sin_addr), client_ip, sizeof(client_ip));
        client_port = ntohs(client_addr->sin_port);
    }
    if (lb_addr != NULL) {
        inet_ntop(AF_INET, &(lb_addr->sin_addr), lb_ip, sizeof(lb_ip));
        lb_port = ntohs(lb_addr->sin_port);
    }

    return snprintf(out_buf, max_len, "PROXY TCP4 %s %s %d %d\r\n",
                    client_ip, lb_ip, client_port, lb_port);
}

bool net_parse_proxy_v1_header(int fd, struct sockaddr_in *out_client_addr) {
    char buf[128];
    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };

    int pr = poll(&pfd, 1, 1500);
    if (pr <= 0) return false;

    ssize_t peeked = recv(fd, buf, sizeof(buf) - 1, MSG_PEEK);
    if (peeked < 8) return false;
    buf[peeked] = '\0';

    if (strncmp(buf, "PROXY ", 6) != 0) {
        return false;
    }

    char *crlf = strstr(buf, "\r\n");
    if (!crlf) return false;

    size_t header_len = (size_t)((crlf - buf) + 2);
    ssize_t consumed = read(fd, buf, header_len);
    if (consumed != (ssize_t)header_len) return false;
    buf[header_len - 2] = '\0';

    char proto[16], src_ip[64], dst_ip[64];
    int src_port = 0, dst_port = 0;
    if (sscanf(buf, "PROXY %15s %63s %63s %d %d", proto, src_ip, dst_ip, &src_port, &dst_port) == 5) {
        if (strcmp(proto, "TCP4") == 0 && out_client_addr != NULL) {
            out_client_addr->sin_family = AF_INET;
            out_client_addr->sin_port = htons((uint16_t)src_port);
            inet_pton(AF_INET, src_ip, &(out_client_addr->sin_addr));
            return true;
        }
    }
    return false;
}

