#define _GNU_SOURCE
#include "advnet/net_proxy_proto.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <errno.h>
#include <time.h>
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
    char buf[PPV1_MAX_HEADER_LEN + 1];
    size_t total_peeked = 0;
    time_t start_time = time(NULL);
    const int timeout_ms = 3000; // 3-second safety timeout against Slowloris

    // Loop with poll to safely handle TCP fragmentation without blocking
    while (total_peeked < PPV1_MAX_HEADER_LEN) {
        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int elapsed_ms = (int)((time(NULL) - start_time) * 1000);
        int remaining_ms = timeout_ms - elapsed_ms;
        if (remaining_ms <= 0) {
            return false;
        }

        int pr = poll(&pfd, 1, remaining_ms);
        if (pr <= 0) {
            return false;
        }

        ssize_t n = recv(fd, buf, sizeof(buf) - 1, MSG_PEEK);
        if (n <= 0) {
            return false;
        }
        total_peeked = (size_t)n;
        buf[total_peeked] = '\0';

        // Check if prefix starts with "PROXY " as soon as 6 bytes are available
        if (total_peeked >= 6 && memcmp(buf, "PROXY ", 6) != 0) {
            return false;
        }

        char *crlf = strstr(buf, "\r\n");
        if (crlf != NULL) {
            size_t header_len = (size_t)((crlf - buf) + 2);
            if (header_len > PPV1_MAX_HEADER_LEN || header_len < 8) {
                return false;
            }

            // Consume exactly the header bytes from the socket receive buffer
            size_t consumed_total = 0;
            while (consumed_total < header_len) {
                ssize_t cr = read(fd, buf + consumed_total, header_len - consumed_total);
                if (cr <= 0) {
                    if (cr < 0 && errno == EINTR) continue;
                    return false;
                }
                consumed_total += (size_t)cr;
            }
            buf[header_len - 2] = '\0'; // strip trailing CRLF

            char proto[16] = {0};
            char src_ip[64] = {0};
            char dst_ip[64] = {0};
            int src_port = 0;
            int dst_port = 0;
            char extra[16] = {0};

            int tokens = sscanf(buf, "PROXY %15s %63s %63s %d %d %15s",
                                proto, src_ip, dst_ip, &src_port, &dst_port, extra);

            // HAProxy v1 specification: PROXY UNKNOWN\r\n (keep existing transport address)
            if (strcmp(proto, "UNKNOWN") == 0) {
                return true;
            }

            // For TCP4: exactly 5 tokens, valid IPv4 addresses, and ports in 1-65535
            if (tokens == 5 && strcmp(proto, "TCP4") == 0) {
                if (src_port < 1 || src_port > 65535 || dst_port < 1 || dst_port > 65535) {
                    return false;
                }

                struct in_addr src_in, dst_in;
                if (inet_pton(AF_INET, src_ip, &src_in) != 1) {
                    return false;
                }
                if (inet_pton(AF_INET, dst_ip, &dst_in) != 1) {
                    return false;
                }

                if (out_client_addr != NULL) {
                    memset(out_client_addr, 0, sizeof(struct sockaddr_in));
                    out_client_addr->sin_family = AF_INET;
                    out_client_addr->sin_port = htons((uint16_t)src_port);
                    out_client_addr->sin_addr = src_in;
                }
                return true;
            }

            // Any other unsupported protocol or malformed format
            return false;
        }

        // Oversized header without CRLF: reject
        if (total_peeked >= PPV1_MAX_HEADER_LEN) {
            return false;
        }
    }

    return false;
}

