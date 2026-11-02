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

int net_build_proxy_v1_header_storage(char *out_buf, size_t max_len,
                                      const struct sockaddr_storage *client_addr,
                                      const struct sockaddr_storage *lb_addr) {
    if (!out_buf || max_len == 0) return -1;

    if (!client_addr || !lb_addr) {
        return snprintf(out_buf, max_len, "PROXY UNKNOWN\r\n");
    }

    if (client_addr->ss_family == AF_INET6 && lb_addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *c6 = (const struct sockaddr_in6 *)client_addr;
        const struct sockaddr_in6 *l6 = (const struct sockaddr_in6 *)lb_addr;
        char c_ip[INET6_ADDRSTRLEN] = "UNKNOWN";
        char l_ip[INET6_ADDRSTRLEN] = "UNKNOWN";
        inet_ntop(AF_INET6, &c6->sin6_addr, c_ip, sizeof(c_ip));
        inet_ntop(AF_INET6, &l6->sin6_addr, l_ip, sizeof(l_ip));
        return snprintf(out_buf, max_len, "PROXY TCP6 %s %s %d %d\r\n",
                        c_ip, l_ip, ntohs(c6->sin6_port), ntohs(l6->sin6_port));
    } else if (client_addr->ss_family == AF_INET && lb_addr->ss_family == AF_INET) {
        const struct sockaddr_in *c4 = (const struct sockaddr_in *)client_addr;
        const struct sockaddr_in *l4 = (const struct sockaddr_in *)lb_addr;
        char c_ip[INET_ADDRSTRLEN] = "UNKNOWN";
        char l_ip[INET_ADDRSTRLEN] = "UNKNOWN";
        inet_ntop(AF_INET, &c4->sin_addr, c_ip, sizeof(c_ip));
        inet_ntop(AF_INET, &l4->sin_addr, l_ip, sizeof(l_ip));
        return snprintf(out_buf, max_len, "PROXY TCP4 %s %s %d %d\r\n",
                        c_ip, l_ip, ntohs(c4->sin_port), ntohs(l4->sin_port));
    }

    return snprintf(out_buf, max_len, "PROXY UNKNOWN\r\n");
}

int net_build_proxy_v1_header(char *out_buf, size_t max_len,
                              const struct sockaddr_in *client_addr,
                              const struct sockaddr_in *lb_addr) {
    struct sockaddr_storage cs, ls;
    memset(&cs, 0, sizeof(cs));
    memset(&ls, 0, sizeof(ls));
    if (client_addr) {
        memcpy(&cs, client_addr, sizeof(*client_addr));
    }
    if (lb_addr) {
        memcpy(&ls, lb_addr, sizeof(*lb_addr));
    }
    return net_build_proxy_v1_header_storage(out_buf, max_len, client_addr ? &cs : NULL, lb_addr ? &ls : NULL);
}

bool net_try_parse_proxy_v1_header(int fd, struct sockaddr_storage *out_client_addr, bool *out_need_more_data) {
    if (out_need_more_data) *out_need_more_data = false;
    char buf[PPV1_MAX_HEADER_LEN + 1];

    ssize_t n = recv(fd, buf, PPV1_MAX_HEADER_LEN, MSG_PEEK | MSG_DONTWAIT);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            if (out_need_more_data) *out_need_more_data = true;
            return false;
        }
        return false;
    }
    if (n == 0) {
        return false;
    }

    size_t total_peeked = (size_t)n;
    buf[total_peeked] = '\0';

    // Must start with "PROXY " as soon as 6 bytes arrive
    if (total_peeked >= 6 && memcmp(buf, "PROXY ", 6) != 0) {
        return false;
    }

    char *crlf = strstr(buf, "\r\n");
    if (!crlf) {
        if (total_peeked >= PPV1_MAX_HEADER_LEN) {
            // Header length exceeded maximum allowed without CRLF
            return false;
        }
        if (out_need_more_data) *out_need_more_data = true;
        return false;
    }

    size_t header_len = (size_t)((crlf - buf) + 2);
    if (header_len > PPV1_MAX_HEADER_LEN || header_len < 8) {
        return false;
    }

    // Consume header from socket buffer
    size_t consumed_total = 0;
    while (consumed_total < header_len) {
        ssize_t cr = read(fd, buf + consumed_total, header_len - consumed_total);
        if (cr <= 0) {
            if (cr < 0 && errno == EINTR) continue;
            return false;
        }
        consumed_total += (size_t)cr;
    }
    buf[header_len - 2] = '\0'; // strip CRLF

    char proto[16] = {0};
    char src_ip[64] = {0};
    char dst_ip[64] = {0};
    int src_port = 0;
    int dst_port = 0;
    char extra[16] = {0};

    int tokens = sscanf(buf, "PROXY %15s %63s %63s %d %d %15s",
                        proto, src_ip, dst_ip, &src_port, &dst_port, extra);

    if (strcmp(proto, "UNKNOWN") == 0) {
        return true;
    }

    if (tokens == 5 && strcmp(proto, "TCP4") == 0) {
        if (src_port < 1 || src_port > 65535 || dst_port < 1 || dst_port > 65535) {
            return false;
        }
        struct in_addr src_in, dst_in;
        if (inet_pton(AF_INET, src_ip, &src_in) != 1 || inet_pton(AF_INET, dst_ip, &dst_in) != 1) {
            return false;
        }
        if (out_client_addr) {
            struct sockaddr_in *sin = (struct sockaddr_in *)out_client_addr;
            memset(sin, 0, sizeof(struct sockaddr_in));
            sin->sin_family = AF_INET;
            sin->sin_port = htons((uint16_t)src_port);
            sin->sin_addr = src_in;
        }
        return true;
    } else if (tokens == 5 && strcmp(proto, "TCP6") == 0) {
        if (src_port < 1 || src_port > 65535 || dst_port < 1 || dst_port > 65535) {
            return false;
        }
        struct in6_addr src_in6, dst_in6;
        if (inet_pton(AF_INET6, src_ip, &src_in6) != 1 || inet_pton(AF_INET6, dst_ip, &dst_in6) != 1) {
            return false;
        }
        if (out_client_addr) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out_client_addr;
            memset(sin6, 0, sizeof(struct sockaddr_in6));
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = htons((uint16_t)src_port);
            sin6->sin6_addr = src_in6;
        }
        return true;
    }

    return false;
}

bool net_parse_proxy_v1_header(int fd, struct sockaddr_in *out_client_addr) {
    time_t start_time = time(NULL);
    const int timeout_ms = 3000;

    while (1) {
        bool need_more = false;
        struct sockaddr_storage ss;
        memset(&ss, 0, sizeof(ss));

        if (net_try_parse_proxy_v1_header(fd, &ss, &need_more)) {
            if (out_client_addr && ss.ss_family == AF_INET) {
                memcpy(out_client_addr, &ss, sizeof(struct sockaddr_in));
            }
            return true;
        }

        if (!need_more) {
            return false;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int elapsed_ms = (int)((time(NULL) - start_time) * 1000);
        int rem_ms = timeout_ms - elapsed_ms;
        if (rem_ms <= 0) return false;

        int pr = poll(&pfd, 1, rem_ms);
        if (pr <= 0) return false;
    }
}
