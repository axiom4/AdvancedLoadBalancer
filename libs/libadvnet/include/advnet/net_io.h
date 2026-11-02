#ifndef ADVNET_IO_H
#define ADVNET_IO_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>

// Complete write with safety timeout against blocking
ssize_t net_write_all(int fd, const char *buf, size_t len, int timeout_ms);

// Read retry on EINTR
ssize_t net_read_retry(int fd, char *buf, size_t len);

// Non-blocking I/O for high-performance proxy forwarding
ssize_t net_write_nonblocking(int fd, const char *buf, size_t len, bool *out_want_io);
ssize_t net_read_nonblocking(int fd, char *buf, size_t max_len, bool *out_want_io);

#ifdef __cplusplus
}
#endif

#endif /* ADVNET_IO_H */

