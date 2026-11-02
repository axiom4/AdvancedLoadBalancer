#ifndef ADVLB_COMPAT_SSL_H
#define ADVLB_COMPAT_SSL_H

#ifndef NO_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#else
#include <stddef.h>

typedef struct ssl_dummy SSL;
typedef struct ssl_ctx_dummy SSL_CTX;

#define SSL_pending(s) (0)
#define SSL_read(s, b, l) (-1)
#define SSL_write(s, b, l) (-1)
#define SSL_free(s) ((void)0)
#define SSL_shutdown(s) ((void)0)
#define SSL_CTX_free(c) ((void)0)
#define SSL_new(c) (NULL)
#define SSL_set_fd(s, f) ((void)0)
#define SSL_accept(s) (-1)
#define SSL_get_error(s, r) (0)
#define SSL_ERROR_WANT_READ 2
#define SSL_ERROR_WANT_WRITE 3
#define SSL_ERROR_SYSCALL 5
#endif

#endif /* ADVLB_COMPAT_SSL_H */

