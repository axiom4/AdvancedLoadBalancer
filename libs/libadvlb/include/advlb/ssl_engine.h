#ifndef ADVLB_SSL_ENGINE_H
#define ADVLB_SSL_ENGINE_H

#include "advlb/compat_ssl.h"

extern SSL_CTX *g_global_ssl_ctx;

SSL_CTX *init_ssl_context(const char *cert_path, const char *key_path);
void cleanup_ssl_context(void);

#endif /* ADVLB_SSL_ENGINE_H */

