#define _GNU_SOURCE
#include "advlb/ssl_engine.h"
#include "advlb/tui.h"
#include <stdio.h>
#include <stdlib.h>

SSL_CTX *g_global_ssl_ctx = NULL;

#ifndef NO_SSL
SSL_CTX *init_ssl_context(const char *cert_path, const char *key_path) {
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        cleanup_tui();
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        cleanup_tui();
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error loading certificate: %s\n", cert_path);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        cleanup_tui();
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error loading private key: %s\n", key_path);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        cleanup_tui();
        fprintf(stderr, "Private key does not match the provided certificate!\n");
        exit(EXIT_FAILURE);
    }

    g_global_ssl_ctx = ctx;
    return ctx;
}
#else
SSL_CTX *init_ssl_context(const char *cert_path, const char *key_path) {
    (void)cert_path;
    (void)key_path;
    cleanup_tui();
    fprintf(stderr, "\033[1;31m[ERROR] Program was compiled without OpenSSL support (-DNO_SSL).\033[0m\n");
    exit(EXIT_FAILURE);
}
#endif

void cleanup_ssl_context(void) {
    if (g_global_ssl_ctx) {
        SSL_CTX_free(g_global_ssl_ctx);
        g_global_ssl_ctx = NULL;
    }
}

