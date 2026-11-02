#define _GNU_SOURCE
#include "advlb/ssl_engine.h"
#include "advlb/tui.h"
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

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

    // 1. Enforce minimum TLS 1.2 protocol version (disables SSLv2, SSLv3, TLS 1.0, TLS 1.1)
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // 2. Security options:
    // - SSL_OP_NO_COMPRESSION: Mitigate CRIME attack by disabling TLS compression
    // - SSL_OP_CIPHER_SERVER_PREFERENCE: Force server cipher preferences over client
    // - SSL_OP_NO_RENEGOTIATION: Prevent client-initiated TLS renegotiation DoS attacks
    // - SSL_OP_SINGLE_ECDH_USE / SSL_OP_SINGLE_DH_USE: Ensure Perfect Forward Secrecy (PFS)
    long ssl_opts = SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE;
#ifdef SSL_OP_NO_RENEGOTIATION
    ssl_opts |= SSL_OP_NO_RENEGOTIATION;
#endif
#ifdef SSL_OP_SINGLE_ECDH_USE
    ssl_opts |= SSL_OP_SINGLE_ECDH_USE;
#endif
#ifdef SSL_OP_SINGLE_DH_USE
    ssl_opts |= SSL_OP_SINGLE_DH_USE;
#endif
    SSL_CTX_set_options(ctx, ssl_opts);

    // 3. Modern Cipher Suites configuration (Mozilla Intermediate Profile)
    // Strictly require forward secrecy (ECDHE/DHE) and authenticated encryption (GCM/ChaCha20)
    // Exclude insecure ciphers (NULL, EXPORT, DES, 3DES, RC4, MD5, PSK)
    const char *tls12_ciphers = "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                "ECDHE-RSA-AES128-GCM-SHA256:"
                                "ECDHE-ECDSA-AES256-GCM-SHA384:"
                                "ECDHE-RSA-AES256-GCM-SHA384:"
                                "ECDHE-ECDSA-CHACHA20-POLY1305:"
                                "ECDHE-RSA-CHACHA20-POLY1305:"
                                "DHE-RSA-AES128-GCM-SHA256:"
                                "DHE-RSA-AES256-GCM-SHA384:"
                                "!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!3DES";
    if (SSL_CTX_set_cipher_list(ctx, tls12_ciphers) <= 0) {
        cleanup_tui();
        ERR_print_errors_fp(stderr);
        fprintf(stderr, "Error configuring TLS 1.2 cipher suites\n");
        exit(EXIT_FAILURE);
    }

    // TLS 1.3 ciphersuites (RFC 8446)
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
    const char *tls13_ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
    SSL_CTX_set_ciphersuites(ctx, tls13_ciphers);
#endif

    // 4. ECDH Curves configuration (X25519, P-256, P-384)
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
    SSL_CTX_set1_curves_list(ctx, "X25519:prime256v1:secp384r1");
#endif

    // 5. Server Session Cache configuration with isolated session ID context
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);
    const unsigned char session_ctx_id[] = "AdvancedLoadBalancer";
    SSL_CTX_set_session_id_context(ctx, session_ctx_id, sizeof(session_ctx_id) - 1);

    // 6. Certificate and private key loading
    struct stat key_stat;
    if (stat(key_path, &key_stat) == 0) {
        if (!S_ISREG(key_stat.st_mode)) {
            cleanup_tui();
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m SSL private key '%s' is not a regular file\n", key_path);
            exit(EXIT_FAILURE);
        }
        if ((key_stat.st_mode & 0077) != 0) {
            cleanup_tui();
            fprintf(stderr, "\033[1;31m[ERROR]\033[0m Insecure file permissions on SSL private key '%s' (%04o).\n",
                    key_path, (unsigned int)(key_stat.st_mode & 0777));
            fprintf(stderr, "SSL private keys must not be accessible by group or others (required: 0600 or 0400).\n");
            fprintf(stderr, "Hint: fix with 'chmod 600 %s'\n", key_path);
            exit(EXIT_FAILURE);
        }
    }

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

