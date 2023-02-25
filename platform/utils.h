#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ITEX_OPENSSL
#include <openssl/ssl.h>

void showSslCerts(SSL* ssl);
SSL_CTX* middlewareContext();
#endif

#ifdef __cplusplus
}
#endif

#endif
