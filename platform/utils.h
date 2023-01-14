#ifndef UTILS_H
#define UTILS_H

#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

void showSslCerts(SSL* ssl);
SSL_CTX* middlewareContext();

#ifdef __cplusplus
}
#endif

#endif
