#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#ifdef ITEX_OPENSSL
#include <openssl/ssl.h>

void showSslCerts(SSL* ssl);
SSL_CTX* middlewareContext();
#endif

int getState(char* data, const size_t len);

#ifdef __cplusplus
}
#endif

#endif
