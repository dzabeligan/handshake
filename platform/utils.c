#include "utils.h"

void showSslCerts(SSL* ssl)
{
    X509* cert;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if (cert != NULL) {
        char* line;
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line); /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line); /* free the malloc'ed string */
        X509_free(cert); /* free the malloc'ed certificate copy */
    } else {
        printf("No certificates.\n");
    }
}

SSL_CTX* middlewareContext()
{
    static SSL_CTX* serverContext = NULL;
    if (!serverContext) {
        serverContext = SSL_CTX_new(SSLv23_client_method());
    }
    return serverContext;
}
