#include <time.h>

#include "utils.h"

#ifdef ITEX_OPENSSL
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

SSL_CTX* middlewareContext(void)
{
    static SSL_CTX* serverContext = NULL;
    if (!serverContext) {
        serverContext = SSL_CTX_new(SSLv23_client_method());
    }
    return serverContext;
}
#endif

int getState(char* state, const size_t size)
{
    const char* str
        = "{\"ptad\": \"ITEX\",\"serial\": \"346228245\",\"bl\": 70,\"btemp\": "
          "30,\"ctime\": \"%s\",\"cs\": \"Charging\",\"ps\": "
          "\"PrinterAvailable\",\"tid\": \"2033GP24\",\"coms\": "
          "\"GSM/LTE\",\"sim\": \"\",\"simID\": "
          "\"621301234567890123456789\",\"imsi\": \"621301234567890\",\"ss\" : "
          "100,\"cloc\": "
          "\"{cid:\"0123\",lac:\"1234\",mcc:\"62130\",mnc:\"30\",ss:100dbm}\","
          "\"tmn\": \"LaptopPort\",\"tmanu\": \"Apple\",\"hb\": "
          "\"true\",\"lTxnAt\": \"%s\",\"sv\": \"0.0.1\",\"pads\": \"\"}";
    time_t now = time(NULL);
    struct tm now_t = *localtime(&now);
    char dateTimeBuff[64] = { '\0' };
    char lastTrans[16] = { '\0' };

    strftime(
        dateTimeBuff, sizeof(dateTimeBuff), "%a %d/%m/%Y %H:%M:%S", &now_t);
    strftime(lastTrans, sizeof(lastTrans), "%Y%m%d%H%M%S", &now_t);

    return snprintf(state, size, str, dateTimeBuff, lastTrans);
}
