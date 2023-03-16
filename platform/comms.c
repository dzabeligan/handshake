/**
 * File: comms.cpp
 * -------------------
 * Implements comms.h interface.
 */

#include "comms.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef ITEX_OPENSSL
#include <openssl/ssl.h>

static int resolveHost(char* hostname, char* ip) {
  struct hostent* hent;
  struct in_addr** addr_list;
  int i;
  if ((hent = gethostbyname(hostname)) == NULL) {
    herror("gethostbyname error");
    return 1;
  }
  addr_list = (struct in_addr**)hent->h_addr_list;
  for (i = 0; addr_list[i] != NULL; i++) {
    strcpy(ip, inet_ntoa(*addr_list[i]));
    return 0;
  }
  return 1;
}

static void showSslCerts(SSL* ssl) {
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
    free(line);      /* free the malloc'ed string */
    X509_free(cert); /* free the malloc'ed certificate copy */
  } else {
    printf("No certificates.\n");
  }
}

static SSL_CTX* middlewareContext(void) {
  static SSL_CTX* serverContext = NULL;
  if (!serverContext) {
    serverContext = SSL_CTX_new(SSLv23_client_method());
  }
  return serverContext;
}

static int sslRead(SSL* sslHandle, unsigned char* buffer, int readSize,
                   const ComSentinel recevSentinel, const char* endTag) {
  int totalReceived = 0;
  fd_set fds;
  struct timeval timeout;

  if (!sslHandle) {
    return 0;
  }
  int count = 0;
  while (count++ < 6) {
    int received =
        SSL_read(sslHandle, &buffer[totalReceived], readSize - totalReceived);
    if (received > 0) {
      totalReceived += received;
      if (recevSentinel && recevSentinel(buffer, totalReceived, endTag)) {
        break;
      }
    }

    int err = SSL_get_error(sslHandle, received);
    switch (err) {
      case SSL_ERROR_NONE: {
        // no real error, just try again...
        printf("SSL_ERROR_NONE %i\n", count);
        continue;
      }

      case SSL_ERROR_ZERO_RETURN: {
        // peer disconnected...
        printf("SSL_ERROR_ZERO_RETURN %i\n", count);
        break;
      }

      case SSL_ERROR_WANT_READ: {
        // no data available right now, wait a few seconds in case
        // new data arrives...
        printf("SSL_ERROR_WANT_READ %i\n", count);

        int sock = SSL_get_rfd(sslHandle);
        FD_ZERO(&fds);
        FD_SET(sock, &fds);

        timeout.tv_sec = 10;
        timeout.tv_usec = 0;

        err = select(sock + 1, &fds, NULL, NULL, &timeout);
        if (err > 0) continue;  // more data to read...

        if (err == 0) {
          // timeout...
        } else {
          // error...
        }

        break;
      }

      default: {
        printf("error %i:%i\n", received, err);
        break;
      }
    }

    break;
  }

  return totalReceived;
}

int comSendReceive(unsigned char* response, const size_t rSize,
                   const unsigned char* request, const size_t len,
                   const char* url, const int port,
                   ConnectionType connectionType,
                   const ComSentinel recevSentinel, const char* endTag) {
  int sockfd = 0, n = 0;
  struct timeval timeout;
  struct sockaddr_in serv_addr;
  short ret = -1;
  char resolvedIp[32] = {'\0'};
  (void)connectionType;

  SSL* ssl;

  timeout.tv_sec = 30;
  timeout.tv_usec = 0;

  if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("\n Error : Could not create socket \n");
    return -1;
  }

  memset(&serv_addr, '0', sizeof(serv_addr));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_port = htons(port);

  resolveHost(url, resolvedIp);
  if (inet_pton(AF_INET, resolvedIp, &serv_addr.sin_addr) <= 0) {
    printf("\n inet_pton error occured\n");
    goto clean_exit;
  }

  if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
    printf("\n Error : Connect Failed \n");
    goto clean_exit;
  }

  if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout,
                 sizeof(timeout)) < 0) {
    printf("\n Error : Set Recv Timeout Failed \n");
  }

  ssl = SSL_new(middlewareContext());
  if (ssl == NULL) {
    goto clean_exit;
  }

  SSL_set_fd(ssl, sockfd);
  if (SSL_connect(ssl) <= 0) {
    fprintf(stderr, "SSl conn.\n");
    goto clean_ssl;
  }
  showSslCerts(ssl);

  n = SSL_write(ssl, request, len);
  if ((size_t)n != len) {
    goto clean_ssl;
  }

  n = sslRead(ssl, response, rSize - 1, recevSentinel, endTag);

  ret = n > 0 ? n : 0;

clean_ssl:
  SSL_shutdown(ssl);
  SSL_free(ssl);
clean_exit:
  close(sockfd);
  return ret;
}
#else

int comSendReceive(unsigned char* response, const size_t rSize,
                   const unsigned char* request, const size_t len,
                   const char* url, const int port,
                   ConnectionType connectionType,
                   const ComSentinel recevSentinel, const char* endTag) {
  (void)response;
  (void)rSize;
  (void)request;
  (void)len;
  (void)url;
  (void)port;
  (void)recevSentinel;
  (void)connectionType;
  (void)endTag;

  return 0;
}

#endif
