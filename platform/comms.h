/**
 * File: itexComms.h
 * Defines a new interface for comms
 */
#ifndef _ITEX_COMMS_INCLUDED
#define _ITEX_COMMS_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <ctype.h>
#include <stdlib.h>

/**
 * @brief Server connection type
 *
 */
typedef enum {
  CONNECTION_TYPE_PLAIN,
  CONNECTION_TYPE_SSL,
} ConnectionType;

#define DEFAULT_TIMEOUT 120000

/**
 * @brief Host struct
 * @url: URL of host
 * @port: PORT
 * @connectionType: connection type enum
 * @receiveTimeout: connection timeout
 *
 */
typedef struct Host {
  char url[256];
  int port;
  ConnectionType connectionType;
} Host;

typedef struct NetworkBuffer {
  unsigned char data[0x4000];
  long len;
} NetworkBuffer;

typedef int (*ComSentinel)(unsigned char* packet, const int bytesRead,
                           const char* endTag);

/**
 * @brief Function pointer to send and receive data
 *
 */
typedef int (*ComSendReceive)(NetworkBuffer* response, NetworkBuffer* request,
                              Host* host, int receiveTimeoutms,
                              const ComSentinel recevSentinel,
                              const char* endTag);

int comSendReceive(NetworkBuffer* response, NetworkBuffer* request, Host* host,
                   int receiveTimeoutms, const ComSentinel recevSentinel,
                   const char* endTag);

#ifdef __cplusplus
}
#endif

#endif
