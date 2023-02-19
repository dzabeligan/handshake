/**
 * File: itexComms.h
 * Defines a new interface for comms
 */
#ifndef _ITEX_COMMS_INCLUDED
#define _ITEX_COMMS_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

typedef int (*HostRecvSentinel)(
    unsigned char* packet, const int bytesRead, const char* endTag);

int comSendReceive(unsigned char* response, const size_t rSize,
    const unsigned char* request, const size_t len, const char* ip,
    const int port, const HostRecvSentinel recevSentinel, const char* endTag);

#ifdef __cplusplus
}
#endif

#endif
