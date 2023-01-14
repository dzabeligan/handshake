#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <string.h>

#include "../platform/comms.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HANDSHAKE_SUCCESS,
    HANDSHAKE_FAILURE,
    HANDSHAKE_MAPTID_FAILURE,
    HANDSHAKE_MAPTID_SUCCESS,
} handshake_Status;

typedef enum {
    HANDSHAKE_MAPTID_FALSE,
    HANDSHAKE_MAPTID_TRUE,
} handshake_MapTid;

typedef enum {
    PLATFORM_NIBSS,
    PLATFORM_TAMS,
} Platform;

typedef enum {
    ERROR_CODE_NO_ERROR,
    ERROR_CODE_HANDSHAKE_INIT_ERROR,
    ERROR_CODE_ERROR,
} ErrorCode;

struct appInfo {
    char name[32];
    char version[32];
};

struct deviceInfo {
    char posUid[32];
    char model[32];
};

typedef struct Host {
    char host[65];
    int port;
    short isSsl;
    unsigned int receiveTimeout;
} Host;

typedef struct Error {
    ErrorCode code;
    char message[0x200];
} Error;

typedef int (*ComSendReceive)(unsigned char* response, const size_t rSize,
    const unsigned char* request, const size_t len, const char* ip,
    const int port, const HostRecvSentinel recevSentinel, const char* endTag);

typedef struct handshake_InitData {
    Platform platform;
    handshake_MapTid mapTid;
    char tid[9];
    struct appInfo appInfo;
    struct deviceInfo deviceInfo;
    Host host;

    // callback
    HostRecvSentinel hostSentinel;
    ComSendReceive comSendReceive;
} handshake_InitData;

typedef struct Handshake {
    Platform platform;
    handshake_MapTid mapTid;
    char tid[9];
    struct appInfo appInfo;
    struct deviceInfo deviceInfo;
    Host host;

    // callback
    HostRecvSentinel hostSentinel;
    ComSendReceive comSendReceive;

    Error error;
} Handshake;

handshake_Status Handshake_Run(Handshake* handshake);
void Handshake_Init(Handshake* handshake, handshake_InitData* initData);

#ifdef __cplusplus
}
#endif

#endif
