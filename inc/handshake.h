/**
 * @file handshake.h
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Declares interface for Handshake
 * @version 0.1
 * @date 2023-02-07
 *
 * @copyright Copyright (c) 2023
 *
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include <string.h>

#include "../platform/comms.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    HANDSHAKE_MAPTID_FALSE,
    HANDSHAKE_MAPTID_TRUE,
} handshake_MapTid;

typedef enum {
    PLATFORM_NIBSS,
    PLATFORM_TAMS,
} Platform;

typedef enum {
    CONNECTION_TYPE_PLAIN,
    CONNECTION_TYPE_SSL,
} ConnectionType;

typedef enum {
    MIDDLEWARE_SERVER_TYPE_POSVAS,
    MIDDLEWARE_SERVER_TYPE_EPMS,
    MIDDLEWARE_SERVER_TYPE_UNKNOWN,
} MiddlewareServerType;

typedef enum {
    TERMINAL_APP_TYPE_MERCHANT,
    TERMINAL_APP_TYPE_AGENT,
    TERMINAL_APP_TYPE_CONVERTED,
    TERMINAL_APP_TYPE_UNKNOWN,
} TerminalAppType;

typedef enum {
    ERROR_CODE_NO_ERROR,
    ERROR_CODE_HANDSHAKE_INIT_ERROR,
    ERROR_CODE_HANDSHAKE_MAPTID_ERROR,
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
    ConnectionType connectionType;
    unsigned int receiveTimeout;
} Host;

typedef struct Error {
    ErrorCode code;
    char message[0x200];
} Error;

typedef struct Server {
    char publicIp[65];
    char privateIp[65];
    int publicPort;
    int privatePort;
} Server;

typedef struct TAMSResponse {
    char accountToDebit[16];
    char accountNumber[16];
    short accountSelectionType;
    char aggregatorName[128];
    char balance[16];
    char commision[16];
    char email[64];
    char merchantAddress[128];
    char merchantName[128];
    char notificationId[64];
    char phone[32];
    char posSupport[64];
    char preConnect[8];
    char rrn[16];
    char stampDuty[16];
    char stampDutyThreshold[16];
    char stampLabel[64];
    TerminalAppType terminalAppType;
    char userId[64];

    struct {
        char amp[5];
        char moreFun[5];
        char newLand[5];
        char newPos[5];
        char nexGo[5];
        char pax[5];
        char paySharp[5];
        char verifone[5];
    } terminals;

    struct {
        MiddlewareServerType middlewareServerType;
        Server tams;
        Server callhome;
        Server callhomePosvas;
        Server epmsSsl;
        Server epmsPlain;
        Server posvasSsl;
        Server posvasPlain;
        Server remoteUpgrade;
        char vasUrl[64];
        int callhomeTime;
        ConnectionType connectionType;
    } servers;
} TAMSResponse;

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
    TAMSResponse tamsResponse;

    // callback
    HostRecvSentinel hostSentinel;
    ComSendReceive comSendReceive;

    Error error;
} Handshake;

void Handshake_Init(Handshake* handshake, handshake_InitData* initData);
void Handshake_MapTid(Handshake* handshake);
void Handshake_Run(Handshake* handshake);

void logTamsResponse(TAMSResponse* tamsResponse);
void logTerminals(TAMSResponse* tamsResponse);
void logServers(TAMSResponse* tamsResponse);

#ifdef __cplusplus
}
#endif

#endif
