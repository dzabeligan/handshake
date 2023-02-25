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
    PTAD_KEY_UNKNOWN,
    PTAD_KEY_POSVAS,
    PTAD_KEY_EPMS,
    PTAD_KEY_NIBSS,
    PTAD_KEY_TAMS,
} PtadKey;

typedef enum {
    HANDSHAKE_MAPTID_FALSE,
    HANDSHAKE_MAPTID_TRUE,
} HandshakeMapTid;

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
    ERROR_CODE_HANDSHAKE_RUN_ERROR,
    ERROR_CODE_ERROR,
} ErrorCode;

typedef enum {
    SIM_TYPE_PUBLIC,
    SIM_TYPE_PRIVATE,
} SimType;

typedef enum {
    HANDSHAKE_OPERATIONS_MASTER_KEY = 1 << 0,
    HANDSHAKE_OPERATIONS_SESSION_KEY = 1 << 1,
    HANDSHAKE_OPERATIONS_PIN_KEY = 1 << 2,
    HANDSHAKE_OPERATIONS_PARAMETER = 1 << 3,
    HANDSHAKE_OPERATIONS_CALLHOME = 1 << 4,
    HANDSHAKE_OPERATIONS_ALL = 0xFF,
} HandshakeOperations;

typedef short (*GetNetworkManagementData)(void* handshake);
typedef int (*ComSendReceive)(unsigned char* response, const size_t rSize,
    const unsigned char* request, const size_t len, const char* ip,
    const int port, const HostRecvSentinel recevSentinel, const char* endTag);

struct appInfo {
    char name[32];
    char version[32];
};

struct deviceInfo {
    char posUid[32];
    char model[32];
};

struct simInfo {
    SimType simType;
    char imsi[32];
};

typedef struct Host {
    char hostUrl[65];
    int port;
    ConnectionType connectionType;
    unsigned int receiveTimeout;
} Host;

typedef struct Error {
    ErrorCode code;
    char message[0x200];
} Error;

typedef struct Server {
    char ip[65];
    int port;
} Server;

typedef struct PrivatePublicServer {
    Server privateServer;
    Server publicServer;
} PrivatePublicServer;

typedef struct MiddlewareServer {
    PrivatePublicServer ssl;
    PrivatePublicServer plain;
} MiddlewareServer;

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
        ConnectionType connectionType;

        MiddlewareServerType middlewareServerType;

        Server tams;
        Server callhome;
        Server callhomePosvas;

        int callhomeTime;

        PrivatePublicServer remoteUpgrade;

        MiddlewareServer epms;
        MiddlewareServer posvas;

        char vasUrl[64];
    } servers;
} TAMSResponse;

typedef struct Key {
    unsigned char key[33];
    unsigned char kcv[33];
} Key;

typedef struct Parameter {
    char callHomeTime[25];
    char cardAcceptorID[41];
    char countryCode[8];
    char currencyCode[8];
    char merchantCategoryCode[8];
    char merchantNameAndLocation[41];
    char serverDateAndTime[20];
    char timeout[34];
} Parameter;

typedef struct NetworkManagementResponse {
    char responseCode[3];
    Key master;
    Key session;
    Key pin;
    Parameter parameter;
} NetworkManagementResponse;

typedef struct handshake_InitData {
    char tid[9];

    struct appInfo appInfo;
    struct deviceInfo deviceInfo;
    struct simInfo simInfo;  

    PtadKey ptadKey;
    Platform platform;
    HandshakeMapTid mapTid;

    // host
    Host mapTidHost;
    Host handshakeHost;
    Host callHomeHost;

    // callback
    HostRecvSentinel hostSentinel;
    ComSendReceive comSendReceive;
} handshake_InitData;

typedef struct Handshake_t {
    char tid[9];

    struct appInfo appInfo;
    struct deviceInfo deviceInfo;
    struct simInfo simInfo;  

    PtadKey ptadKey;
    Platform platform;
    HandshakeMapTid mapTid;

    // hosts
    Host mapTidHost;
    Host callHomeHost;
    Host handshakeHost;

    // responses
    TAMSResponse tamsResponse;
    NetworkManagementResponse networkManagementResponse;

    // callback
    HostRecvSentinel hostSentinel;
    ComSendReceive comSendReceive;
    GetNetworkManagementData getMasterKey;
    GetNetworkManagementData getSessionKey;
    GetNetworkManagementData getPinKey;
    GetNetworkManagementData getParameter;

    Error error;
} Handshake_t;

void logTamsResponse(TAMSResponse* tamsResponse);
void logTerminals(TAMSResponse* tamsResponse);
void logServers(TAMSResponse* tamsResponse);
void logKey(Key* key, const char* title);
void logParameter(Parameter* parameter);
void logNetworkManagementResponse(NetworkManagementResponse* networkManagementResponse);

void Handshake(Handshake_t* handshake, handshake_InitData* initData,
    HandshakeOperations ops);

#ifdef __cplusplus
}
#endif

#endif
