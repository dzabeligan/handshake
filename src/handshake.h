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

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

#include "../EftDef.h"

/**
 * @brief Handshake operations
 *
 */
typedef enum {
  HANDSHAKE_OPERATIONS_NONE,
  HANDSHAKE_OPERATIONS_MASTER_KEY = 1 << 0,
  HANDSHAKE_OPERATIONS_SESSION_KEY = 1 << 1,
  HANDSHAKE_OPERATIONS_PIN_KEY = 1 << 2,
  HANDSHAKE_OPERATIONS_PARAMETER = 1 << 3,
  HANDSHAKE_OPERATIONS_CALLHOME = 1 << 4,
  HANDSHAKE_OPERATIONS_EFT_TOTAL = 1 << 5,
  HANDSHAKE_OPERATIONS_CAPK = 1 << 6,
  HANDSHAKE_OPERATIONS_ALL = 0xFF,
} HandshakeOperationBitmap;

/**
 * @brief PTAD Key type
 *
 */
typedef enum {
  PTAD_KEY_UNKNOWN,
  PTAD_KEY_POSVAS,
  PTAD_KEY_EPMS,
  PTAD_KEY_NIBSS,
  PTAD_KEY_TAMS,
} PtadKey;

/**
 * @brief Map Device bool
 *
 */
typedef enum {
  HANDSHAKE_MAP_DEVICE_FALSE,
  HANDSHAKE_MAP_DEVICE_TRUE,
} HandshakeMapDevice;

/**
 * @brief Middleware server type
 *
 */
typedef enum {
  MIDDLEWARE_SERVER_TYPE_UNKNOWN,
  MIDDLEWARE_SERVER_TYPE_POSVAS,
  MIDDLEWARE_SERVER_TYPE_EPMS,
} MiddlewareServerType;

/**
 * @brief Terminal application type
 *
 */
typedef enum {
  TERMINAL_APP_TYPE_UNKNOWN,
  TERMINAL_APP_TYPE_MERCHANT,
  TERMINAL_APP_TYPE_AGENT,
  TERMINAL_APP_TYPE_CONVERTED,
} TerminalAppType;

/**
 * @brief Sim type
 *
 */
typedef enum {
  SIM_TYPE_PUBLIC,
  SIM_TYPE_PRIVATE,
} SimType;

/**
 * @brief Function pointer to get call home data
 *
 */
typedef int (*GetCallHomeData)(char* data, const size_t len);

/**
 * @brief application information
 * @name: application name
 * @version: application version
 *
 */
struct appInfo {
  char name[32];
  char version[32];
};

/**
 * @brief device information
 * @posUid: device serial number
 * @model: device model
 *
 */
struct deviceInfo {
  char posUid[32];
  char model[32];
};

/**
 * @brief SIM information
 * @simType: Enum of sim type
 * @imsi: IMSI of SIM
 *
 */
struct simInfo {
  SimType simType;
  char imsi[32];
};

/**
 * @brief Server
 * @ip: server ip
 * @port: server port
 *
 */
typedef struct Server {
  char ip[65];
  int port;
} Server;

/**
 * @brief Private and public address of a server
 * @privateServer: private address
 * @publicServer: public address
 *
 */
typedef struct PrivatePublicServer {
  Server privateServer;
  Server publicServer;
} PrivatePublicServer;

/**
 * @brief Middleware server
 * @ssl: ssl server
 * @plain: plain server
 *
 */
typedef struct MiddlewareServer {
  PrivatePublicServer ssl;
  PrivatePublicServer plain;
} MiddlewareServer;

/**
 * @brief TAMS Response from Map TID
 * @accountToDebit: account to debit
 * @accountNumber: account number assigned to device
 * @accountSelectionType: Should allow account selection
 * @aggregatorName: aggregator name
 * @balance: balance
 * @commision: commision
 * @email: email
 * @merchantAddress: merchant address
 * @merchantName: merchant name
 * @notificationId: notification ID
 * @phone: phone number
 * @posSupport: POS support
 * @preConnect: pre connect
 * @rrn: RRN
 * @stampDuty: stamp duty
 * @stampDutyThreshold: stamp duty threshold
 * @stampLabel: stamp label
 * @terminalAppType: terminal app type
 * @userId: user ID
 * @terminals: struct terminals
 * @servers: Servers
 *
 */
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

  /**
   * @brief Terminals
   * @amp: amp
   * @moreFun: morefun
   * @newLand: newland
   * @newPos: newpos
   * @nexGo: nexgo
   * @pax: pax
   * @paySharp: paysharp
   * @verifone: verifone
   *
   */
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

  /**
   * @brief Servers
   * @connectionType: connection type
   * @middlewareServerType: middleware server type
   * @tams: TAMS
   * @callhome: Call Home EPMS
   * @callhomePosvas: Call Home POSVAS
   * @callhomeTime: receive timeout for call home
   * @remoteUpgrade: remote upgrade
   * @epms: EPMS
   * @posvas: POSVAS
   * @vasurl: vas url
   *
   */
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

/**
 * @brief Key
 * @key: key
 * @kcv: KCV
 *
 */
typedef struct Key {
  unsigned char key[33];
  unsigned char kcv[33];
} Key;

/**
 * @brief Parameters
 * @callHomeTime: call home time
 * @cardAcceptorID: card acceptor ID
 * @currencyCode: currency code
 * @countryCode: country code
 * @merchantCategoryCode: merchant category code
 * @merchantNameAndLocation: merchant name and location
 * @serverDateAndTime: server date and time
 * @timeout: timeout
 *
 */
typedef struct Parameters {
  int batchNumber;
  char callHomeTime[25];
  char cardAcceptorID[41];
  char countryCode[8];
  char currencyCode[8];
  char currencySymbol[8];
  long endOfDay;
  char footer[40];
  char header[40];
  char merchantCategoryCode[8];
  char merchantNameAndLocation[41];
  short resetPin;
  char serverDateAndTime[20];
  char timeout[34];
} Parameters;

/**
 * @brief Network management response
 * @responseCode: response code
 * @master: master key
 * @session: session key
 * @pin: pin key
 * @parameters: parameters
 *
 */
typedef struct NetworkManagementResponse {
  char responseCode[3];
  Key master;
  Key session;
  Key pin;
  Parameters parameters;
} NetworkManagementResponse;
/**
 * @brief Handshake
 * @tid: Terminal ID
 * @appInfo: Application information
 * @deviceInfo: Device information
 * @simInfo: SIM Information
 * @mapDevice: should map device
 * @operations: operations to perform
 * @platform: platform
 * @ptadKey: ptad key type
 * @callHomeHost: call home host
 * @handshakeHost: handshake host
 * @mapDeviceHost: map device host
 * @networkManagementResponse: network management response
 * @tamsResponse: TAMS response
 * @comSendReceive: send and receive function pointer
 * @getCallHomeData: get call home data function pointer
 * @comSentinel: com sentinel function pointer
 * @error: error
 *
 */
typedef struct Handshake_t {
  char tid[9];

  // info
  struct appInfo appInfo;
  struct deviceInfo deviceInfo;
  struct simInfo simInfo;

  // enums
  HandshakeMapDevice mapDevice;
  HandshakeOperationBitmap operations;
  Platform platform;
  PtadKey ptadKey;

  // hosts
  int callHomeTime;
  Host callHomeHost;
  Host handshakeHost;
  Host mapDeviceHost;

  // responses
  NetworkManagementResponse networkManagementResponse;
  TAMSResponse tamsResponse;

  // callback
  ComSendReceive comSendReceive;
  GetCallHomeData getCallHomeData;
  ComSentinel comSentinel;

  Error error;
} Handshake_t;

#define HANDSHAKE_INIT_DATA \
  { '\0' }

void logTamsResponse(TAMSResponse* tamsResponse);
void logTerminals(TAMSResponse* tamsResponse);
void logServers(TAMSResponse* tamsResponse);
void logKey(Key* key, const char* title);
void logParameter(Parameters* parameters);
void logNetworkManagementResponse(
    NetworkManagementResponse* networkManagementResponse);

void Handshake(Handshake_t* handshake);

#ifdef __cplusplus
}
#endif

#endif
