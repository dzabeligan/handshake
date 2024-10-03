/**
 * @file handshake.h
 * @author Elijah Balogun (elijah.balogun@cyberpay.net.ng)
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

#include "../def.h"

#ifndef FALSE   /* in case these macros already exist */
#define FALSE 0 /* values of boolean */
#endif
#ifndef TRUE
#define TRUE 1
#endif

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
  HANDSHAKE_OPERATIONS_CAPK = 1 << 5,
  HANDSHAKE_OPERATIONS_AID = 1 << 6,
  HANDSHAKE_OPERATIONS_ALL = 0xFF,
} HandshakeOperationBitmap;

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
  char brand[32];
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
 * @posSupportPhone: posSupportPhone number
 * @posSupportName: POS support
 * @preConnect: pre connect
 * @rrn: RRN
 * @stampDuty: stamp duty
 * @stampDutyThreshold: stamp duty threshold
 * @stampLabel: stamp label
 * @userId: user ID
 *
 */
typedef struct TMSResponse {
  char adminPin[8];
  char bankName[32];
  short changePin;
  char componentKey[33];
  char currencyCode[8];
  char currencySymbol[8];
  char customerCopyLabel[24];
  char email[64];
  char footer[40];
  char footnote[40];
  char logoPath[128];
  char merchantAddress[128];
  char merchantCopyLabel[24];
  char merchantName[128];
  char merchantPin[8];
  char posSupportName[64];
  char posSupportPhone[32];
  short shouldPrintLogo;
} TMSResponse;

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
  char callHomeTime[25];
  char cardAcceptorID[41];
  char countryCode[8];
  char currencyCode[8];
  char currencySymbol[8];
  char merchantCategoryCode[8];
  char merchantNameAndLocation[41];
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
 * @shouldGetDeviceConfig: should map device
 * @operations: operations to perform
 * @platform: platform
 * @callHomeHost: call home host
 * @handshakeHost: handshake host
 * @deviceConfigHost: map device host
 * @networkManagementResponse: network management response
 * @tmsResponse: TAMS response
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
  short shouldGetDeviceConfig;
  HandshakeOperationBitmap operations;
  Platform platform;

  // hosts
  int callHomeTime;
  Host callHomeHost;
  Host handshakeHost;
  Host deviceConfigHost;

  // responses
  NetworkManagementResponse networkManagementResponse;
  TMSResponse tmsResponse;

  // callback
  ComSendReceive comSendReceive;
  GetCallHomeData getCallHomeData;
  ComSentinel comSentinel;

  Error error;
} Handshake_t;

#define HANDSHAKE_INIT_DATA {'\0'}

void logTMSResponse(const TMSResponse* tmsResponse);
void logKey(const Key* key, const char* title);
void logParameter(Parameters* parameters);
void logNetworkManagementResponse(
    NetworkManagementResponse* networkManagementResponse);

void Handshake(Handshake_t* handshake);

#ifdef __cplusplus
}
#endif

#endif
