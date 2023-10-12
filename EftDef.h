/**
 * File: EftDef.h
 * --------------
 * Defines new types for eft.h
 * @author Opeyemi Adeyemi Sunday, Itex Interated Services.
 */

#ifndef __EFT_DEF_INCLUDED__
#define __EFT_DEF_INCLUDED__

#include <stdarg.h>
#include <stdlib.h>

#include "platform/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

#define UI_STR_EFT_NOT_READY "NOT READY, PRESS HANDSHAKE"
#define UI_STR_EFT_HANDSHAKE "HANDSHAKE"

#define APP_NAME "Tamslite"
#define APP_VERSION "1.0.0"

#define LOG_STREAM stderr

// #define HOSTS_FILE "tests/hosts.json"
#define MERCHANT_PATH "flash"

// Note that the following will be updated if tid mapping is done since they are
// comming from Tams.
#define UPGRADE_SERVER "Upgrade"
#define MIDDLEWARE_SERVER "Middleware"
#define MIDDLEWARE_DESTINATION_SERVER "NibssDirect"
#define TAMS_SERVER "Tams"
#define TAMS_BASE_SERVER "BaseTams"
#define TAMS_UBA_DEVELOPMENT "UbaTestTams"
#define TAMS_FBN_DEVELOPMENT "FbnTestTams"
#define TAMS_FBN_PRODUCTION "FbnProductionTams"
#define TAMS_UBA_PRODUCTION "UbaTamsProduction"
#define TAMS_TEST_SERVER "TestTams"
#define VAS_SERVER "Vas"
#define MERCHANT_PAYVICE_SERVER "merchant_payvice"

// For direct connection to Nibss production enviroment, currently using
// middleware
#define CONFIG_HOST_PUBLIC_LIVE_POSVAS_PLAIN "PublicLiveDirectPosVasPlain"
#define CONFIG_HOST_PUBLIC_LIVE_POSVAS_SSL "PublicLiveDirectPosVasSsl"
#define CONFIG_HOST_PUBLIC_LIVE_EPMS_PLAIN "PublicLiveDirectEpmsPlain"
#define CONFIG_HOST_PUBLIC_LIVE_EPMS_SSL "PublicLiveDirectEpmsSsl"

#define CONFIG_HOST_PRIVATE_LIVE_POSVAS_PLAIN "PrivateLiveDirectPosVasPlain"
#define CONFIG_HOST_PRIVATE_LIVE_POSVAS_SSL "PrivateLiveDirectPosVasSsl"
#define CONFIG_HOST_PRIVATE_LIVE_EPMS_PLAIN "PrivateLiveDirectEpmsPlain"
#define CONFIG_HOST_PRIVATE_LIVE_EPMS_SSL "PrivateLiveDirectEpmsSsl"

// For direct connection to Nibss development environment on Public sim, who
// cares of private sim on test.
#define CONFIG_HOST_TEST_POSVAS_PLAIN "TestDirectPosVasPlain"
#define CONFIG_HOST_TEST_POSVAS_SSL "TestDirectPosVasSsl"
#define CONFIG_HOST_TEST_EPMS_PLAIN "TestDirectEpmsPlain"
#define CONFIG_HOST_TEST_EPMS_SSL "TestDirectEpmsSsl"

#define MAX_ADDITIONAL_AMOUNT 6

#define MANUAL_REVERSAL 0
#define AUTO_REVERSAL 1

typedef short (*PrintSummaryRowCB)(const char* rowData, const int font);
typedef short (*PrintSummaryTitleCB)(const char* title);

#define MINISTATEMENT_DATA_MAX 10

typedef struct MiniStatementData {
  char date[16];
  char narration[64];
  short transType;
  char tranAmount[32];
} MiniStatementData;

typedef struct {
  char startDate[21];
  char stopDate[21];
  unsigned char filter;
  /*
  PrintSummaryRowCB printSummaryRow;
  PrintSummaryTitleCB printSummaryTitle;
  const int maxPrintBufSize;
  const int fontSize;
  */
} EftFilter;

typedef enum {
  ICC_TAG_MANDATORY,
  ICC_TAG_CONDITIONAL,
  ICC_TAG_OPTIONAL,
  ICC_TAG_DISABLE,
} IccTagOption;

typedef struct {
  unsigned char* tag;
  IccTagOption iccTagOption;
} IccTag;

typedef struct {
  unsigned char rid[5];              //{0xA0, 0x00, 0x00, 0x00, 0x03},    RID
  unsigned char ridIndex;            // 0x01,       CAPK index
  unsigned char hashAlgorithmIndex;  // 0x01,       hash algorithm id
  unsigned char rsaAlgorithmId;      // 0x01,       //RSA algorithm id, same as
                                     // hash algorithm id
  unsigned char modulusLen;          // 128,        //CAPK module length
  unsigned char modulus
      [248];  //{0xC6, 0x96, 0x03, 0x42, 0x13, 0xD7, 0xD8, 0x54, 0x69, 0x84,
              // 0x57, 0x9D, 0x1D, 0x0F, 0x0E, 0xA5, 0x19, 0xCF, 0xF8, 0xDE,
              // 0xFF, 0xC4, 0x29, 0x35, 0x4C, 0xF3, 0xA8, 0x71, 0xA6, 0xF7,
              // 0x18, 0x3F, 0x12, 0x28, 0xDA, 0x5C, 0x74, 0x70, 0xC0, 0x55,
              // 0x38, 0x71, 0x00, 0xCB, 0x93, 0x5A, 0x71, 0x2C, 0x4E, 0x28,
              // 0x64, 0xDF, 0x5D, 0x64, 0xBA, 0x93, 0xFE, 0x7E, 0x63, 0xE7,
              // 0x1F, 0x25, 0xB1, 0xE5, 0xF5, 0x29, 0x85, 0x75, 0xEB, 0xE1,
              // 0xC6, 0x3A, 0xA6, 0x17, 0x70, 0x69, 0x17, 0x91, 0x1D, 0xC2,
              // 0xA7, 0x5A, 0xC2, 0x8B, 0x25, 0x1C, 0x7E, 0xF4, 0x0F, 0x23,
              // 0x65, 0x91, 0x24, 0x90, 0xB9, 0x39, 0xBC, 0xA2, 0x12, 0x4A,
              // 0x30, 0xA2, 0x8F, 0x54, 0x40, 0x2C, 0x34, 0xAE, 0xCA, 0x33,
              // 0x1A, 0xB6, 0x7E, 0x1E, 0x79, 0xB2, 0x85, 0xDD, 0x57, 0x71,
              // 0xB5, 0xD9, 0xFF, 0x79, 0xEA, 0x63, 0x0B, 0x75} // module
  unsigned char exponentLen;  // 1,      //exponent length
  unsigned char exponent[3];  //{0x03},     //exponent
  unsigned char checkSumLen;  // 0x14,       //hash result length
  unsigned char
      checkSum[20];  //{0xD3, 0x4A, 0x6A, 0x77, 0x60, 0x11, 0xC7, 0xE7,0xCE,
                     // 0x3A, 0xEC, 0x5F, 0x03, 0xAD, 0x2F, 0x8C,0xFC, 0x55,
                     // 0x03, 0xCC}// hash result (SHA-1)
  unsigned char expiryDate[4];  //{0x20, 0x20, 0x12, 0x31}// expire date
} Capk;

typedef struct {
  const char* filename;
} CapkFileName;

typedef struct {
  const char* filename;
} EftAidFileName;

/* AID parameters */
typedef struct {
  unsigned char AidLen;   // AID length(5-16 bytes)
  unsigned char Aid[16];  // AID
  unsigned char
      Asi;  // Application Selection Indicator: 0- match partially(up to the
            // AID length preload in the terminal), 1-match exactly
  unsigned char AppVerNum[2];      // Application Version Number
  unsigned char TacDefault[5];     // TAC-default
  unsigned char TacOnline[5];      // TAC-online
  unsigned char TacDecline[5];     // TAC-decline
  unsigned char FloorLimit[4];     // terminal floor limit
  unsigned char Threshold[4];      // threshold
  unsigned char MaxTargetPercent;  // maximum target percent
  unsigned char TargetPercent;     // target percent
  unsigned char TermDDOLLen;       // DDOL length
  unsigned char TermDDOL[128];     // DDOL
  unsigned char TermPinCap;        // whether to support online PIN, 1-yes, 0-no
  unsigned char vlptranslimit[6];  // Visa Low-value Payment
  unsigned char termcvm_limit[6];  // Reader CVM Required Limit
  unsigned char
      clessofflineamt[6];  // Reader Contactless Transaction Limit (RCTL)
  unsigned char clessofflinelimitamt[6];  // Reader Contactless Floor Limit
  unsigned char bShowRandNum;  // whether to show random number, 1-yes, 0-no
  unsigned char bLocalName;    // mode for displaying candidate list:  0 - use
                               // card info, 1 - use local language
  unsigned char AppLocalNameLen;   // application name length
  unsigned char AppLocalName[16];  // application name
  unsigned char bForceOnline;      // whether to force the transaction to go
                                   // online, 1-yes, 0-no
} EftAid;

enum CommsStatus {
  SEND_RECEIVE_SUCCESSFUL,
  CONNECTION_FAILED,
  SENDING_FAILED,
  RECEIVING_FAILED,

  // ex for screen display
  HOST_RECEIVING,
  HOST_SENDING,
  HOST_RECONNECTING,
  HOST_CONNECTING

};

enum HostDecision {
  HOST_DEFAULT,
  HOST_APPROVED,
  HOST_REVERSED,
  HOST_REVERSAL_FAILED,  // Auto reversal attempt failed
  HOST_DECLINED,
  HOST_ABORTED,
};

typedef enum AccountType {
  DEFAULT_ACCOUNT = 0,
  SAVINGS_ACCOUNT = 1,
  CURRENT_ACCOUNT = 2,
  CREDIT_ACCOUNT = 3,
  UNIVERSAL_ACCOUNT = 4,
  INVESTMENT_ACCOUNT = 5,
} AccountType;

enum TechMode {
  CONTACTLESS_MODE,
  CONTACTLESS_MAGSTRIPE_MODE,
  CHIP_MODE,
  MAGSTRIPE_MODE,
  MANUAL_MODE,
  FALLBACK_MODE,
  UNKNOWN_MODE,
};

typedef enum CommMode {
  COMM_NONE,
  COMM_GPRS,
  COMM_ETHERNET_STATIC,
  COMM_ETHERNET_DYNAMIC,
  COMM_WIFI,
  COMM_MODEM,
  COMM_MODEMPPP,
  COMM_BLUETOOTH,
  COMM_SERIAL,
} CommMode;

enum ReversalReason {
  TIMEOUT_WAITING_FOR_RESPONSE,
  CUSTOMER_CANCELLATION,
  CHANGE_DISPENSED,
  CARD_ISSUER_UNAVAILABLE,
  UNDER_FLOOR_LIMIT,
  PIN_VERIFICATION_FAILURE,
  IOU_RECEIPT_PRINTED,
  OVER_FLOOR_LIMIT,
  NEGATIVE_CARD,
  UNSPECIFIED_NO_ACTION_TAKEN,
  COMPLETED_PARTIALLY,
};

typedef enum TransType {
  EFT_NONE = 0,
  EFT_PURCHASE = 1,
  EFT_CASHBACK = 2,
  EFT_REVERSAL = 4,
  EFT_REFUND = 5,
  EFT_BALANCE = 7,
  EFT_CHANGEPIN = 8,
  EFT_MINISTAT = 9,
  EFT_TRANSFER = 10,
  EFT_DEPOSIT = 11,
  EFT_ROLLBACK = 12,
  EFT_PREAUTH = 33,
  EFT_COMPLETION = 34,
  EFT_CASHADVANCE = 45,
  EFT_WITHDRAWAL = 46,
  EFT_PIN_SELECTION = 47,
  EFT_AUTHONLY,
  EFT_PURCHASE_CASH,
  EFT_ALL = 0xFF
} TransType;

enum AmountType {
  AMOUNT_TYPE_UNKNOWN,
  AMOUNT_LEDGER_BALANCE,
  AMOUNT_AVAILABLE_BALANCE,
  AMOUNT_CASHBACK,
  AMOUNT_AVAILABLE_CREDIT,
  CREDIT_LIMIT,
};

typedef struct AdditionalAmount {
  enum AccountType accountType;  // Position 1-2
  enum AmountType amountType;    // Position 3-4
  char currencyCode[4];          // Position 5-7
  char debitOrCredit;            // C or D //8
  unsigned char amount[13];      // 9-20
} AdditionalAmount;

/**
 * @brief Error Code
 *
 */
typedef enum {
  ERROR_CODE_NO_ERROR,
  ERROR_CODE_HANDSHAKE_INIT_ERROR,
  ERROR_CODE_HANDSHAKE_MAPTID_ERROR,
  ERROR_CODE_HANDSHAKE_RUN_ERROR,
  ERROR_CODE_HOST_DECISION_ERROR,
  ERROR_CODE_ERROR,
} ErrorCode;

/**
 * @brief error
 * @code: error code
 * @message: error message
 *
 */
typedef struct Error {
  ErrorCode code;
  char message[0x200];
} Error;

typedef struct KeyT {
  char key[33];
  char eKey[33];
  unsigned char bcKey[16];
  unsigned char bcEkey[16];
  short bcKeySize;
  char kcv[33];
  unsigned char bcKcv[16];
  short bcKcvSize;
} KeyT;

typedef struct HostKey {
  char keyType[35];
  KeyT tmk;
  KeyT tsk;
  KeyT tpk;
} HostKey;

typedef int (*HostRecvSentinel)(unsigned char* packet, const int bytesRead,
                                const char* endTag);

/**
 * @brief Host struct
 * @hostUrl: URL of host
 * @port: PORT
 * @connectionType: connection type enum
 * @receiveTimeout: connection timeout
 *
 */
typedef struct Host {
  char hostUrl[65];
  int port;
  ConnectionType connectionType;
  unsigned int receiveTimeout;
} Host;

// typedef struct Host {
//   char name[35];
//   char host[65];
//   char port[7];
//   short isSsl;
//   unsigned int receiveTimeout;
//   char keyType[45];
//   char serverCertPath[64];
//   char clientCertPath[64];
//   char clientKeyPath[64];
//   char sslPolicy[65];
//   char sslProtVersion[35];
//   char minSslProtVerion[35];
//   char description[256];
//   short async;
//   HostRecvSentinel recevSentinel;
//   char endTag[35];
//   char requestTitle[45];
// } Host;

typedef struct DualHost {
  Host main;
  Host failover;
  short isIso8583;
  void* commHandle;
  short shouldConnectAsync;
  short shouldDetach;
} DualHost;

typedef struct Packet {
  unsigned char data[0x1000];
  int dataLen;
} Packet;

typedef struct {
  char apn[45];
  char username[45];
  char password[45];
} Apn;

typedef enum Platform {
  PLATFORM_NIBSS,
  PLATFORM_TAMS,
} Platform;

typedef enum EncryptionType {
  ENCRYPTION_TYPE_DUKPT,
  ENCRYPTION_TYPE_MSK,
} EncryptionType;

typedef struct DukptT {
  unsigned char bcKlk[16];
  char bdk[33];
  unsigned char bcBdk[16];

  char bdkKsn[21];
  unsigned char bcBdkKsn[10];

  char ipek[33];
  unsigned char bcIpek[16];
} DukptT;

typedef short (*InjectHostKeysCB)(const HostKey* hostKey, const void* device,
                                  Error* error);
typedef short (*DukptInitCB)(const DukptT* dukpt, const void* device,
                             Error* error);

typedef short (*GetUnixTimestamp)(char* unixTimestamp, const int size);

typedef short (*GetModelCB)(char* model, const int size);
typedef short (*GetPosSnCB)(char* serialNumber, const int size);
typedef short (*GetCallhomeDataCB)(char* callhomData, Error* error,
                                   const void* device);

typedef short (*SetSupervisorPinCB)(char* pinBuf, const int size,
                                    const int pinLen, char* dateBuf,
                                    int dateBufLen, char* title);

typedef short (*InitCommsCB)(Error* error, void* device, Apn* prevApn);

typedef short (*DnsResolveHostCB)(char ip[16], Error* error, const Host* host,
                                  const Host* failoverHost);
typedef short (*GetApnCB)(Apn* apn);
typedef short (*SelectApnCB)(const Apn* apnList, const short apnListSize);
typedef void (*DisplayApnCB)(const Apn* apn, const char* simOperation);
typedef short (*InitSimCB)(const Host* host, const Apn* prevApn);
typedef short (*GetImsiAndSimIdCB)(char* imsi, char* simId, Error* error);
typedef void* (*AttachToHost)(void* device, const short isAsync);
typedef void (*DetachFromHost)(void* device);
typedef short (*CanPreDial)(const void* device);

typedef short (*GetBatteryLevel)(int* batteryLevel, Error* errMsg);
typedef short (*GetBatteryTemperature)(int* batteryTemperature, Error* errMsg);
typedef short (*GetChargingState)(char* chargingState, const int size,
                                  Error* errMsg);
typedef short (*GetPrinterState)(char* printerState, const int size,
                                 Error* errMsg);
typedef short (*GetGprsState)(char* gprsState, const int size, Error* errMsg);
typedef short (*GetSsid)(char* ssid, const int size, Error* errMsg);
typedef short (*HasBattery)(char* isBatteryPressent, const int size,
                            Error* errMsg);
typedef short (*GetGsmSignal)(int* signal, Error* errMsg);
typedef short (*GetWlanSignal)(int* percent, Error* errMsg);
typedef short (*GetState)(char* state, const int size, Error* errMsg,
                          const void* device);

typedef struct {
  char name[128];
  char table[35];
  char version[21];
  int rowLimit;
  int preAuthLifetime;
} EftDB;

typedef enum CommsStatus (*TcpCommsCB)(Packet* responsePacket,
                                       const Packet* requestPacket,
                                       const void* device);
typedef void (*ScreenDisplayCB)(const enum CommsStatus commStatus,
                                const char* message);

typedef struct Vas {
  int (*genAuxPayload)(char auxPayload[], const size_t auxPayloadSize,
                       const void* eftStruct);
  void* callbackdata;
  char auxResponse[4096];
  char customRefCode[1024];
  int switchMerchant;
} Vas;

typedef int (*IccReadTlvCB)(const unsigned char* pheTag,
                            unsigned char* pheOutData, int* len);

enum SdkIccReturnType {
  ICC_NONE,
  ICC_VALUE_ONLY,
  ICC_LENGHT_VALUE,
  ICC_TLV,
};

typedef enum EftPinblockType {
  EFT_PINBLOCK_NONE,
  EFT_PINBLOCK_CURRENT,
  EFT_PINBLOCK_NEW,
  EFT_PINBLOCK_CONFIRM,

} EftPinblockType;

typedef struct IccData {
  char iccData[1000];
  unsigned char iccDataBcd[500];
  unsigned int iccDataBcdLen;
  IccReadTlvCB iccReadTlvCB;
  enum SdkIccReturnType sdkIccReturnType;
  IccTag* iccTags;
} IccData;

typedef struct Pinblock {
  char pinblock[17];
  char ksn[21];
} Pinblock;

// struct Pinblock {
//   unsigned char pinblock[8];
//   int pinblockSize;
//   char pinblockAsc[17];

//   unsigned char ksn[10];
//   int ksnSize;
//   char ksnAsc[21];
// };

struct EftPinblock {
  struct Pinblock currentPinblock;
  struct Pinblock newPinblock;
  struct Pinblock confirmPinblock;
};

typedef struct EftType {
  char title[35];
  unsigned int code;
  char category[35];
  unsigned short status;  // true or false (1 or 0)
} EftType;

typedef struct Eft {
  EftType eftTranType;
  AdditionalAmount additionalAmountList[MAX_ADDITIONAL_AMOUNT];
  short additionalAmountCount;
  char additionalAmount[13];
  char formatedAdditionalAmount[43];
  unsigned char bcdAdditionalAmount[6];
  unsigned char additionalAmountLen;
  unsigned char aidBcd[16];
  short aidLen;
  char aid[32];

  short cryptogramLen;
  char cryptogram[17];
  unsigned char cryptogramBcd[8];

  short cidLen;
  char cid[3];
  unsigned char cidBcd;

  short cvmrLen;
  unsigned char cvmrBcd[3];
  char cvmr[7];

  char amount[13];
  char formatedAmount[43];
  unsigned char amountLen;
  unsigned char bcdAmount[6];
  char authorizationCode[7];
  char balance[256];
  char cardHolderName[35];
  char cardLabel[35];
  char cardSequenceNumber[4];
  char currencyCode[5];
  char cvv[4];
  char echoData[256];
  char entryMode[5];
  char expiryDate[7];
  char forwardingInstitutionIdCode[12];
  char freeBuffer1[256];
  char freeBuffer2[256];
  char freeBuffer3[512];
  char freeBuffer4[512];
  char freeBuffer5[1024];
  char freeBuffer6[2048];
  char freeBuffer7[2048];
  char isOfflineTrans;
  char manualFlag;
  char merchantId[16];
  char merchantName[41];
  char merchantType[5];
  char message[256];

  char originalAmount[13];
  unsigned char track2len;
  unsigned char track2BcdData[19];
  unsigned char expiryDateBcd[3];
  unsigned char expiryDateLen;
  unsigned char panBcd[10];
  unsigned char panLen;
  char originalMti[5];
  char originalRrn[13];
  char originalStan[7];
  char originalYyyymmddhhmmss[15];
  char orignalUnixTimestamp[22];  // for reversal
  char otherData[256];
  char pan[20];
  char maskedPan[20];
  char posConditionCode[3];
  char posDataCode[16];
  char posPinCaptureCode[3];
  char reserved20[256];
  char reserved27[256];
  char reserved28[256];
  char reserved29[256];
  char reserved30[512];
  char reserved31[512];
  char reserved32[1024];
  char reserved33[2048];
  char responseCode[3];
  char responseDesc[256];
  char rrn[13];
  char secondaryMessageHashValue[64];
  char serviceRestrictionCode[4];
  char sessionKey[33];
  char stan[7];
  char supervisorFlag;
  char tableName[30];
  char terminalId[9];
  char track1Data[42];
  char track2Data[39];
  char transCategory[32];
  char tsi[5];
  unsigned char tsiBcd[2];
  unsigned char tsiLen;

  char tvr[11];
  unsigned char tvrBcd[5];
  unsigned char tvrLen;

  char unixTimestamp[22];  // New
  char yyyymmddhhmmss[15];
  enum AccountType fromAccount;
  enum AccountType toAccount;
  enum HostDecision hostDecision;
  enum ReversalReason reversalReason;
  enum TechMode techMode;
  enum TransType originalTransType;
  enum TransType transType;
  int budgetPeriod;
  int iOperator;
  int otherTrans;
  int tipAmount;
  long atPrimaryIndex;
  int freeInt1;
  int freeInt2;
  unsigned int freeInt3;
  unsigned int freeInt4;
  long freeInt5;
  unsigned long freeInt6;
  int freeInt7;
  int batchNumber;
  int originalBatchNumber;
  short isFallback;
  int sequenceNumber;
  int originalSequenceNumber;
  char toAccountNumber[21];
  short isVasTrans;
  struct EftPinblock eftPinblock;
  IccData iccData;
  Vas vas;
  char mti[5];
  char processingCode[7];
  int requestType;
  MiniStatementData miniStatementData[MINISTATEMENT_DATA_MAX];
  short dataLen;
} Eft;

typedef struct HostType {
  short onlineResult;

  char authCodeStr[7];
  unsigned char authCodeBcd[3];
  unsigned short authCodeBcdLen;

  char authDataStr[512];  // tag 91
  unsigned char authDataBcd[256];
  unsigned short authDataBcdLen;

  char authResponseStr[3];  // de39
  unsigned char authResponseBcd[1];
  unsigned short authResponseBcdLen;

  char scriptCritStr[512];  // tag 71
  unsigned char scriptCritBcd[256];
  unsigned short scriptCritBcdLen;

  char scriptUnCritStr[512];  // tag 72
  unsigned char scriptUnCritBcd[256];
  unsigned short scriptUnCritBcdLen;

  char iccData[1000];
  unsigned char iccDataBcd[500];
  unsigned short iccDataBcdLen;

  unsigned char unKnownData[1024];
  unsigned short unKnownDataLen;
} HostType;

typedef struct MerchantParameters {
  char cardAcceptorID[41];
  char currencyCode[5];
  char countryCode[5];
  char currencySymbol[5];
  unsigned char currencyCodeBcd[2];
  unsigned char countryCodeBcd[2];
  char header[40];
  char footer[40];
  unsigned int endOfDay;
  short resetPin;
  char serverDateAndTime[20];
  char timeout[34];
  char callHomeTime[25];
  char merchantCategoryCode[5];
  char merchantNameAndLocation[41];
  char message[256];
} MerchantParameters;

typedef struct EftTotal {
  short allTransCount;               // T
  unsigned long allTransTotalValue;  // A

  short purchaseTransCount;               // PC
  unsigned long purchaseTransTotalValue;  // PV

  short purchaseReversalTransCount;               // PRC;
  unsigned long purchaseReversalTransTotalValue;  // PRV;

  short refundTransactionCount;         // RC
  unsigned long refundTransTotalValue;  // RV

  short refundReversalTransCount;               // RRC;
  unsigned long refundReversalTransTotalValue;  // RRV;
} EftTotal;

typedef struct TransTypeStat {
  unsigned long totalApproved;
  unsigned int approvedCount;
  unsigned long totalDeclined;
  unsigned int declinedCount;
  TransType transType;
} TransTypeStat;

typedef struct {
  int debitOperationCount;             // Number of debit operations,
  unsigned long debitOperationAmount;  // Amount of debit operations
  char fmtDebitAmt[45];

  int creditOperationCount;             // Number of credit operations
  unsigned long creditOperationAmount;  // Amount of credit operations
  char fmtCreditAmt[45];

  int cancelOperationCount;             // Number of cancel operations
  unsigned long cancelOperationAmount;  // Amount of cancel operations
  char fmtCancelAmt[45];

  TransTypeStat transTypeStatList[12];
  unsigned short statCount;

} EftStat;

typedef struct EftRecord {
  char transType[35];
  char transCategory[32];  // This shouldn't show.
  char rrn[13];
  enum HostDecision hostDecision;
  char hostDecisionStatus;
  char stan[7];
  char pan[20];
  char amount[13];
  char responseCode[3];
  char dateTime[35];
} EftRecord;

typedef struct EftReport {
  char weekDayLabel[35];  // Currently not used for single file DB.
  EftStat eftStat;
  EftRecord* records;
  unsigned int recordSize;
  unsigned int capacity;
} EftReport;

typedef struct EftWeekDay {
  char weekdayLabel[35];
  char eftDbPathname[45];
} EftWeekDay;

typedef short (*AddAnyCapkListCB)(Error* error, const Capk* capkList,
                                  const int numberOfCapk);
typedef short (*AddAnyAidListCB)(Error* error, const EftAid* aidList,
                                 const int numberOfAid);

#ifdef __cplusplus
}
#endif

#endif
