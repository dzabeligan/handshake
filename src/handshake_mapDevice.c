/**
 * @file handshake_maptid.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implements Handshake Map Terminal ID
 * @version 0.1
 * @date 2023-02-07
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <ctype.h>
#include <stdio.h>

#include "handshake_internals.h"

typedef enum { STATUS_READY, STATUS_NOT_READY } pos_status;

/**
 * @brief Build TAMS Request
 *
 * @param requestBuf request buffer
 * @param bufLen buffer length
 * @param handshake handshake object
 * @return ssize_t - length of request
 */
static ssize_t buildTamsHomeRequest(char* requestBuf, size_t bufLen,
                                    Handshake_t* handshake) {
  const char* TRANS_ADVICE_PATH =
      "tams/eftpos/devinterface/transactionadvice.php";
  const char* DEFAULT_TID = "2070AS89";
  ssize_t pos = 0;

  pos += snprintf(
      requestBuf, bufLen,
      "GET "
      "/%s?action=TAMS_WEBAPI&termID=%s&posUID=%s&ver=%s%s&model=%s&control="
      "TamsSecurity\r\n",
      TRANS_ADVICE_PATH, DEFAULT_TID, handshake->deviceInfo.posUid,
      handshake->appInfo.name, handshake->appInfo.version,
      handshake->deviceInfo.model);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "Host: %s:%d",
                  handshake->mapDeviceHost.url, handshake->mapDeviceHost.port);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "%s", "\r\n\r\n");

  return pos;
}

/**
 * @brief Get the Pos Status object
 *
 * @param handshake handshake object
 * @param tranTag ezxml object
 * @return pos_status
 */
static pos_status getPosStatus(Handshake_t* handshake, ezxml_t tranTag) {
  ezxml_t item = NULL;
  pos_status ret = STATUS_NOT_READY;

  check((item = ezxml_child(tranTag, "result")), "Unable to get result tag");
  check(strncmp(item->txt, "0", 1) == 0, "(Result) %s Not Mapped",
        handshake->deviceInfo.posUid);
  check((item = ezxml_child(tranTag, "status")), "Unable to get status tag");
  check(strncmp(item->txt, "1", 1) == 0, "(Status) %s Not Mapped",
        handshake->deviceInfo.posUid);

  ret = STATUS_READY;
error:
  if (ret != STATUS_READY) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "'%s' Not Mapped", handshake->deviceInfo.posUid);
  }
  return ret;
}

/**
 * @brief Get the Terminal From Tams Response object
 *
 * @param tamsResponse tamsResponse object
 * @param tranTag ezxml object
 * @return short
 */
static short getTerminalFromTamsResponse(TAMSResponse* tamsResponse,
                                         ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_AMP_TAG = "Amp";
  const char* TAMS_MOREFUN_TAG = "MoreFun";
  const char* TAMS_NEWLAND_TAG = "NewLand";
  const char* TAMS_NEWPOS_TAG = "newpos";
  const char* TAMS_NEXGO_TAG = "NexGo";
  const char* TAMS_PAX_TAG = "PAX";
  const char* TAMS_PAYSHARP_TAG = "PAYSHARP";
  const char* TAMS_VERIFONE_TAG = "verifones";

  check((item = ezxml_child(tranTag, TAMS_AMP_TAG)), "Error Getting '%s'",
        TAMS_AMP_TAG);
  strncpy(tamsResponse->terminals.amp, item->txt,
          sizeof(tamsResponse->terminals.amp));

  check((item = ezxml_child(tranTag, TAMS_MOREFUN_TAG)), "Error Getting '%s'",
        TAMS_MOREFUN_TAG);
  strncpy(tamsResponse->terminals.moreFun, item->txt,
          sizeof(tamsResponse->terminals.moreFun));

  check((item = ezxml_child(tranTag, TAMS_NEWLAND_TAG)), "Error Getting '%s'",
        TAMS_NEWLAND_TAG);
  strncpy(tamsResponse->terminals.newLand, item->txt,
          sizeof(tamsResponse->terminals.newLand));

  check((item = ezxml_child(tranTag, TAMS_NEWPOS_TAG)), "Error Getting '%s'",
        TAMS_NEWPOS_TAG);
  strncpy(tamsResponse->terminals.newPos, item->txt,
          sizeof(tamsResponse->terminals.newPos));

  check((item = ezxml_child(tranTag, TAMS_NEXGO_TAG)), "Error Getting '%s'",
        TAMS_NEXGO_TAG);
  strncpy(tamsResponse->terminals.nexGo, item->txt,
          sizeof(tamsResponse->terminals.nexGo));

  check((item = ezxml_child(tranTag, TAMS_PAX_TAG)), "Error Getting '%s'",
        TAMS_PAX_TAG);
  strncpy(tamsResponse->terminals.pax, item->txt,
          sizeof(tamsResponse->terminals.pax));

  check((item = ezxml_child(tranTag, TAMS_PAYSHARP_TAG)), "Error Getting '%s'",
        TAMS_PAYSHARP_TAG);
  strncpy(tamsResponse->terminals.paySharp, item->txt,
          sizeof(tamsResponse->terminals.paySharp));

  check((item = ezxml_child(tranTag, TAMS_VERIFONE_TAG)), "Error Getting '%s'",
        TAMS_VERIFONE_TAG);
  strncpy(tamsResponse->terminals.verifone, item->txt,
          sizeof(tamsResponse->terminals.verifone));

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Servers From Tams Response object Helper
 *
 * @param server MiddlewareServer
 * @param tranTag ezxml_t
 * @param privateTag private tag
 * @param publicTag public tag
 * @return short
 */
static short getServersFromTamsResponseHelper(MiddlewareServer* server,
                                              ezxml_t tranTag,
                                              const char* privateTag,
                                              const char* publicTag,
                                              const char* privateSslTag,
                                              const char* publicSslTag) {
  ezxml_t item = NULL;
  char portBuf[16] = {'\0'};
  short ret = EXIT_FAILURE;

  check((item = ezxml_child(tranTag, privateTag)), "Error Getting '%s'",
        privateTag);
  memset(portBuf, '\0', sizeof(portBuf));
  splitStr(server->plain.privateServer.ip,
           sizeof(server->plain.privateServer.ip), portBuf, sizeof(portBuf),
           item->txt, ';');
  server->plain.privateServer.port = atoi(portBuf);

  check((item = ezxml_child(tranTag, publicTag)), "Error Getting '%s'",
        publicTag);
  memset(portBuf, '\0', sizeof(portBuf));
  splitStr(server->plain.publicServer.ip, sizeof(server->plain.publicServer.ip),
           portBuf, sizeof(portBuf), item->txt, ';');
  server->plain.publicServer.port = atoi(portBuf);

  check((item = ezxml_child(tranTag, privateSslTag)), "Error Getting '%s'",
        privateSslTag);
  memset(portBuf, '\0', sizeof(portBuf));
  splitStr(server->ssl.privateServer.ip, sizeof(server->ssl.privateServer.ip),
           portBuf, sizeof(portBuf), item->txt, ';');
  server->ssl.privateServer.port = atoi(portBuf);

  check((item = ezxml_child(tranTag, publicSslTag)), "Error Getting '%s'",
        publicSslTag);
  memset(portBuf, '\0', sizeof(portBuf));
  splitStr(server->ssl.publicServer.ip, sizeof(server->ssl.publicServer.ip),
           portBuf, sizeof(portBuf), item->txt, ';');
  server->ssl.publicServer.port = atoi(portBuf);

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Middleware Servers object
 *
 * @param tamsResponse
 * @param tranTag
 * @return short
 */
static short getMiddlewareServers(TAMSResponse* tamsResponse, ezxml_t tranTag) {
  short ret = EXIT_FAILURE;
  const char* TAMS_EPMSPUBLIC_TAG = "EPMSPUBLIC";
  const char* TAMS_EPMSPRIVATE_TAG = "EPMSPRIVATE";
  const char* TAMS_EPMSPUBLIC_SSL_TAG = "EPMSPUBLIC_SSL";
  const char* TAMS_EPMSPRIVATE_SSL_TAG = "EPMSPRIVATE_SSL";
  const char* TAMS_POSVASPUBLIC_TAG = "POSVASPUBLIC";
  const char* TAMS_POSVASPRIVATE_TAG = "POSVASPRIVATE";
  const char* TAMS_POSVASPUBLIC_SSL_TAG = "POSVASPUBLIC_SSL";
  const char* TAMS_POSVASPRIVATE_SSL_TAG = "POSVASPRIVATE_SSL";

  check(getServersFromTamsResponseHelper(
            &tamsResponse->servers.epms, tranTag, TAMS_EPMSPRIVATE_TAG,
            TAMS_EPMSPUBLIC_TAG, TAMS_EPMSPRIVATE_SSL_TAG,
            TAMS_EPMSPUBLIC_SSL_TAG) == EXIT_SUCCESS,
        "Error Getting EPMS Servers");

  check(getServersFromTamsResponseHelper(
            &tamsResponse->servers.posvas, tranTag, TAMS_POSVASPRIVATE_TAG,
            TAMS_POSVASPUBLIC_TAG, TAMS_POSVASPRIVATE_SSL_TAG,
            TAMS_POSVASPUBLIC_SSL_TAG) == EXIT_SUCCESS,
        "Error Getting POSVAS Servers");

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Remote Upgrade Server object
 *
 * @param tamsResponse
 * @param tranTag
 * @return short
 */
static short getRemoteUpgradeServer(TAMSResponse* tamsResponse,
                                    ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_REMOTEUPGRADE_PUBLIC_TAG = "REMOTEUPGRADE_PUBLIC";
  const char* TAMS_REMOTEUPGRADE_PRIVATE_TAG = "REMOTEUPGRADE_PRIVATE";

  check((item = ezxml_child(tranTag, TAMS_REMOTEUPGRADE_PUBLIC_TAG)),
        "Error Getting '%s'", TAMS_REMOTEUPGRADE_PUBLIC_TAG);
  strncpy(tamsResponse->servers.remoteUpgrade.publicServer.ip, item->txt,
          sizeof(tamsResponse->servers.remoteUpgrade.publicServer.ip));

  check((item = ezxml_child(tranTag, TAMS_REMOTEUPGRADE_PRIVATE_TAG)),
        "Error Getting '%s'", TAMS_REMOTEUPGRADE_PRIVATE_TAG);
  strncpy(tamsResponse->servers.remoteUpgrade.privateServer.ip, item->txt,
          sizeof(tamsResponse->servers.remoteUpgrade.privateServer.ip));

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Call Home Servers object
 *
 * @param tamsResponse
 * @param tranTag
 * @return short
 */
static short getCallHomeServers(TAMSResponse* tamsResponse, ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_CALLHOME_TIME_TAG = "CallhomeTime";
  const char* TAMS_CALLHOME_PORT_TAG = "CallhomePort";
  const char* TAMS_CALLHOME_IP_TAG = "CallhomeIp";
  const char* TAMS_POSVAS_CALLHOME_PORT_TAG = "CallhomePosvasPort";
  const char* TAMS_POSVAS_CALLHOME_IP_TAG = "CallhomePosvasIp";

  check((item = ezxml_child(tranTag, TAMS_CALLHOME_IP_TAG)),
        "Error Getting '%s'", TAMS_CALLHOME_IP_TAG);
  strncpy(tamsResponse->servers.callhome.ip, item->txt,
          sizeof(tamsResponse->servers.callhome.ip));

  check((item = ezxml_child(tranTag, TAMS_CALLHOME_PORT_TAG)),
        "Error Getting '%s'", TAMS_CALLHOME_PORT_TAG);
  tamsResponse->servers.callhome.port = atoi(item->txt);

  check((item = ezxml_child(tranTag, TAMS_POSVAS_CALLHOME_IP_TAG)),
        "Error Getting '%s'", TAMS_POSVAS_CALLHOME_IP_TAG);
  strncpy(tamsResponse->servers.callhomePosvas.ip, item->txt,
          sizeof(tamsResponse->servers.callhomePosvas.ip));

  check((item = ezxml_child(tranTag, TAMS_POSVAS_CALLHOME_PORT_TAG)),
        "Error Getting '%s'", TAMS_POSVAS_CALLHOME_PORT_TAG);
  tamsResponse->servers.callhomePosvas.port = atoi(item->txt);

  check((item = ezxml_child(tranTag, TAMS_CALLHOME_TIME_TAG)),
        "Error Getting '%s'", TAMS_CALLHOME_TIME_TAG);
  tamsResponse->servers.callhomeTime = atoi(item->txt);

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Servers From Tams Response object
 *
 * @param tamsResponse
 * @param tranTag
 * @return short
 */
static short getServersFromTamsResponse(TAMSResponse* tamsResponse,
                                        ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_PREFIX_TAG = "PREFIX";
  const char* TAMS_PORT_TYPE_TAG = "PORT_TYPE";
  const char* TAMS_TAMSPUBLIC_TAG = "TAMSPUBLIC";
  const char* TAMS_VASURL_TAG = "VASURL";

  check((item = ezxml_child(tranTag, TAMS_PREFIX_TAG)), "Error Getting '%s'",
        TAMS_PREFIX_TAG);
  tamsResponse->servers.middlewareServerType =
      strcmp(item->txt, "POSVAS") == 0 ? MIDDLEWARE_SERVER_TYPE_POSVAS
      : strcmp(item->txt, "EPMS") == 0 ? MIDDLEWARE_SERVER_TYPE_EPMS
                                       : MIDDLEWARE_SERVER_TYPE_UNKNOWN;

  check((item = ezxml_child(tranTag, TAMS_PORT_TYPE_TAG)), "Error Getting '%s'",
        TAMS_PORT_TYPE_TAG);
  tamsResponse->servers.connectionType =
      strcmp(item->txt, "SSL") ? CONNECTION_TYPE_PLAIN : CONNECTION_TYPE_SSL;

  check((item = ezxml_child(tranTag, TAMS_TAMSPUBLIC_TAG)),
        "Error Getting '%s'", TAMS_TAMSPUBLIC_TAG);
  strncpy(tamsResponse->servers.tams.ip, item->txt,
          sizeof(tamsResponse->servers.tams.ip));

  check((item = ezxml_child(tranTag, TAMS_VASURL_TAG)), "Error Getting '%s'",
        TAMS_VASURL_TAG);
  strncpy(tamsResponse->servers.vasUrl, item->txt,
          sizeof(tamsResponse->servers.vasUrl));

  check(getMiddlewareServers(tamsResponse, tranTag) == EXIT_SUCCESS,
        "Error Getting Middleware Servers");

  check(getRemoteUpgradeServer(tamsResponse, tranTag) == EXIT_SUCCESS,
        "Error Getting Remote Upgrade Servers");

  check(getCallHomeServers(tamsResponse, tranTag) == EXIT_SUCCESS,
        "Error Getting Call Home Servers");

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Account Info From Tams Response object
 *
 * @param handshake
 * @param tranTag
 * @return short
 */
static short getAccountInfoFromTamsResponse(Handshake_t* handshake,
                                            ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_ACCOUNT_TO_DEBIT_TAG = "ACCOUNT-TO-DEBIT";
  const char* TAMS_ACCOUNT_NUMBER_TAG = "accountnum";
  const char* TAMS_ACCOUNT_SELECTION_TAG = "accountSelection";

  check((item = ezxml_child(tranTag, TAMS_ACCOUNT_TO_DEBIT_TAG)),
        "Unable to get %s tag", TAMS_ACCOUNT_TO_DEBIT_TAG);
  strncpy(handshake->tamsResponse.accountToDebit, item->txt,
          sizeof(handshake->tamsResponse.accountToDebit));

  check((item = ezxml_child(tranTag, TAMS_ACCOUNT_NUMBER_TAG)),
        "Unable to get %s tag", TAMS_ACCOUNT_NUMBER_TAG);
  strncpy(handshake->tamsResponse.accountNumber, item->txt,
          sizeof(handshake->tamsResponse.accountNumber));

  check((item = ezxml_child(tranTag, TAMS_ACCOUNT_SELECTION_TAG)),
        "Unable to get %s tag", TAMS_ACCOUNT_SELECTION_TAG);
  handshake->tamsResponse.accountSelectionType = atoi(item->txt);

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Unable To Get Account Info");
  }
  return ret;
}

/**
 * @brief Get the Customer Info From Tams Response object
 *
 * @param handshake
 * @param tranTag
 * @return short
 */
static short getCustomerInfoFromTamsResponse(Handshake_t* handshake,
                                             ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_ADDRESS_TAG = "Address";
  const char* TAMS_AGGREGATOR_NAME_TAG = "AggregatorName";
  const char* TAMS_EMAIL_TAG = "EMAIL";
  const char* TAMS_PHONE_TAG = "phone";
  const char* TAMS_TERMAPPTYPE_TAG = "TERMAPPTYPE";
  const char* TAMS_USER_ID_TAG = "USER-ID";

  check((item = ezxml_child(tranTag, TAMS_ADDRESS_TAG)), "Unable to get %s tag",
        TAMS_ADDRESS_TAG);
  splitStr(handshake->tamsResponse.merchantName,
           sizeof(handshake->tamsResponse.merchantName),
           handshake->tamsResponse.merchantAddress,
           sizeof(handshake->tamsResponse.merchantAddress), item->txt, '|');

  check((item = ezxml_child(tranTag, TAMS_AGGREGATOR_NAME_TAG)),
        "Unable to get %s tag", TAMS_AGGREGATOR_NAME_TAG);
  strncpy(handshake->tamsResponse.aggregatorName, item->txt,
          sizeof(handshake->tamsResponse.aggregatorName));

  check((item = ezxml_child(tranTag, TAMS_EMAIL_TAG)), "Unable to get %s tag",
        TAMS_EMAIL_TAG);
  strncpy(handshake->tamsResponse.email, item->txt,
          sizeof(handshake->tamsResponse.email));

  check((item = ezxml_child(tranTag, TAMS_PHONE_TAG)), "Unable to get %s tag",
        TAMS_PHONE_TAG);
  strncpy(handshake->tamsResponse.phone, item->txt,
          sizeof(handshake->tamsResponse.phone));

  check((item = ezxml_child(tranTag, TAMS_TERMAPPTYPE_TAG)),
        "Unable to get %s tag", TAMS_TERMAPPTYPE_TAG);
  handshake->tamsResponse.terminalAppType =
      strcmp(item->txt, "MERCHANT") == 0    ? TERMINAL_APP_TYPE_MERCHANT
      : strcmp(item->txt, "AGENCY") == 0    ? TERMINAL_APP_TYPE_AGENT
      : strcmp(item->txt, "CONVERTED") == 0 ? TERMINAL_APP_TYPE_CONVERTED
                                            : TERMINAL_APP_TYPE_UNKNOWN;

  check((item = ezxml_child(tranTag, TAMS_USER_ID_TAG)), "Unable to get %s tag",
        TAMS_USER_ID_TAG);
  strncpy(handshake->tamsResponse.userId, item->txt,
          sizeof(handshake->tamsResponse.userId));

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Unable To Get Customer Info");
  }
  return ret;
}

/**
 * @brief Get the Tams Response Helper object
 *
 * @param handshake
 * @param tranTag
 * @return short
 */
static short getTamsResponseHelper(Handshake_t* handshake, ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_BALANCE_TAG = "balance";
  const char* TAMS_COMMISSION_TAG = "commission";
  const char* TAMS_NOTIFICATION_ID_TAG_OPT = "NOTIFICATION_ID";
  const char* TAMS_POS_SUPPORT_TAG = "POS_SUPPORT";
  const char* TAMS_PRE_CONNECT_TAG = "PRE-CONNECT";
  const char* TAMS_RRN_TAG = "RRN";
  const char* TAMS_STAMP_DUTY_TAG = "STAMP_DUTY";
  const char* TAMS_STAMP_DUTY_THRESHOLD_TAG = "STAMP_DUTY_THRESHOLD";
  const char* TAMS_STAMP_LABEL_TAG = "STAMP_LABEL";

  check(getAccountInfoFromTamsResponse(handshake, tranTag) == EXIT_SUCCESS,
        "Parse Error");

  check(getCustomerInfoFromTamsResponse(handshake, tranTag) == EXIT_SUCCESS,
        "Parse Error");

  check((item = ezxml_child(tranTag, TAMS_BALANCE_TAG)), "Unable to get %s tag",
        TAMS_BALANCE_TAG);
  strncpy(handshake->tamsResponse.balance, item->txt,
          sizeof(handshake->tamsResponse.balance));

  check((item = ezxml_child(tranTag, TAMS_COMMISSION_TAG)),
        "Unable to get %s tag", TAMS_COMMISSION_TAG);
  strncpy(handshake->tamsResponse.commision, item->txt,
          sizeof(handshake->tamsResponse.commision));

  if ((item = ezxml_child(tranTag, TAMS_NOTIFICATION_ID_TAG_OPT)) != NULL) {
    strncpy(handshake->tamsResponse.notificationId, item->txt,
            sizeof(handshake->tamsResponse.notificationId));
  }

  check((item = ezxml_child(tranTag, TAMS_PRE_CONNECT_TAG)),
        "Unable to get %s tag", TAMS_PRE_CONNECT_TAG);
  strncpy(handshake->tamsResponse.preConnect, item->txt,
          sizeof(handshake->tamsResponse.preConnect));

  check((item = ezxml_child(tranTag, TAMS_POS_SUPPORT_TAG)),
        "Unable to get %s tag", TAMS_POS_SUPPORT_TAG);
  strncpy(handshake->tamsResponse.posSupport, item->txt,
          sizeof(handshake->tamsResponse.posSupport));

  check((item = ezxml_child(tranTag, TAMS_RRN_TAG)), "Unable to get %s tag",
        TAMS_RRN_TAG);
  strncpy(handshake->tamsResponse.rrn, item->txt,
          sizeof(handshake->tamsResponse.rrn));

  check((item = ezxml_child(tranTag, TAMS_STAMP_DUTY_TAG)),
        "Unable to get %s tag", TAMS_STAMP_DUTY_TAG);
  strncpy(handshake->tamsResponse.stampDuty, item->txt,
          sizeof(handshake->tamsResponse.stampDuty));

  check((item = ezxml_child(tranTag, TAMS_STAMP_DUTY_THRESHOLD_TAG)),
        "Unable to get %s tag", TAMS_STAMP_DUTY_THRESHOLD_TAG);
  strncpy(handshake->tamsResponse.stampDutyThreshold, item->txt,
          sizeof(handshake->tamsResponse.stampDutyThreshold));

  check((item = ezxml_child(tranTag, TAMS_STAMP_LABEL_TAG)),
        "Unable to get %s tag", TAMS_STAMP_LABEL_TAG);
  strncpy(handshake->tamsResponse.stampLabel, item->txt,
          sizeof(handshake->tamsResponse.stampLabel));

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Parse Error");
  }
  return ret;
}

/**
 * @brief Get the Tams Response object
 *
 * @param handshake
 * @param tranTag
 * @return short
 */
static short getTamsResponse(Handshake_t* handshake, ezxml_t tranTag) {
  ezxml_t item = NULL;
  short ret = EXIT_FAILURE;
  const char* TAMS_MESSAGE_TAG = "message";

  check(
      (item = ezxml_child(tranTag, TAMS_MESSAGE_TAG)) && isdigit(item->txt[0]),
      "Unable to get %s tag", TAMS_MESSAGE_TAG);
  strncpy(handshake->tid, item->txt, sizeof(handshake->tid));

  check(getTerminalFromTamsResponse(&handshake->tamsResponse, tranTag) ==
            EXIT_SUCCESS,
        "Unable to get terminal");

  check(getServersFromTamsResponse(&handshake->tamsResponse, tranTag) ==
            EXIT_SUCCESS,
        "Unable to get servers");

  if (handshake->ptadKey == PTAD_KEY_UNKNOWN) {
    handshake->ptadKey =
        handshake->tamsResponse.servers.middlewareServerType ==
                MIDDLEWARE_SERVER_TYPE_POSVAS
            ? PTAD_KEY_POSVAS
        : handshake->tamsResponse.servers.middlewareServerType ==
                MIDDLEWARE_SERVER_TYPE_EPMS
            ? PTAD_KEY_EPMS
            : PTAD_KEY_UNKNOWN;
  }

  check(getTamsResponseHelper(handshake, tranTag) == EXIT_SUCCESS,
        "Parse Error");

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Unable to Get Mandatory Tags From Map TID Response");
  }
  return ret;
}

/**
 * @brief Parse Map TID Response Helper
 *
 * @param handshake
 * @param root
 * @return short
 */
static short parseMapDeviceResponseHelper(Handshake_t* handshake,
                                          ezxml_t root) {
  ezxml_t tranTag = NULL;
  short ret = EXIT_FAILURE;

  tranTag = ezxml_get(root, "tran", -1);

  check_mem(tranTag);
  check(getPosStatus(handshake, tranTag) == STATUS_READY,
        "Error Getting POS Status");
  check(getTamsResponse(handshake, tranTag) == EXIT_SUCCESS,
        "Error Getting TAMS Response");

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Parse Map TID Response
 *
 * @param handshake
 * @param response
 * @return short
 */
static short parseMapDeviceResponse(Handshake_t* handshake, char* response) {
  ezxml_t root = NULL;
  short ret = EXIT_FAILURE;

  root = ezxml_parse_str(response, strlen(response));
  check_mem(root);
  check(checkTamsError(handshake->error.message,
                       sizeof(handshake->error.message) - 1, root) == 0,
        "TAMS Error");
  check(parseMapDeviceResponseHelper(handshake, root) == EXIT_SUCCESS,
        "Parse Error");

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Unable to Parse Map TID Response");
  }
  ezxml_free(root);
  return ret;
}

/**
 * @brief Handshake Map Device
 *
 * @param handshake
 */
void Handshake_MapDevice(Handshake_t* handshake) {
  NetworkBuffer request = {{'\0'}, 0};
  NetworkBuffer response = {{'\0'}, 0};
  int ret = -1;

  handshake->error.code = ERROR_CODE_HANDSHAKE_MAPTID_ERROR;
  request.len = buildTamsHomeRequest((char*)request.data,
                                     sizeof(request.data) - 1, handshake);
  check(request.len > 0, "Error building TAMS request");
  debug("Request: '%s' (%ld)", request.data, request.len);

  response.len = handshake->comSendReceive(
      &response, &request, &handshake->mapDeviceHost, DEFAULT_TIMEOUT,
      handshake->comSentinel, "</efttran>");
  check(response.len > 0, "Error sending or receiving request");
  debug("Response: '%s (%ld)'", response.data, response.len);

  check(parseMapDeviceResponse(handshake, (char*)response.data) == EXIT_SUCCESS,
        "Parse Error");
  debug("TID after mapping: %s", handshake->tid);

  handshake->error.code = ERROR_CODE_NO_ERROR;
  memset(handshake->error.message, '\0', sizeof(handshake->error.message));
error:
  if (ret >= 0 && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Handshake Map Device Error");
  }
}
