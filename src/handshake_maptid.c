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

#include "../dbg.h"
#include "../ezxml/ezxml.h"

#include "../inc/handshake.h"

static const char* TAMS_ACCOUNT_TO_DEBIT_TAG = "ACCOUNT-TO-DEBIT";
static const char* TAMS_ACCOUNT_NUMBER_TAG = "accountnum";
static const char* TAMS_ACCOUNT_SELECTION_TAG = "accountSelection";
static const char* TAMS_ADDRESS_TAG = "Address";
static const char* TAMS_AGGREGATOR_NAME_TAG = "AggregatorName";
static const char* TAMS_BALANCE_TAG = "balance";
static const char* TAMS_COMMISSION_TAG = "commission";
static const char* TAMS_EMAIL_TAG = "EMAIL";
static const char* TAMS_MESSAGE_TAG = "message";
static const char* TAMS_NOTIFICATION_ID_TAG_OPT = "NOTIFICATION_ID";
static const char* TAMS_PHONE_TAG = "phone";
static const char* TAMS_POS_SUPPORT_TAG = "POS_SUPPORT";
static const char* TAMS_PRE_CONNECT_TAG = "PRE-CONNECT";
static const char* TAMS_RRN_TAG = "RRN";
static const char* TAMS_STAMP_DUTY_TAG = "STAMP_DUTY";
static const char* TAMS_STAMP_DUTY_THRESHOLD_TAG = "STAMP_DUTY_THRESHOLD";
static const char* TAMS_STAMP_LABEL_TAG = "STAMP_LABEL";
static const char* TAMS_TERMAPPTYPE_TAG = "TERMAPPTYPE";
static const char* TAMS_USER_ID_TAG = "USER-ID";

// Terminals
static const char* TAMS_AMP_TAG = "Amp";
static const char* TAMS_MOREFUN_TAG = "MoreFun";
static const char* TAMS_NEWLAND_TAG = "NewLand";
static const char* TAMS_NEWPOS_TAG = "newpos";
static const char* TAMS_NEXGO_TAG = "NexGo";
static const char* TAMS_PAX_TAG = "PAX";
static const char* TAMS_PAYSHARP_TAG = "PAYSHARP";
static const char* TAMS_VERIFONE_TAG = "verifones";

// Servers
static const char* TAMS_PREFIX_TAG = "PREFIX";
static const char* TAMS_PORT_TYPE_TAG = "PORT_TYPE";
static const char* TAMS_TAMSPUBLIC_TAG = "TAMSPUBLIC";
static const char* TAMS_EPMSPUBLIC_TAG = "EPMSPUBLIC";
static const char* TAMS_EPMSPRIVATE_TAG = "EPMSPRIVATE";
static const char* TAMS_EPMSPUBLIC_SSL_TAG = "EPMSPUBLIC_SSL";
static const char* TAMS_EPMSPRIVATE_SSL_TAG = "EPMSPRIVATE_SSL";
static const char* TAMS_POSVASPUBLIC_TAG = "POSVASPUBLIC";
static const char* TAMS_POSVASPRIVATE_TAG = "POSVASPRIVATE";
static const char* TAMS_POSVASPUBLIC_SSL_TAG = "POSVASPUBLIC_SSL";
static const char* TAMS_POSVASPRIVATE_SSL_TAG = "POSVASPRIVATE_SSL";
static const char* TAMS_REMOTEUPGRADE_PUBLIC_TAG = "REMOTEUPGRADE_PUBLIC";
static const char* TAMS_REMOTEUPGRADE_PRIVATE_TAG = "REMOTEUPGRADE_PRIVATE";
static const char* TAMS_CALLHOME_TIME_TAG = "CallhomeTime";
static const char* TAMS_CALLHOME_PORT_TAG = "CallhomePort";
static const char* TAMS_CALLHOME_IP_TAG = "CallhomeIp";
static const char* TAMS_POSVAS_CALLHOME_PORT_TAG = "CallhomePosvasPort";
static const char* TAMS_POSVAS_CALLHOME_IP_TAG = "CallhomePosvasIp";
static const char* TAMS_VASURL_TAG = "VASURL";

typedef enum { STATUS_READY, STATUS_NOT_READY } pos_status;

/**
 * @brief Builds TAMS Request
 *
 * @param handshake
 * @param requestBuf
 * @param bufLen
 * @return ssize_t
 */
static ssize_t buildTamsHomeRequest(
    Handshake_t* handshake, char* requestBuf, size_t bufLen)
{
    const char* TRANS_ADVICE_PATH
        = "tams/eftpos/devinterface/transactionadvice.php";
    const char* DEFAULT_TID = "2070AS89";
    ssize_t pos = 0;

    pos += snprintf(requestBuf, bufLen,
        "GET "
        "/%s?action=TAMS_WEBAPI&termID=%s&posUID=%s&ver=%s%s&model=%s&control="
        "TamsSecurity\r\n",
        TRANS_ADVICE_PATH, DEFAULT_TID, handshake->deviceInfo.posUid,
        handshake->appInfo.name, handshake->appInfo.version,
        handshake->deviceInfo.model);
    pos += snprintf(&requestBuf[pos], bufLen - pos, "Host: %s:%d",
        handshake->mapTidHost.hostUrl, handshake->mapTidHost.port);
    pos += snprintf(&requestBuf[pos], bufLen - pos, "%s", "\r\n\r\n");

    return pos;
}

/**
 * @brief Checks TAMS Error in Response
 *
 * @param handshake
 * @param root
 * @return short
 */
static short checkTamsError(Handshake_t* handshake, ezxml_t root)
{
    ezxml_t msgTag, errorTag;

    errorTag = ezxml_child(root, "error");

    if (errorTag) {
        msgTag = ezxml_child(errorTag, "errmsg");
    } else {
        msgTag = ezxml_child(root, "errmsg");
    }

    if (msgTag) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "%s", msgTag->txt);
        return 1;
    }

    return 0;
}

/**
 * @brief Get the Pos Status object
 *
 * @param handshake
 * @param tranTag
 * @return pos_status
 */
static pos_status getPosStatus(Handshake_t* handshake, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, "result")) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get result tag");
        return STATUS_NOT_READY;
    }

    debug("RESULT: %s", item->txt);
    if (strncmp(item->txt, "0", 1)) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "(Result) %s Not Mapped", handshake->deviceInfo.posUid);
        return STATUS_NOT_READY;
    }

    if ((item = ezxml_child(tranTag, "status")) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get status tag");
        return STATUS_NOT_READY;
    }

    debug("STATUS: %s", item->txt);
    if (strncmp(item->txt, "1", 1)) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "(Status) %s Not Mapped", handshake->deviceInfo.posUid);
        return STATUS_NOT_READY;
    }

    return STATUS_READY;
}

/**
 * @brief Split string at separator
 *
 * @param firstPart
 * @param fLen
 * @param secondPart
 * @param sLen
 * @param data
 * @param separator
 */
static void splitStr(char* firstPart, size_t fLen, char* secondPart,
    size_t sLen, const char* data, int separator)
{
    const char* separatorIndex = strchr(data, separator);
    size_t len = 0;

    if (separatorIndex == NULL)
        return;
    len = separatorIndex - data;
    strncpy(firstPart, data, len > fLen ? fLen : len);
    strncpy(secondPart, &separatorIndex[1], sLen);
}

/**
 * @brief Get the Terminal From Tams Response object
 *
 * @param tamsResponse
 * @param tranTag
 * @return short
 */
static short getTerminalFromTamsResponse(
    TAMSResponse* tamsResponse, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, TAMS_AMP_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.amp, item->txt,
        sizeof(tamsResponse->terminals.amp));

    if ((item = ezxml_child(tranTag, TAMS_MOREFUN_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.moreFun, item->txt,
        sizeof(tamsResponse->terminals.moreFun));

    if ((item = ezxml_child(tranTag, TAMS_NEWLAND_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.newLand, item->txt,
        sizeof(tamsResponse->terminals.newLand));

    if ((item = ezxml_child(tranTag, TAMS_NEWPOS_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.newPos, item->txt,
        sizeof(tamsResponse->terminals.newPos));

    if ((item = ezxml_child(tranTag, TAMS_NEXGO_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.nexGo, item->txt,
        sizeof(tamsResponse->terminals.nexGo));

    if ((item = ezxml_child(tranTag, TAMS_PAX_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.pax, item->txt,
        sizeof(tamsResponse->terminals.pax));

    if ((item = ezxml_child(tranTag, TAMS_PAYSHARP_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.paySharp, item->txt,
        sizeof(tamsResponse->terminals.paySharp));

    if ((item = ezxml_child(tranTag, TAMS_VERIFONE_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->terminals.verifone, item->txt,
        sizeof(tamsResponse->terminals.verifone));

    return EXIT_SUCCESS;
}

/**
 * @brief Get the Servers From Tams Response object Helper
 *
 * @param server
 * @param tranTag
 * @param privateTag
 * @param publicTag
 * @return short
 */
static short getServersFromTamsResponseHelper(MiddlewareServer* server,
    ezxml_t tranTag, const char* privateTag, const char* publicTag,
    const char* privateSslTag, const char* publicSslTag)
{
    ezxml_t item = NULL;
    char portBuf[16] = { '\0' };

    if ((item = ezxml_child(tranTag, privateTag)) == NULL) {
        return EXIT_FAILURE;
    }
    memset(portBuf, '\0', sizeof(portBuf));
    splitStr(server->plain.privateServer.ip, sizeof(server->plain.privateServer.ip),
        portBuf, sizeof(portBuf), item->txt, ';');
    server->plain.privateServer.port = atoi(portBuf);

    if ((item = ezxml_child(tranTag, publicTag)) == NULL) {
        return EXIT_FAILURE;
    }
    memset(portBuf, '\0', sizeof(portBuf));
    splitStr(server->plain.publicServer.ip, sizeof(server->plain.publicServer.ip), portBuf,
        sizeof(portBuf), item->txt, ';');
    server->plain.publicServer.port = atoi(portBuf);

    if ((item = ezxml_child(tranTag, privateSslTag)) == NULL) {
        return EXIT_FAILURE;
    }
    memset(portBuf, '\0', sizeof(portBuf));
    splitStr(server->ssl.privateServer.ip, sizeof(server->ssl.privateServer.ip), portBuf,
        sizeof(portBuf), item->txt, ';');
    server->ssl.privateServer.port = atoi(portBuf);

    if ((item = ezxml_child(tranTag, publicSslTag)) == NULL) {
        return EXIT_FAILURE;
    }
    memset(portBuf, '\0', sizeof(portBuf));
    splitStr(server->ssl.publicServer.ip, sizeof(server->ssl.publicServer.ip), portBuf,
        sizeof(portBuf), item->txt, ';');
    server->ssl.publicServer.port = atoi(portBuf);

    return EXIT_SUCCESS;
}

static short getMiddlewareServers(TAMSResponse* tamsResponse, ezxml_t tranTag)
{
    if (getServersFromTamsResponseHelper(&tamsResponse->servers.epms, tranTag,
            TAMS_EPMSPRIVATE_TAG, TAMS_EPMSPUBLIC_TAG, TAMS_EPMSPRIVATE_SSL_TAG,
            TAMS_EPMSPUBLIC_SSL_TAG)
        != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (getServersFromTamsResponseHelper(&tamsResponse->servers.posvas, tranTag,
            TAMS_POSVASPRIVATE_TAG, TAMS_POSVASPUBLIC_TAG,
            TAMS_POSVASPRIVATE_SSL_TAG, TAMS_POSVASPUBLIC_SSL_TAG)
        != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static short getRemoteUpgradeServer(TAMSResponse* tamsResponse, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, TAMS_REMOTEUPGRADE_PUBLIC_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->servers.remoteUpgrade.publicServer.ip, item->txt,
        sizeof(tamsResponse->servers.remoteUpgrade.publicServer.ip));

    if ((item = ezxml_child(tranTag, TAMS_REMOTEUPGRADE_PRIVATE_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->servers.remoteUpgrade.privateServer.ip, item->txt,
        sizeof(tamsResponse->servers.remoteUpgrade.privateServer.ip));

    return EXIT_SUCCESS;
}

static short getCallhomeServers(TAMSResponse* tamsResponse, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, TAMS_CALLHOME_IP_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->servers.callhome.ip, item->txt,
        sizeof(tamsResponse->servers.callhome.ip));

    if ((item = ezxml_child(tranTag, TAMS_CALLHOME_PORT_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    tamsResponse->servers.callhome.port = atoi(item->txt);

    if ((item = ezxml_child(tranTag, TAMS_POSVAS_CALLHOME_IP_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->servers.callhomePosvas.ip, item->txt,
        sizeof(tamsResponse->servers.callhomePosvas.ip));

    if ((item = ezxml_child(tranTag, TAMS_POSVAS_CALLHOME_PORT_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    tamsResponse->servers.callhomePosvas.port = atoi(item->txt);

    if ((item = ezxml_child(tranTag, TAMS_CALLHOME_TIME_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    tamsResponse->servers.callhomeTime = atoi(item->txt);

    return EXIT_SUCCESS;
}

/**
 * @brief Get the Servers From Tams Response object
 *
 * @param tamsResponse
 * @param tranTag
 * @return short
 */
static short getServersFromTamsResponse(
    TAMSResponse* tamsResponse, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, TAMS_PREFIX_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    tamsResponse->servers.middlewareServerType
        = strcmp(item->txt, "POSVAS") == 0 ? MIDDLEWARE_SERVER_TYPE_POSVAS
        : strcmp(item->txt, "EPMS") == 0   ? MIDDLEWARE_SERVER_TYPE_EPMS
                                           : MIDDLEWARE_SERVER_TYPE_UNKNOWN;

    if ((item = ezxml_child(tranTag, TAMS_PORT_TYPE_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    tamsResponse->servers.connectionType = strcmp(item->txt, "SSL")
        ? CONNECTION_TYPE_PLAIN
        : CONNECTION_TYPE_SSL;

    if ((item = ezxml_child(tranTag, TAMS_TAMSPUBLIC_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->servers.tams.ip, item->txt,
        sizeof(tamsResponse->servers.tams.ip));

    if ((item = ezxml_child(tranTag, TAMS_VASURL_TAG)) == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(tamsResponse->servers.vasUrl, item->txt,
        sizeof(tamsResponse->servers.vasUrl));

    if (getMiddlewareServers(tamsResponse, tranTag) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (getRemoteUpgradeServer(tamsResponse, tranTag) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (getCallhomeServers(tamsResponse, tranTag) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static short getAccountInfoFromTamsResponse(
    Handshake_t* handshake, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, TAMS_ACCOUNT_TO_DEBIT_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_ACCOUNT_TO_DEBIT_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.accountToDebit, item->txt,
        sizeof(handshake->tamsResponse.accountToDebit));

    if ((item = ezxml_child(tranTag, TAMS_ACCOUNT_NUMBER_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_ACCOUNT_NUMBER_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.accountNumber, item->txt,
        sizeof(handshake->tamsResponse.accountNumber));

    if ((item = ezxml_child(tranTag, TAMS_ACCOUNT_SELECTION_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_ACCOUNT_SELECTION_TAG);
        return EXIT_FAILURE;
    }
    handshake->tamsResponse.accountSelectionType = atoi(item->txt);

    return EXIT_SUCCESS;
}

static short getCustomerInfoFromTamsResponse(
    Handshake_t* handshake, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, TAMS_ADDRESS_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_ADDRESS_TAG);
        return EXIT_FAILURE;
    }
    splitStr(handshake->tamsResponse.merchantName,
        sizeof(handshake->tamsResponse.merchantName),
        handshake->tamsResponse.merchantAddress,
        sizeof(handshake->tamsResponse.merchantAddress), item->txt, '|');

    if ((item = ezxml_child(tranTag, TAMS_AGGREGATOR_NAME_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_AGGREGATOR_NAME_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.aggregatorName, item->txt,
        sizeof(handshake->tamsResponse.aggregatorName));

    if ((item = ezxml_child(tranTag, TAMS_EMAIL_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_EMAIL_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.email, item->txt,
        sizeof(handshake->tamsResponse.email));

    if ((item = ezxml_child(tranTag, TAMS_PHONE_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_PHONE_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.phone, item->txt,
        sizeof(handshake->tamsResponse.phone));

    if ((item = ezxml_child(tranTag, TAMS_TERMAPPTYPE_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_TERMAPPTYPE_TAG);
        return EXIT_FAILURE;
    }
    handshake->tamsResponse.terminalAppType = strcmp(item->txt, "MERCHANT") == 0
        ? TERMINAL_APP_TYPE_MERCHANT
        : strcmp(item->txt, "AGENCY") == 0    ? TERMINAL_APP_TYPE_AGENT
        : strcmp(item->txt, "CONVERTED") == 0 ? TERMINAL_APP_TYPE_CONVERTED
                                              : TERMINAL_APP_TYPE_UNKNOWN;

    if ((item = ezxml_child(tranTag, TAMS_USER_ID_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_USER_ID_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.userId, item->txt,
        sizeof(handshake->tamsResponse.userId));

    return EXIT_SUCCESS;
}

static short getTamsResponseHelper(Handshake_t* handshake, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if (getAccountInfoFromTamsResponse(handshake, tranTag) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if (getCustomerInfoFromTamsResponse(handshake, tranTag) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    if ((item = ezxml_child(tranTag, TAMS_BALANCE_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_BALANCE_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.balance, item->txt,
        sizeof(handshake->tamsResponse.balance));

    if ((item = ezxml_child(tranTag, TAMS_COMMISSION_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_COMMISSION_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.commision, item->txt,
        sizeof(handshake->tamsResponse.commision));

    if ((item = ezxml_child(tranTag, TAMS_NOTIFICATION_ID_TAG_OPT)) != NULL) {
        strncpy(handshake->tamsResponse.notificationId, item->txt,
            sizeof(handshake->tamsResponse.notificationId));
    }

    if ((item = ezxml_child(tranTag, TAMS_PRE_CONNECT_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_PRE_CONNECT_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.preConnect, item->txt,
        sizeof(handshake->tamsResponse.preConnect));

    if ((item = ezxml_child(tranTag, TAMS_POS_SUPPORT_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_POS_SUPPORT_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.posSupport, item->txt,
        sizeof(handshake->tamsResponse.posSupport));

    if ((item = ezxml_child(tranTag, TAMS_RRN_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_RRN_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.rrn, item->txt,
        sizeof(handshake->tamsResponse.rrn));

    if ((item = ezxml_child(tranTag, TAMS_STAMP_DUTY_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_STAMP_DUTY_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.stampDuty, item->txt,
        sizeof(handshake->tamsResponse.stampDuty));

    if ((item = ezxml_child(tranTag, TAMS_STAMP_DUTY_THRESHOLD_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_STAMP_DUTY_THRESHOLD_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.stampDutyThreshold, item->txt,
        sizeof(handshake->tamsResponse.stampDutyThreshold));

    if ((item = ezxml_child(tranTag, TAMS_STAMP_LABEL_TAG)) == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag", TAMS_STAMP_LABEL_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tamsResponse.stampLabel, item->txt,
        sizeof(handshake->tamsResponse.stampLabel));

    return EXIT_SUCCESS;
}

/**
 * @brief Get the Tams Response object
 *
 * @param handshake
 * @param tranTag
 * @return short
 */
static short getTamsResponse(Handshake_t* handshake, ezxml_t tranTag)
{
    ezxml_t item = NULL;

    if ((item = ezxml_child(tranTag, TAMS_MESSAGE_TAG)) == NULL
        || !isdigit(item->txt[0])) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get %s tag (TID)", TAMS_MESSAGE_TAG);
        return EXIT_FAILURE;
    }
    strncpy(handshake->tid, item->txt, sizeof(handshake->tid));

    if (getTerminalFromTamsResponse(&handshake->tamsResponse, tranTag)
        != EXIT_SUCCESS) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get terminal tags");
        return EXIT_FAILURE;
    }

    if (getServersFromTamsResponse(&handshake->tamsResponse, tranTag)
        != EXIT_SUCCESS) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get servers");
        return EXIT_FAILURE;
    }

    if (getTamsResponseHelper(handshake, tranTag) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

/**
 * @brief Parse Map TID Response Helper
 *
 * @param handshake
 * @param root
 * @return short
 */
static short parseMapTidResponseHelper(Handshake_t* handshake, ezxml_t root)
{
    ezxml_t tranTag = NULL;

    tranTag = ezxml_get(root, "tran", -1);

    if (tranTag == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to get tran tag");
        return EXIT_FAILURE;
    }
    if (getPosStatus(handshake, tranTag) != STATUS_READY)
        return EXIT_FAILURE;
    if (getTamsResponse(handshake, tranTag) != EXIT_SUCCESS)
        return EXIT_FAILURE;
    return EXIT_SUCCESS;
}

/**
 * @brief Parse Map TID Response
 *
 * @param handshake
 * @param response
 * @return short
 */
static short parseMapTidResponse(Handshake_t* handshake, char* response)
{
    ezxml_t root = NULL;
    short ret = EXIT_FAILURE;

    root = ezxml_parse_str(response, strlen(response));
    if (root == NULL) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Unable to parse response");
        goto exit;
    }
    if (checkTamsError(handshake, root))
        goto exit;
    if (parseMapTidResponseHelper(handshake, root) != EXIT_SUCCESS)
        goto exit;

    ret = EXIT_SUCCESS;
exit:
    ezxml_free(root);
    return ret;
}

/**
 * @brief Handshake Map TID
 *
 * @param handshake
 */
void Handshake_MapTid(Handshake_t* handshake)
{
    char requestBuf[0x1000] = { '\0' };
    unsigned char responseBuf[0x1000] = { '\0' };
    ssize_t pos = 0;
    int ret = -1;

    handshake->error.code = ERROR_CODE_HANDSHAKE_MAPTID_ERROR;
    pos = buildTamsHomeRequest(handshake, requestBuf, sizeof(requestBuf) - 1);
    if (pos <= 0) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error building TAMS request");
        return;
    }
    debug("Request: '%s'", requestBuf);

    ret = handshake->comSendReceive(responseBuf, sizeof(responseBuf) - 1,
        (unsigned char*)requestBuf, sizeof(requestBuf) - 1,
        handshake->mapTidHost.hostUrl, handshake->mapTidHost.port,
        handshake->hostSentinel, "</efttran>");
    if (ret < 0) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error sending or receiving request");
        return;
    }
    debug("Response: '%s (%d)'", responseBuf, ret);

    if (parseMapTidResponse(handshake, (char*)responseBuf) != EXIT_SUCCESS)
        return;
    debug("TID after mapping: %s", handshake->tid);

    handshake->error.code = ERROR_CODE_NO_ERROR;
    memset(handshake->error.message, '\0', sizeof(handshake->error.message));
}
