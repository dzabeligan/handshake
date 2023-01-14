/**
 * @file handshake.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implements Handshake with NIBSS or Middleware and TAMS
 * @version 0.1
 * @date 2023-01-09
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <stdio.h>

#include "../dbg.h"

#include "../inc/handshake.h"

static const char* TRANS_ADVICE_PATH
    = "tams/eftpos/devinterface/transactionadvice.php";
static const char* TAMS_HOME_IP = "197.253.19.75";
static const int TAMS_HOME_PORT = 443;

/**
 * @brief Check that data needed for mapping tid is set
 *
 * @param initData
 * @return short
 */
static short checkMapTidData(handshake_InitData* initData)
{
    return initData->appInfo.name[0] && initData->appInfo.version[0]
        && initData->deviceInfo.model[0] && initData->deviceInfo.posUid[0];
}

/**
 * @brief Ensures all data needed for handshake is set.
 * Should be called before `Handshake_Run`
 *
 * @test comSendReceive and host must be set
 * if mapTid is false, tid must be set
 * else, data needed for mapping tid must be set
 *
 * @param handshake
 * @param initData
 */
void Handshake_Init(Handshake* handshake, handshake_InitData* initData)
{
    const char* DEFAULT_TID = "12345678";

    memset(handshake, '\0', sizeof(Handshake));

    handshake->error.code = ERROR_CODE_HANDSHAKE_INIT_ERROR;

    if (!initData->comSendReceive || !initData->host.host[0]) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "`comSendReceive` or `host` not set");
        return;
    }
    handshake->comSendReceive = initData->comSendReceive;
    handshake->hostSentinel = initData->hostSentinel;
    handshake->platform = initData->platform;
    handshake->mapTid = initData->mapTid;

    memcpy(&handshake->host, &initData->host, sizeof(handshake->host));

    if (handshake->mapTid == HANDSHAKE_MAPTID_FALSE && !(initData->tid[0])) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "TID can't be empty when `mapTid` is false");
        return;
    }

    strncpy(handshake->tid, initData->tid[0] ? initData->tid : DEFAULT_TID,
        sizeof(handshake->tid));
    if (handshake->mapTid == HANDSHAKE_MAPTID_TRUE
        && !checkMapTidData(initData)) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Map TID data not set");
        return;
    }

    memcpy(&handshake->appInfo, &initData->appInfo, sizeof(handshake->appInfo));
    memcpy(&handshake->deviceInfo, &initData->deviceInfo,
        sizeof(handshake->deviceInfo));

    handshake->error.code = ERROR_CODE_NO_ERROR;
    memset(handshake->error.message, '\0', sizeof(handshake->error.message));
}

static ssize_t buildTamsHomeRequest(
    Handshake* handshake, char* requestBuf, size_t bufLen)
{
    ssize_t pos = 0;

    pos += snprintf(requestBuf, bufLen,
        "GET "
        "/%s?action=TAMS_WEBAPI&termID=%s&posUID=%s&ver=%s%s&model=%s&control="
        "TamsSecurity\r\n",
        TRANS_ADVICE_PATH, handshake->tid, handshake->deviceInfo.posUid,
        handshake->appInfo.name, handshake->appInfo.version,
        handshake->deviceInfo.model);
    pos += snprintf(&requestBuf[pos], bufLen - pos, "Host: %s:%d",
        handshake->host.host, handshake->host.port);
    pos += snprintf(&requestBuf[pos], bufLen - pos, "%s", "\r\n\r\n");

    return pos;
}

static handshake_Status Handshake_MapTid(Handshake* handshake)
{
    handshake_Status status = HANDSHAKE_MAPTID_FAILURE;
    char requestBuf[0x1000] = { '\0' };
    unsigned char responseBuf[0x1000] = { '\0' };
    ssize_t pos = 0;

    pos = buildTamsHomeRequest(handshake, requestBuf, sizeof(requestBuf) - 1);
    if (pos <= 0)
        return status;

    debug("Request: '%s'", requestBuf);
    handshake->comSendReceive(responseBuf, sizeof(responseBuf) - 1,
        (unsigned char*)requestBuf, sizeof(requestBuf) - 1, TAMS_HOME_IP,
        TAMS_HOME_PORT, handshake->hostSentinel, "</efttran>");
    debug("Response: '%s'", responseBuf);

    return status;
}

static handshake_Status Handshake_PlatformHandshake(Handshake* handshake)
{
    handshake_Status status = HANDSHAKE_FAILURE;
    (void)handshake;

    return status;
}

handshake_Status Handshake_Run(Handshake* handshake)
{
    if (handshake->mapTid == HANDSHAKE_MAPTID_TRUE) {
        handshake_Status status = Handshake_MapTid(handshake);
        if (status != HANDSHAKE_MAPTID_SUCCESS)
            return status;
    }
    return Handshake_PlatformHandshake(handshake);
}
