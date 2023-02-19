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

    strncpy(handshake->tid, initData->tid, sizeof(handshake->tid));
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

static void Handshake_PlatformHandshake(Handshake* handshake)
{
    (void)handshake;

    return;
}

void Handshake_Run(Handshake* handshake)
{
    if (handshake->mapTid == HANDSHAKE_MAPTID_TRUE) {
        Handshake_MapTid(handshake);
        if (handshake->error.code != ERROR_CODE_NO_ERROR)
            return;
    }
    Handshake_PlatformHandshake(handshake);
}
