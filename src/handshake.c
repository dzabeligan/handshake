/**
 * @file handshake.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implements Handshake with NIBSS/Middleware and TAMS
 * @version 0.1
 * @date 2023-01-09
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <stdio.h>

#include "../dbg.h"

#include "../inc/handshake.h"
#include "../inc/handshake_internals.h"

/**
 * @brief Check that data needed for mapping tid is set
 *
 * @param initData
 * @return short
 */
static short checkMapTidData(handshake_InitData* initData)
{
    return initData->appInfo.name[0] && initData->appInfo.version[0]
        && initData->deviceInfo.model[0] && initData->deviceInfo.posUid[0]
        && initData->mapTidHost.hostUrl[0] && initData->mapTidHost.port != 0;
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
static void Handshake_Init(Handshake_t* handshake, handshake_InitData* initData)
{
    memset(handshake, '\0', sizeof(Handshake_t));

    handshake->error.code = ERROR_CODE_HANDSHAKE_INIT_ERROR;

    if (!initData->comSendReceive
        || (!(initData->mapTidHost.hostUrl[0]
            || initData->handshakeHost.hostUrl[0]))) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "`comSendReceive` or `host` not set");
        return;
    }
    handshake->comSendReceive = initData->comSendReceive;
    handshake->hostSentinel = initData->hostSentinel;
    handshake->platform = initData->platform;
    handshake->mapTid = initData->mapTid;
    handshake->simType = initData->simType;

    memcpy(&handshake->mapTidHost, &initData->mapTidHost,
        sizeof(handshake->mapTidHost));
    memcpy(&handshake->handshakeHost, &initData->handshakeHost,
        sizeof(handshake->handshakeHost));
    memcpy(&handshake->callHomeHost, &initData->callHomeHost,
        sizeof(handshake->callHomeHost));

    if (handshake->mapTid == HANDSHAKE_MAPTID_FALSE && !(initData->tid[0])) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "TID can't be empty when `mapTid` is false");
        return;
    }

    strncpy(handshake->tid, initData->tid, sizeof(handshake->tid));
    if (handshake->mapTid == HANDSHAKE_MAPTID_TRUE
        && !checkMapTidData(initData)) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Map TID `data` or `host` not set");
        return;
    }

    memcpy(&handshake->appInfo, &initData->appInfo, sizeof(handshake->appInfo));
    memcpy(&handshake->deviceInfo, &initData->deviceInfo,
        sizeof(handshake->deviceInfo));

    if (handshake->platform == PLATFORM_NIBSS) {
        bindNibss(handshake);
    }

    handshake->error.code = ERROR_CODE_NO_ERROR;
    memset(handshake->error.message, '\0', sizeof(handshake->error.message));
}

static void getHandshakeHostHelper(
    Handshake_t* handshake, PrivatePublicServer* server)
{
    SimType simType = handshake->simType;

    if (simType == SIM_TYPE_PUBLIC) {
        strncpy(handshake->handshakeHost.hostUrl, server->publicServer.ip,
            sizeof(handshake->handshakeHost.hostUrl));
        handshake->handshakeHost.port = server->publicServer.port;
    } else if (simType == SIM_TYPE_PRIVATE) {
        strncpy(handshake->handshakeHost.hostUrl, server->privateServer.ip,
            sizeof(handshake->handshakeHost.hostUrl));
        handshake->handshakeHost.port = server->privateServer.port;
    }
}

static void getHandshakeHost(
    Handshake_t* handshake, MiddlewareServer* middlewareServer)
{
    ConnectionType connectionType
        = handshake->tamsResponse.servers.connectionType;

    if (connectionType == CONNECTION_TYPE_SSL) {
        getHandshakeHostHelper(handshake, &middlewareServer->ssl);
    } else if (connectionType == CONNECTION_TYPE_PLAIN) {
        getHandshakeHostHelper(handshake, &middlewareServer->plain);
    }
}

static void Handshake_GetHosts(Handshake_t* handshake)
{
    MiddlewareServerType middlewareServerType
        = handshake->tamsResponse.servers.middlewareServerType;
    int fromTamsResponse = 0;

    if (!handshake->handshakeHost.hostUrl[0]
        || handshake->handshakeHost.port == 0) {
        if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_POSVAS) {
            getHandshakeHost(
                handshake, &handshake->tamsResponse.servers.posvas);
        } else if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_EPMS) {
            getHandshakeHost(
                handshake, &handshake->tamsResponse.servers.posvas);
        }

        fromTamsResponse = 1;
    }

    if (!handshake->callHomeHost.hostUrl[0]
        || handshake->callHomeHost.port == 0) {
        if (fromTamsResponse) {
            if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_POSVAS) {
                strncpy(handshake->callHomeHost.hostUrl,
                    handshake->tamsResponse.servers.callhomePosvas.ip,
                    sizeof(handshake->callHomeHost.hostUrl));
                handshake->callHomeHost.port
                    = handshake->tamsResponse.servers.callhomePosvas.port;
            } else if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_EPMS) {
                strncpy(handshake->callHomeHost.hostUrl,
                    handshake->tamsResponse.servers.callhome.ip,
                    sizeof(handshake->callHomeHost.hostUrl));
                handshake->callHomeHost.port
                    = handshake->tamsResponse.servers.callhome.port;
            }
        } else {
            strncpy(handshake->callHomeHost.hostUrl,
                handshake->handshakeHost.hostUrl,
                sizeof(handshake->callHomeHost.hostUrl));
            handshake->callHomeHost.port = handshake->handshakeHost.port;
        }
        handshake->callHomeHost.receiveTimeout
            = handshake->tamsResponse.servers.callhomeTime;
    }
}

static void Handshake_Run(Handshake_t* handshake, HandshakeOperations ops)
{
    handshake->error.code = ERROR_CODE_HANDSHAKE_RUN_ERROR;

    if (ops & HANDSHAKE_OPERATIONS_MASTER_KEY) {
        if (handshake->getMasterKey(handshake) != EXIT_SUCCESS)
            return;
    }
    if (ops & HANDSHAKE_OPERATIONS_SESSION_KEY) {
        if (handshake->getSessionKey(handshake) != EXIT_SUCCESS)
            return;
    }
    if (ops & HANDSHAKE_OPERATIONS_PIN_KEY) {
        if (handshake->getPinKey(handshake) != EXIT_SUCCESS)
            return;
    }

    handshake->error.code = ERROR_CODE_NO_ERROR;
    memset(handshake->error.message, '\0', sizeof(handshake->error.message));
}

void Handshake(Handshake_t* handshake, handshake_InitData* initData,
    HandshakeOperations ops)
{
    Handshake_Init(handshake, initData);
    if (handshake->error.code != ERROR_CODE_NO_ERROR)
        return;

    if (handshake->mapTid == HANDSHAKE_MAPTID_TRUE) {
        Handshake_MapTid(handshake);
        if (handshake->error.code != ERROR_CODE_NO_ERROR)
            return;
    }

    Handshake_GetHosts(handshake);
    debug("Handshake host: %s:%d", handshake->handshakeHost.hostUrl,
        handshake->handshakeHost.port);
    debug("Callhome host: %s:%d", handshake->callHomeHost.hostUrl,
        handshake->callHomeHost.port);

    Handshake_Run(handshake, ops);
}
