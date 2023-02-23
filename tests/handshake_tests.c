#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../dbg.h"
#include "../inc/handshake.h"
#include "../platform/comms.h"
#include "minunit.h"

static int isResponseSentinel(
    unsigned char* packet, const int bytesRead, const char* endTag)
{
    int result = 0;

    if (bytesRead) {
        const int tpduSize = 2;

        if (*packet && endTag && *endTag
            && strstr((const char*)packet, endTag)) {
            result = 1;
        } else if (bytesRead > 2 && *(&packet[tpduSize])) {
            unsigned char bcdLen[2];
            int msgLen;

            memcpy(bcdLen, packet, tpduSize);
            msgLen = ((bcdLen[0] << 8) + bcdLen[1]) + tpduSize;
            result = (msgLen == bytesRead) ? 1 : 0;
        }

        packet[bytesRead] = 0;
    }

    return result;
}

const char* testHandshakeInit_comSendReceiveNotSet()
{
    Handshake_t handshake;
    handshake_InitData initData;

    memset(&initData, '\0', sizeof(initData));

    initData.comSendReceive = NULL;
    initData.hostSentinel = isResponseSentinel;

    Handshake(&handshake, &initData, HANDSHAKE_OPERATIONS_ALL);
    log_err("%s", handshake.error.message);
    mu_assert(handshake.error.code == ERROR_CODE_HANDSHAKE_INIT_ERROR, "%s",
        handshake.error.message);

    return NULL;
}

const char* testHandshakeInit_hostNotSet()
{
    Handshake_t handshake;
    handshake_InitData initData;

    memset(&initData, '\0', sizeof(initData));

    initData.comSendReceive = comSendReceive;
    initData.hostSentinel = isResponseSentinel;

    Handshake(&handshake, &initData, HANDSHAKE_OPERATIONS_ALL);
    log_err("%s", handshake.error.message);
    mu_assert(handshake.error.code == ERROR_CODE_HANDSHAKE_INIT_ERROR, "%s",
        handshake.error.message);

    return NULL;
}

const char* testHandshakeInit_mapTidTrue_dataNotSet()
{
    Handshake_t handshake;
    handshake_InitData initData;

    memset(&initData, '\0', sizeof(initData));

    initData.comSendReceive = comSendReceive;
    initData.hostSentinel = isResponseSentinel;

    initData.platform = PLATFORM_NIBSS;
    initData.mapTid = HANDSHAKE_MAPTID_TRUE;
    strcpy(initData.tid, "");
    strcpy(initData.mapTidHost.hostUrl, "197.253.19.75");
    initData.mapTidHost.port = 443;

    Handshake(&handshake, &initData, HANDSHAKE_OPERATIONS_ALL);
    log_err("%s", handshake.error.message);
    mu_assert(handshake.error.code == ERROR_CODE_HANDSHAKE_INIT_ERROR, "%s",
        handshake.error.message);

    return NULL;
}

const char* testHandshakeInit_mapTidTrue()
{
    Handshake_t handshake;
    handshake_InitData initData;

    memset(&initData, '\0', sizeof(initData));

    initData.comSendReceive = comSendReceive;
    initData.hostSentinel = isResponseSentinel;

    initData.platform = PLATFORM_NIBSS;
    initData.mapTid = HANDSHAKE_MAPTID_TRUE;
    strcpy(initData.tid, "2033GP24");
    strcpy(initData.appInfo.name, "Tamslite");
    strcpy(initData.appInfo.version, "0.0.1");
    strcpy(initData.deviceInfo.model, "LaptopPort");
    strcpy(initData.deviceInfo.posUid, "346228245");
    strcpy(initData.mapTidHost.hostUrl, "197.253.19.75");
    initData.mapTidHost.port = 443;

    Handshake(&handshake, &initData, HANDSHAKE_OPERATIONS_ALL);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);

    return NULL;
}

const char* allTests()
{
    mu_suite_start();

    mu_run_test(testHandshakeInit_comSendReceiveNotSet);
    mu_run_test(testHandshakeInit_hostNotSet);
    mu_run_test(testHandshakeInit_mapTidTrue_dataNotSet);
    mu_run_test(testHandshakeInit_mapTidTrue);

    return NULL;
}

RUN_TESTS(allTests);
