#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../dbg.h"
#include "../inc/handshake.h"
#include "../platform/comms.h"
#include "../platform/utils.h"
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

    memset(&handshake, '\0', sizeof(Handshake_t));

    handshake.comSendReceive = NULL;
    handshake.comSentinel = isResponseSentinel;

    Handshake(&handshake);
    log_err("%s", handshake.error.message);
    mu_assert(handshake.error.code == ERROR_CODE_HANDSHAKE_INIT_ERROR, "%s",
        handshake.error.message);

    return NULL;
}

const char* testHandshakeInit_hostNotSet()
{
    Handshake_t handshake;

    memset(&handshake, '\0', sizeof(Handshake_t));

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    Handshake(&handshake);
    log_err("%s", handshake.error.message);
    mu_assert(handshake.error.code == ERROR_CODE_HANDSHAKE_INIT_ERROR, "%s",
        handshake.error.message);

    return NULL;
}

const char* testHandshakeInit_mapTidTrue_dataNotSet()
{
    Handshake_t handshake;

    memset(&handshake, '\0', sizeof(Handshake_t));

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.platform = PLATFORM_NIBSS;
    handshake.mapTid = HANDSHAKE_MAPTID_TRUE;
    strcpy(handshake.tid, "");
    strcpy(handshake.mapTidHost.hostUrl, "197.253.19.75");
    handshake.mapTidHost.port = 443;

    Handshake(&handshake);
    log_err("%s", handshake.error.message);
    mu_assert(handshake.error.code == ERROR_CODE_HANDSHAKE_INIT_ERROR, "%s",
        handshake.error.message);

    return NULL;
}

const char* testHandshakeInit_mapTidTrue()
{
    Handshake_t handshake;

    memset(&handshake, '\0', sizeof(Handshake_t));

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;
    handshake.getCallHomeData = getState;

    handshake.operations = HANDSHAKE_OPERATIONS_ALL;
    handshake.platform = PLATFORM_NIBSS;
    handshake.mapTid = HANDSHAKE_MAPTID_TRUE;
    strcpy(handshake.tid, "2033GP24");

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.mapTidHost.hostUrl, "197.253.19.75");
    handshake.mapTidHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* testHandshake_Tams()
{
    Handshake_t handshake;

    memset(&handshake, '\0', sizeof(Handshake_t));

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.operations = HANDSHAKE_OPERATIONS_ALL;
    handshake.platform = PLATFORM_TAMS;
    strcpy(handshake.tid, "22330745");

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.handshakeHost.hostUrl, "197.253.19.75");
    handshake.handshakeHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* allTests()
{
    mu_suite_start();

    // mu_run_test(testHandshakeInit_comSendReceiveNotSet);
    // mu_run_test(testHandshakeInit_hostNotSet);
    // mu_run_test(testHandshakeInit_mapTidTrue_dataNotSet);
    // mu_run_test(testHandshakeInit_mapTidTrue);
    mu_run_test(testHandshake_Tams);

    return NULL;
}

RUN_TESTS(allTests);
