#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../dbg.h"
#include "../inc/handshake.h"
#include "../platform/comms.h"
#include "../platform/utils.h"
#include "minunit.h"

Handshake_t g_handshake = HANDSHAKE_INIT_DATA;

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
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

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
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

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
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.platform = PLATFORM_NIBSS;
    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;
    strcpy(handshake.tid, "");
    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    log_err("%s", handshake.error.message);
    mu_assert(handshake.error.code == ERROR_CODE_HANDSHAKE_INIT_ERROR, "%s",
        handshake.error.message);

    return NULL;
}

// NIBSS TESTS
// -------------------------------------------------------------
const char* test_HandshakeNibssAllMapDeviceTrue()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;
    handshake.getCallHomeData = getState;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;
    handshake.platform = PLATFORM_NIBSS;

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssAllMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;
    handshake.getCallHomeData = getState;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_FALSE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.ptadKey = PTAD_KEY_POSVAS;

    strcpy(handshake.tid, "2033GP24");

    // not required
    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 5003;
    // needed if call home host is different from handshake host
    strcpy(handshake.callHomeHost.hostUrl, "basehuge.itexapp.com");
    handshake.callHomeHost.port = 7003;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssMasterMapDeviceTrue()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.operations = HANDSHAKE_OPERATIONS_MASTER_KEY;

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssMasterMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_FALSE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.ptadKey = PTAD_KEY_POSVAS;
    handshake.operations = HANDSHAKE_OPERATIONS_MASTER_KEY;

    strcpy(handshake.tid, "2033GP24");

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 5003;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    strcpy((char*)g_handshake.networkManagementResponse.master.key,
        (char*)handshake.networkManagementResponse.master.key);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssSessionMapDeviceTrue()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.operations = HANDSHAKE_OPERATIONS_SESSION_KEY;

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssSessionMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_FALSE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.ptadKey = PTAD_KEY_POSVAS;
    handshake.operations = HANDSHAKE_OPERATIONS_SESSION_KEY;

    strcpy(handshake.tid, "2033GP24");

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 5003;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    strcpy((char*)g_handshake.networkManagementResponse.session.key,
        (char*)handshake.networkManagementResponse.session.key);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssPinMapDeviceTrue()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.operations = HANDSHAKE_OPERATIONS_PIN_KEY;

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssPinMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;
    handshake.getCallHomeData = getState;

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_FALSE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.ptadKey = PTAD_KEY_POSVAS;
    handshake.operations = HANDSHAKE_OPERATIONS_PIN_KEY;

    strcpy(handshake.tid, "2033GP24");

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 5003;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssParametersMapDeviceTrue()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    // session key needed
    strcpy((char*)handshake.networkManagementResponse.session.key,
        (char*)g_handshake.networkManagementResponse.session.key);

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.operations = HANDSHAKE_OPERATIONS_PARAMETER;

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssParametersMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    // session key needed
    strcpy((char*)handshake.networkManagementResponse.session.key,
        (char*)g_handshake.networkManagementResponse.session.key);

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_FALSE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.ptadKey = PTAD_KEY_POSVAS;
    handshake.operations = HANDSHAKE_OPERATIONS_PARAMETER;

    strcpy(handshake.tid, "2033GP24");

    // not required
    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 5003;
    // needed if call home host is different from handshake host
    strcpy(handshake.callHomeHost.hostUrl, "basehuge.itexapp.com");
    handshake.callHomeHost.port = 7003;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssCallHomeMapDeviceTrue()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;
    handshake.getCallHomeData = getState;

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    // session key needed
    strcpy((char*)handshake.networkManagementResponse.session.key,
        (char*)g_handshake.networkManagementResponse.session.key);

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.operations = HANDSHAKE_OPERATIONS_CALLHOME;

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeNibssCallHomeMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    // not required
    handshake.comSentinel = isResponseSentinel;
    handshake.getCallHomeData = getState;

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    // session key needed
    strcpy((char*)handshake.networkManagementResponse.session.key,
        (char*)g_handshake.networkManagementResponse.session.key);

    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_FALSE;
    handshake.platform = PLATFORM_NIBSS;
    handshake.ptadKey = PTAD_KEY_POSVAS;
    handshake.operations = HANDSHAKE_OPERATIONS_CALLHOME;

    strcpy(handshake.tid, "2033GP24");

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.simInfo.imsi, "621301234567890");
    handshake.simInfo.simType = SIM_TYPE_PUBLIC;

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 5003;
    // needed if call home host is different from handshake host
    strcpy(handshake.callHomeHost.hostUrl, "basehuge.itexapp.com");
    handshake.callHomeHost.port = 7003;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logTamsResponse(&handshake.tamsResponse);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

// TAMS TESTS
// -------------------------------------------------------------
const char* test_HandshakeTamsAllMapDeviceTrue()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.operations = HANDSHAKE_OPERATIONS_ALL;
    handshake.platform = PLATFORM_TAMS;
    handshake.mapDevice = HANDSHAKE_MAP_DEVICE_TRUE;

    // not required tid will be replaced after mapping device
    strcpy(handshake.tid, "22330745");

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 443;

    strcpy(handshake.mapDeviceHost.hostUrl, "basehuge.itexapp.com");
    handshake.mapDeviceHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeTamsAllMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.operations = HANDSHAKE_OPERATIONS_ALL;
    handshake.platform = PLATFORM_TAMS;
    strcpy(handshake.tid, "22330745");

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeTamsMasterMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.operations = HANDSHAKE_OPERATIONS_MASTER_KEY;
    handshake.platform = PLATFORM_TAMS;
    strcpy(handshake.tid, "22330745");

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    strcpy((char*)g_handshake.networkManagementResponse.master.key,
        (char*)handshake.networkManagementResponse.master.key);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeTamsSessionMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.operations = HANDSHAKE_OPERATIONS_SESSION_KEY;
    handshake.platform = PLATFORM_TAMS;
    strcpy(handshake.tid, "22330745");

    // master key needed
    strcpy((char*)handshake.networkManagementResponse.master.key,
        (char*)g_handshake.networkManagementResponse.master.key);

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    strcpy((char*)g_handshake.networkManagementResponse.session.key,
        (char*)handshake.networkManagementResponse.session.key);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeTamsParametersMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.operations = HANDSHAKE_OPERATIONS_PARAMETER;
    handshake.platform = PLATFORM_TAMS;
    strcpy(handshake.tid, "22330745");

    // session key needed
    strcpy((char*)handshake.networkManagementResponse.session.key,
        (char*)g_handshake.networkManagementResponse.session.key);

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
    handshake.handshakeHost.port = 443;

    Handshake(&handshake);
    mu_assert(handshake.error.code == ERROR_CODE_NO_ERROR, "%s",
        handshake.error.message);
    logNetworkManagementResponse(&handshake.networkManagementResponse);

    return NULL;
}

const char* test_HandshakeTamsEftTotalMapDeviceFalse()
{
    Handshake_t handshake = HANDSHAKE_INIT_DATA;

    handshake.comSendReceive = comSendReceive;
    handshake.comSentinel = isResponseSentinel;

    handshake.operations = HANDSHAKE_OPERATIONS_EFT_TOTAL;
    handshake.platform = PLATFORM_TAMS;
    strcpy(handshake.tid, "22330745");

    // session key needed
    strcpy((char*)handshake.networkManagementResponse.session.key,
        (char*)g_handshake.networkManagementResponse.session.key);

    strcpy(handshake.appInfo.name, "Tamslite");
    strcpy(handshake.appInfo.version, "0.0.1");

    strcpy(handshake.deviceInfo.model, "LaptopPort");
    strcpy(handshake.deviceInfo.posUid, "346228245");

    strcpy(handshake.handshakeHost.hostUrl, "basehuge.itexapp.com");
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

    mu_run_test(testHandshakeInit_comSendReceiveNotSet);
    mu_run_test(testHandshakeInit_hostNotSet);
    mu_run_test(testHandshakeInit_mapTidTrue_dataNotSet);

    // NIBSS TESTS
    mu_run_test(test_HandshakeNibssAllMapDeviceTrue);
    mu_run_test(test_HandshakeNibssAllMapDeviceFalse);
    mu_run_test(test_HandshakeNibssMasterMapDeviceTrue);
    mu_run_test(test_HandshakeNibssMasterMapDeviceFalse);
    mu_run_test(test_HandshakeNibssSessionMapDeviceTrue);
    mu_run_test(test_HandshakeNibssSessionMapDeviceFalse);
    mu_run_test(test_HandshakeNibssPinMapDeviceTrue);
    mu_run_test(test_HandshakeNibssPinMapDeviceFalse);
    mu_run_test(test_HandshakeNibssParametersMapDeviceTrue);
    mu_run_test(test_HandshakeNibssParametersMapDeviceFalse);
    mu_run_test(test_HandshakeNibssCallHomeMapDeviceTrue);
    mu_run_test(test_HandshakeNibssCallHomeMapDeviceFalse);

    // TAMS TESTS
    // need to find device that is mapped and has master key change enabled
    // mu_run_test(test_HandshakeTamsAllMapDeviceTrue);

    mu_run_test(test_HandshakeTamsAllMapDeviceFalse);
    mu_run_test(test_HandshakeTamsMasterMapDeviceFalse);
    mu_run_test(test_HandshakeTamsSessionMapDeviceFalse);
    mu_run_test(test_HandshakeTamsParametersMapDeviceFalse);
    mu_run_test(test_HandshakeTamsEftTotalMapDeviceFalse);

    return NULL;
}

RUN_TESTS(allTests);
