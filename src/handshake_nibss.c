/**
 * @file handshake_nibss.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implements NIBSS Handshake
 * @version 0.1
 * @date 2023-02-19
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <string.h>
#include <time.h>

#include "../c8583/C8583.h"
#include "../c8583/FieldNames.h"
#include "../dbg.h"

#include "../inc/handshake.h"
#include "../inc/handshake_internals.h"

typedef enum {
    NETWORK_MANAGEMENT_MASTER_KEY,
    NETWORK_MANAGEMENT_SESSION_KEY,
    NETWORK_MANAGEMENT_PIN_KEY,
    NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD,
    NETWORK_MANAGEMENT_CALL_HOME,
    NETWORK_MANAGEMENT_UNKNOWN,
} NetworkManagementType;

static void rightTrim(char* input, const char ch)
{
    int len = strlen(input);

    while (len--) {
        if (input[len] == ch) {
            input[len] = '\0';
        } else {
            break;
        }
    }
}

static short c8583Check(
    Handshake_t* handshake, const short failed, IsoMsg isoMsg)
{
    if (failed) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "ISO Error - %s", getMessage(isoMsg));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static short isApprovedResponse(const char* responseCode)
{
    return strncmp(responseCode, "00", strlen(responseCode)) == 0;
}

static const char* networkManagementTypeToProcessCode(
    NetworkManagementType networkManagementType)
{
    switch (networkManagementType) {
    case NETWORK_MANAGEMENT_MASTER_KEY:
        return "9A";
    case NETWORK_MANAGEMENT_SESSION_KEY:
        return "9B";
    case NETWORK_MANAGEMENT_PIN_KEY:
        return "9G";
    case NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD:
        return "9C";
    default:
        return NULL;
    }
}

int buildNetworkManagementIso(unsigned char* packetBuf, size_t len,
    Handshake_t* handshake, NetworkManagementType networkManagementType)
{
    char dateTimeBuff[16] = { '\0' };
    char dateBuff[8] = { '\0' };
    char timeBuff[8] = { '\0' };
    char processingCode[8] = { '\0' };
    time_t now = time(NULL);
    struct tm now_t = *localtime(&now);
    IsoMsg isoMsg = createIso8583();
    short ret = -1;
    const unsigned char NETWORK_MANAGEMENT_MTI[] = "0800";

    snprintf(processingCode, sizeof(processingCode), "%s0000",
        networkManagementTypeToProcessCode(networkManagementType));
    strftime(dateTimeBuff, sizeof(dateTimeBuff), "%m%d%H%M%S", &now_t);
    strftime(dateBuff, sizeof(dateBuff), "%m%d", &now_t);
    strftime(timeBuff, sizeof(timeBuff), "%H%M%S", &now_t);

    if (c8583Check(handshake,
            setDatum(
                isoMsg, MESSAGE_TYPE_INDICATOR_0, NETWORK_MANAGEMENT_MTI, 4),
            isoMsg))
        goto exit;
    if (c8583Check(handshake,
            setDatum(isoMsg, PROCESSING_CODE_3, (unsigned char*)processingCode,
                strlen(processingCode)),
            isoMsg))
        goto exit;
    if (c8583Check(handshake,
            setDatum(isoMsg, TRANSACTION_DATE_TIME_7,
                (unsigned char*)dateTimeBuff, strlen(dateTimeBuff)),
            isoMsg))
        goto exit;
    if (c8583Check(handshake,
            setDatum(isoMsg, SYSTEM_TRACE_AUDIT_NUMBER_11,
                (unsigned char*)timeBuff, strlen(timeBuff)),
            isoMsg))
        goto exit;
    if (c8583Check(handshake,
            setDatum(isoMsg, LOCAL_TRANSACTION_TIME_12,
                (unsigned char*)timeBuff, strlen(timeBuff)),
            isoMsg))
        goto exit;
    if (c8583Check(handshake,
            setDatum(isoMsg, LOCAL_TRANSACTION_DATE_13,
                (unsigned char*)dateBuff, strlen(dateBuff)),
            isoMsg))
        goto exit;
    if (c8583Check(handshake,
            setDatum(isoMsg, CARD_ACCEPTOR_TERMINAL_IDENTIFICATION_41,
                (unsigned char*)handshake->tid, strlen(handshake->tid)),
            isoMsg))
        goto exit;

    ret = packData(isoMsg, packetBuf, len);
exit:
    destroyIso8583(isoMsg);
    return ret;
}

short parseGetKeyResponse(
    Handshake_t* handshake, unsigned char* responseBuf, Key* key)
{
    short ret = EXIT_FAILURE;
    IsoMsg isoMsg = createIso8583();
    unsigned char de53Buff[97] = { '\0' };
    size_t keySize = sizeof(key->key) - 1;

    if (c8583Check(handshake,
            unpackData(
                isoMsg, &responseBuf[2], (responseBuf[0] << 8) + responseBuf[1])
                == 0,
            isoMsg))
        goto exit;

    logIsoMsg(isoMsg, stderr);

    if (c8583Check(handshake,
            getDatum(isoMsg, RESPONSE_CODE_39,
                handshake->networkManagementResponse.responseCode, 3)
                == 0,
            isoMsg))
        goto exit;
    if (!isApprovedResponse(handshake->networkManagementResponse.responseCode))
        goto exit;

    if (c8583Check(handshake,
            getDatum(isoMsg, SECURITY_RELATED_CONTROL_INFORMATION_53, de53Buff,
                sizeof(de53Buff))
                == 0,
            isoMsg))
        goto exit;

    rightTrim((char*)de53Buff, '0');
    memcpy(key->key, de53Buff, keySize);
    memcpy(key->kcv, &de53Buff[keySize], strlen((char*)de53Buff) - keySize);
    debug("Key: %s", key->key);
    debug("KCV: %s", key->kcv);

    ret = EXIT_SUCCESS;
exit:
    destroyIso8583(isoMsg);
    return ret;
}

static short getKey(Handshake_t* handshake, Key* key,
    NetworkManagementType networkManagementType)
{
    unsigned char packetBuf[0x1000] = { '\0' };
    unsigned char responseBuf[0x1000] = { '\0' };
    unsigned char requestBuf[0x1000] = { '\0' };
    int len = 0;

    memset(packetBuf, '\0', sizeof(packetBuf));
    len = buildNetworkManagementIso(
        packetBuf, sizeof(packetBuf), handshake, networkManagementType);
    if (len <= 0) {
        return EXIT_FAILURE;
    }

    debug("Packet: '%s (%d)'", packetBuf, len);

    snprintf((char*)requestBuf, sizeof(requestBuf) - 1, "%c%c%s", len >> 8, len,
        packetBuf);

    len = handshake->comSendReceive(responseBuf, sizeof(responseBuf) - 1,
        requestBuf, sizeof(requestBuf) - 1, handshake->handshakeHost.hostUrl,
        handshake->handshakeHost.port, NULL, NULL);
    if (len < 0) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error sending or receiving request");
        return EXIT_FAILURE;
    }

    debug("Response: '%s (%d) (%d)'", &responseBuf[2], len,
        (responseBuf[0] << 8) + responseBuf[1]);
    if (parseGetKeyResponse(handshake, responseBuf, key) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

static short getMasterKey(void* vHandshake)
{
    Handshake_t* handshake = (Handshake_t*)vHandshake;

    debug("MASTER");
    return getKey(handshake, &handshake->networkManagementResponse.master,
        NETWORK_MANAGEMENT_MASTER_KEY);
}

static short getSessionKey(void* vHandshake)
{
    Handshake_t* handshake = (Handshake_t*)vHandshake;

    debug("SESSION");
    return getKey(handshake, &handshake->networkManagementResponse.session,
        NETWORK_MANAGEMENT_SESSION_KEY);
}

static short getPinKey(void* vHandshake)
{
    Handshake_t* handshake = (Handshake_t*)vHandshake;

    debug("PIN");
    return getKey(handshake, &handshake->networkManagementResponse.pin,
        NETWORK_MANAGEMENT_PIN_KEY);
}

void bindNibss(Handshake_t* handshake)
{
    handshake->getMasterKey = getMasterKey;
    handshake->getSessionKey = getSessionKey;
    handshake->getPinKey = getPinKey;
}
