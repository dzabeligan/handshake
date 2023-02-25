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
#include "../des/des.h"
#include "../inc/handshake_utils.h"

#include "../inc/handshake_internals.h"

typedef enum {
    NETWORK_MANAGEMENT_MASTER_KEY,
    NETWORK_MANAGEMENT_SESSION_KEY,
    NETWORK_MANAGEMENT_PIN_KEY,
    NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD,
    NETWORK_MANAGEMENT_CALL_HOME,
    NETWORK_MANAGEMENT_UNKNOWN,
} NetworkManagementType;

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

static const char* networkManagementTypeToString(
    NetworkManagementType networkManagementType)
{
    switch (networkManagementType) {
    case NETWORK_MANAGEMENT_MASTER_KEY:
        return "MASTER KEY";
    case NETWORK_MANAGEMENT_SESSION_KEY:
        return "SESSION KEY";
    case NETWORK_MANAGEMENT_PIN_KEY:
        return "PIN KEY";
    case NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD:
        return "PARAMETER DOWNLOAD";
    case NETWORK_MANAGEMENT_CALL_HOME:
        return "CALL HOME";
    default:
        return NULL;
    }
}

static int buildDE62(char* buf, size_t bufLen, Handshake_t* handshake,
    NetworkManagementType networkManagementType)
{
    short pos = 0;

    if (networkManagementType != NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD
        && networkManagementType != NETWORK_MANAGEMENT_CALL_HOME)
        return EXIT_FAILURE;

    pos += snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "01",
        (int)strlen(handshake->deviceInfo.posUid),
        handshake->deviceInfo.posUid);
    if (networkManagementType == NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD)
        return EXIT_SUCCESS;

    pos += snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "09",
        (int)strlen(handshake->appInfo.version), handshake->appInfo.version);
    pos += snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "10",
        (int)strlen(handshake->deviceInfo.model), handshake->deviceInfo.model);
    pos += snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "11",
        (int)strlen("handshake->deviceInfo.model"),
        "handshake->deviceInfo.model");
    snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "12",
        (int)strlen(handshake->simInfo.imsi), handshake->simInfo.imsi);

    return EXIT_SUCCESS;
}

static const char* getPtadKey(PtadKey ptadKey)
{
    switch (ptadKey) {
    case PTAD_KEY_EPMS:
        return "DBCC87EE50A6810682FAD28B1190F578";
    case PTAD_KEY_POSVAS:
        return "F9F6FF09D77B6A78595541DB63D821FA";
    case PTAD_KEY_NIBSS:
        return "DBEECACCB4210977ACE73A1D873CA59F";
    case PTAD_KEY_TAMS:
        return "ACE73A1D873CA59FDBCC87EE50A68106";
    case PTAD_KEY_UNKNOWN:
    default:
        return NULL;
    }
}

static short checkKeyValue(const char* key, const char* kcv)
{
    unsigned char keyBcd[16];
    unsigned char actualCheckValueBcd[16] = { '\0' };
    unsigned char data[9] = "\x00\x00\x00\x00\x00\x00";
    char actualCheckValueStr[33] = { '\0' };

    debug("Key: '%s'", key);
    ascToBcd(keyBcd, sizeof(keyBcd), (const char*)key);
    des3_ecb_encrypt(
        actualCheckValueBcd, data, sizeof(data) - 1, keyBcd, sizeof(keyBcd));
    bcdToAsc((unsigned char*)actualCheckValueStr, sizeof(actualCheckValueStr),
        actualCheckValueBcd, sizeof(actualCheckValueBcd));
    debug("KCV: '%s'", actualCheckValueStr);

    return strncmp(kcv, actualCheckValueStr, 6) == 0;
}

static void getClearKey(
    char* clearKey, const int size, const char* encryptedData, const char* key)
{
    unsigned char keyBcd[16];
    unsigned char encrytedDataBcd[16];
    unsigned char clearKeyBcd[16];

    ascToBcd(keyBcd, sizeof(keyBcd), (const char*)key);
    ascToBcd(
        encrytedDataBcd, sizeof(encrytedDataBcd), (const char*)encryptedData);

    des3_ecb_decrypt(clearKeyBcd, encrytedDataBcd, sizeof(encrytedDataBcd),
        keyBcd, sizeof(keyBcd));
    bcdToAsc((unsigned char*)clearKey, size, clearKeyBcd, sizeof(clearKeyBcd));
}

static void getDecryptionKey(Handshake_t* handshake,
    NetworkManagementType networkManagementType, char* decryptionKey,
    size_t keyBufLen)
{
    if (networkManagementType == NETWORK_MANAGEMENT_MASTER_KEY) {
        strncpy(decryptionKey, getPtadKey(handshake->ptadKey), keyBufLen);
    } else {
        char clearKey[33] = { '\0' };

        getClearKey(clearKey, sizeof(clearKey),
            (char*)handshake->networkManagementResponse.master.key,
            getPtadKey(handshake->ptadKey));

        strncpy(decryptionKey, clearKey, keyBufLen);
    }
}

static short validateKey(Handshake_t* handshake, Key* key,
    NetworkManagementType networkManagementType)
{
    char decryptionKey[33] = { '\0' };
    char clearKey[33] = { '\0' };

    getDecryptionKey(
        handshake, networkManagementType, decryptionKey, sizeof(decryptionKey));
    getClearKey(clearKey, sizeof(clearKey), (char*)key->key, decryptionKey);

    debug("Decryption key '%s'", decryptionKey);
    debug("Clear key '%s'", clearKey);

    if (!checkKeyValue(clearKey, (char*)key->kcv)) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error validating key (%s)",
            networkManagementTypeToString(networkManagementType));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int buildNetworkManagementIso(unsigned char* packetBuf, size_t len,
    Handshake_t* handshake, NetworkManagementType networkManagementType)
{
    char dateTimeBuff[16] = { '\0' };
    char dateBuff[8] = { '\0' };
    char timeBuff[8] = { '\0' };
    char processingCode[8] = { '\0' };
    char de62Buf[0x1000] = { '\0' };
    time_t now = time(NULL);
    struct tm now_t = *localtime(&now);
    IsoMsg isoMsg = createIso8583();
    short ret = -1;
    short useMac = 0;
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
    if (buildDE62(de62Buf, sizeof(de62Buf), handshake, networkManagementType)
        == EXIT_SUCCESS) {
        if (c8583Check(handshake,
                setDatum(isoMsg, RESERVED_PRIVATE_62, (unsigned char*)de62Buf,
                    strlen(de62Buf)),
                isoMsg))
            goto exit;
        useMac = 1;
    }

    logIsoMsg(isoMsg, stderr);

    if (useMac) {
        char decryptionKey[33] = { '\0' };
        char clearKey[33] = { '\0' };

        getDecryptionKey(handshake, NETWORK_MANAGEMENT_SESSION_KEY,
            decryptionKey, sizeof(decryptionKey));
        getClearKey(clearKey, sizeof(clearKey),
            (char*)handshake->networkManagementResponse.session.key,
            decryptionKey);

        ret = packDataWithMac(isoMsg, packetBuf, len, (unsigned char*)clearKey,
            strlen(clearKey), generateMac);
    } else {
        ret = packData(isoMsg, packetBuf, len);
    }
exit:
    destroyIso8583(isoMsg);
    return ret;
}

static short parseGetKeyResponse(
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
                (unsigned char*)
                    handshake->networkManagementResponse.responseCode,
                3)
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

    if (validateKey(handshake, key, networkManagementType) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static int getLength(char* line, int nCopy)
{
    int len = strlen(line);
    int ret = 0;
    char value[23] = { '\0' };

    if (len && (nCopy < len)) {
        char buffer[0x1000] = { '\0' };

        strncpy(value, line, nCopy);
        sprintf(buffer, "%s", &line[nCopy]);
        memset(line, '\0', strlen(line));
        sprintf(line, "%s", buffer);
        ret = atoi(value);
    }

    return ret;
}

static int getValue(char* line, char* value, int nCopy)
{
    int len = strlen(line);

    if (len && nCopy <= len) {
        char buffer[10000] = { '\0' };
        sprintf(buffer, "%s", &line[nCopy]);
        strncpy(value, line, nCopy);
        memset(line, '\0', strlen(line));
        sprintf(line, "%s", buffer);
        return nCopy;
    }

    return 0;
}

static short expandMerchantParameters(
    Handshake_t* handshake, const char* de62, const int size)
{
    int tagLen, valueWidth;
    char current[0x512] = { '\0' };
    int processed = 0;

    sprintf(current, "%s", de62);

    tagLen = 2;
    valueWidth = 3;

    while (1) {
        char nextTag[3] = { '\0' };
        int result = 0;
        getValue(current, nextTag, tagLen);

        if (!atoi(nextTag) || processed >= size)
            break;

        if (strcmp(nextTag, "02") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter
                    .serverDateAndTime,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "03") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter.cardAcceptorID,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "04") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter.timeout,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "05") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter.currencyCode,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "06") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter.countryCode,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "07") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter.callHomeTime,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "08") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter
                    .merchantCategoryCode,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "52") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameter
                    .merchantNameAndLocation,
                getLength(current, valueWidth));
        }

        if (result)
            processed += result;
    }

    return 0;
}

static short parseGetNetworkDataResponse(
    Handshake_t* handshake, unsigned char* responseBuf)
{
    short ret = EXIT_FAILURE;
    IsoMsg isoMsg = createIso8583();
    unsigned char de62Buff[0x1000] = { '\0' };

    if (c8583Check(handshake,
            unpackData(
                isoMsg, &responseBuf[2], (responseBuf[0] << 8) + responseBuf[1])
                == 0,
            isoMsg))
        goto exit;

    logIsoMsg(isoMsg, stderr);

    if (c8583Check(handshake,
            getDatum(isoMsg, RESPONSE_CODE_39,
                (unsigned char*)
                    handshake->networkManagementResponse.responseCode,
                3)
                == 0,
            isoMsg))
        goto exit;

    if (!isApprovedResponse(handshake->networkManagementResponse.responseCode))
        goto exit;

    if (c8583Check(handshake,
            getDatum(isoMsg, RESERVED_PRIVATE_62, de62Buff, sizeof(de62Buff))
                == 0,
            isoMsg))
        goto exit;
    expandMerchantParameters(handshake, (char*)de62Buff, sizeof(de62Buff));
    ret = EXIT_SUCCESS;
exit:
    destroyIso8583(isoMsg);
    return ret;
}

static short getNetworkData(
    Handshake_t* handshake, NetworkManagementType networkManagementType)
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

    if (parseGetNetworkDataResponse(handshake, responseBuf) != EXIT_SUCCESS) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static short getMasterKey(void* vHandshake)
{
    Handshake_t* handshake = (Handshake_t*)vHandshake;

    debug("\n\nMASTER");
    return getKey(handshake, &handshake->networkManagementResponse.master,
        NETWORK_MANAGEMENT_MASTER_KEY);
}

static short getSessionKey(void* vHandshake)
{
    Handshake_t* handshake = (Handshake_t*)vHandshake;

    debug("\n\nSESSION");
    return getKey(handshake, &handshake->networkManagementResponse.session,
        NETWORK_MANAGEMENT_SESSION_KEY);
}

static short getPinKey(void* vHandshake)
{
    Handshake_t* handshake = (Handshake_t*)vHandshake;

    debug("\n\nPIN");
    return getKey(handshake, &handshake->networkManagementResponse.pin,
        NETWORK_MANAGEMENT_PIN_KEY);
}

static short getParameter(void* vHandshake)
{
    (void)vHandshake;
    debug("\n\nPARAMETER");
    return EXIT_SUCCESS;
}

void bindNibss(Handshake_t* handshake)
{
    handshake->getMasterKey = getMasterKey;
    handshake->getSessionKey = getSessionKey;
    handshake->getPinKey = getPinKey;
    handshake->getParameter = getParameter;
}
