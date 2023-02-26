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
    case NETWORK_MANAGEMENT_CALL_HOME:
        return "9D";
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
    short ret = EXIT_FAILURE;
    char state[0x10000] = { '\0' };

    check_debug(networkManagementType == NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD
            || networkManagementType == NETWORK_MANAGEMENT_CALL_HOME,
        "Build DE 62 for only `Parameters Download` or `Call Home`");

    pos += snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "01",
        (int)strlen(handshake->deviceInfo.posUid),
        handshake->deviceInfo.posUid);
    if (networkManagementType == NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD)
        return EXIT_SUCCESS;

    pos += snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "09",
        (int)strlen(handshake->appInfo.version), handshake->appInfo.version);
    pos += snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "10",
        (int)strlen(handshake->deviceInfo.model), handshake->deviceInfo.model);
    check(handshake->getCallHomeData(state, sizeof(state)),
        "Error Getting State");
    pos += snprintf(
        &buf[pos], bufLen - pos, "%s%03d%s", "11", (int)strlen(state), state);
    snprintf(&buf[pos], bufLen - pos, "%s%03d%s", "12",
        (int)strlen(handshake->simInfo.imsi), handshake->simInfo.imsi);

    ret = EXIT_SUCCESS;
error:
    return ret;
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

    check(c8583Check(handshake,
              setDatum(
                  isoMsg, MESSAGE_TYPE_INDICATOR_0, NETWORK_MANAGEMENT_MTI, 4),
              isoMsg)
            == EXIT_SUCCESS,
        "Error Setting MTI");
    check(c8583Check(handshake,
              setDatum(isoMsg, PROCESSING_CODE_3,
                  (unsigned char*)processingCode, strlen(processingCode)),
              isoMsg)
            == EXIT_SUCCESS,
        "Error Setting DE 3");
    check(c8583Check(handshake,
              setDatum(isoMsg, TRANSACTION_DATE_TIME_7,
                  (unsigned char*)dateTimeBuff, strlen(dateTimeBuff)),
              isoMsg)
            == EXIT_SUCCESS,
        "Error Setting DE 7");
    check(c8583Check(handshake,
              setDatum(isoMsg, SYSTEM_TRACE_AUDIT_NUMBER_11,
                  (unsigned char*)timeBuff, strlen(timeBuff)),
              isoMsg)
            == EXIT_SUCCESS,
        "Error Setting DE 11");
    check(c8583Check(handshake,
              setDatum(isoMsg, LOCAL_TRANSACTION_TIME_12,
                  (unsigned char*)timeBuff, strlen(timeBuff)),
              isoMsg)
            == EXIT_SUCCESS,
        "Error Setting DE 12");
    check(c8583Check(handshake,
              setDatum(isoMsg, LOCAL_TRANSACTION_DATE_13,
                  (unsigned char*)dateBuff, strlen(dateBuff)),
              isoMsg)
            == EXIT_SUCCESS,
        "Error Setting DE 13");
    check(c8583Check(handshake,
              setDatum(isoMsg, CARD_ACCEPTOR_TERMINAL_IDENTIFICATION_41,
                  (unsigned char*)handshake->tid, strlen(handshake->tid)),
              isoMsg)
            == EXIT_SUCCESS,
        "Error Setting DE 41");
    if (buildDE62(de62Buf, sizeof(de62Buf), handshake, networkManagementType)
        == EXIT_SUCCESS) {
        check(c8583Check(handshake,
                  setDatum(isoMsg, RESERVED_PRIVATE_62, (unsigned char*)de62Buf,
                      strlen(de62Buf)),
                  isoMsg)
                == EXIT_SUCCESS,
            "Error Setting DE 62");
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
error:
    destroyIso8583(isoMsg);
    return ret;
}

static int getLength(char* line, int nCopy)
{
    int ret = 0;
    int len = strlen(line);

    if (len && (nCopy < len)) {
        char value[23] = { '\0' };
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

static short parseDE62(
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
                handshake->networkManagementResponse.parameters
                    .serverDateAndTime,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "03") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameters.cardAcceptorID,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "04") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameters.timeout,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "05") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameters.currencyCode,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "06") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameters.countryCode,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "07") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameters.callHomeTime,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "08") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameters
                    .merchantCategoryCode,
                getLength(current, valueWidth));
        } else if (strcmp(nextTag, "52") == 0) {
            result = getValue(current,
                handshake->networkManagementResponse.parameters
                    .merchantNameAndLocation,
                getLength(current, valueWidth));
        }

        if (result)
            processed += result;
    }

    return 0;
}

static short getNetworkDataHelper(unsigned char* responseBuf, size_t bufLen,
    Handshake_t* handshake, NetworkManagementType networkManagementType)
{
    unsigned char packetBuf[0x1000] = { '\0' };
    unsigned char requestBuf[0x1000] = { '\0' };
    int len = 0;
    short ret = EXIT_FAILURE;

    memset(packetBuf, '\0', sizeof(packetBuf));
    len = buildNetworkManagementIso(
        packetBuf, sizeof(packetBuf), handshake, networkManagementType);
    check(len > 0, "Error Building Packet");
    debug("Packet: '%s (%d)'", packetBuf, len);

    snprintf((char*)requestBuf, sizeof(requestBuf) - 1, "%c%c%s", len >> 8, len,
        packetBuf);

    if (networkManagementType == NETWORK_MANAGEMENT_CALL_HOME) {
        len = handshake->comSendReceive(responseBuf, bufLen, requestBuf,
            sizeof(requestBuf) - 1, handshake->callHomeHost.hostUrl,
            handshake->callHomeHost.port, NULL, NULL);
    } else {
        len = handshake->comSendReceive(responseBuf, bufLen, requestBuf,
            sizeof(requestBuf) - 1, handshake->handshakeHost.hostUrl,
            handshake->handshakeHost.port, NULL, NULL);
    }
    if (len < 0) {
        log_err("Error sending or receiving request");
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error sending or receiving request");
        return EXIT_FAILURE;
    }
    debug("Response: '%s (%d) (%d)'", &responseBuf[2], len,
        (responseBuf[0] << 8) + responseBuf[1]);

    ret = EXIT_SUCCESS;
error:
    return ret;
}

static short parseGetNetworkDataResponseHelper(
    Handshake_t* handshake, IsoMsg isoMsg, unsigned char* responseBuf)
{
    short ret = EXIT_FAILURE;

    check(c8583Check(handshake,
              unpackData(isoMsg, &responseBuf[2],
                  (responseBuf[0] << 8) + responseBuf[1])
                  == 0,
              isoMsg)
            == EXIT_SUCCESS,
        "Error Unpacking Data");

    logIsoMsg(isoMsg, stderr);

    check(c8583Check(handshake,
              getDatum(isoMsg, RESPONSE_CODE_39,
                  (unsigned char*)
                      handshake->networkManagementResponse.responseCode,
                  3)
                  == 0,
              isoMsg)
            == EXIT_SUCCESS,
        "Error Getting DE 39 - Response Code");

    check(isApprovedResponse(handshake->networkManagementResponse.responseCode),
        "Not Arroved Response");

    ret = EXIT_SUCCESS;
error:
    return ret;
}

static short parseGetKeyResponse(
    Handshake_t* handshake, unsigned char* responseBuf, Key* key)
{
    short ret = EXIT_FAILURE;
    IsoMsg isoMsg = createIso8583();
    unsigned char de53Buff[97] = { '\0' };
    size_t keySize = sizeof(key->key) - 1;

    check(parseGetNetworkDataResponseHelper(handshake, isoMsg, responseBuf)
            == EXIT_SUCCESS,
        "Parsing Error");

    check(c8583Check(handshake,
              getDatum(isoMsg, SECURITY_RELATED_CONTROL_INFORMATION_53,
                  de53Buff, sizeof(de53Buff))
                  == 0,
              isoMsg)
            == EXIT_SUCCESS,
        "Error Getting DE 53");

    rightTrim((char*)de53Buff, '0');
    memcpy(key->key, de53Buff, keySize);
    memcpy(key->kcv, &de53Buff[keySize], strlen((char*)de53Buff) - keySize);

    ret = EXIT_SUCCESS;
error:
    destroyIso8583(isoMsg);
    return ret;
}

static short parseGetNetworkDataResponse(Handshake_t* handshake,
    unsigned char* responseBuf, NetworkManagementType networkManagementType)
{
    short ret = EXIT_FAILURE;
    IsoMsg isoMsg = createIso8583();
    unsigned char de62Buff[0x1000] = { '\0' };

    check(parseGetNetworkDataResponseHelper(handshake, isoMsg, responseBuf)
            == EXIT_SUCCESS,
        "Parsing Error");

    if (networkManagementType == NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD) {
        check(c8583Check(handshake,
                  getDatum(
                      isoMsg, RESERVED_PRIVATE_62, de62Buff, sizeof(de62Buff))
                      == 0,
                  isoMsg)
                == EXIT_SUCCESS,
            "Error Getting DE 62");

        parseDE62(handshake, (char*)de62Buff, sizeof(de62Buff));
    }

    ret = EXIT_SUCCESS;
error:
    destroyIso8583(isoMsg);
    return ret;
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
        log_err("Error validating key (%s)",
            networkManagementTypeToString(networkManagementType));
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error validating key (%s)",
            networkManagementTypeToString(networkManagementType));
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}

static short getKey(Handshake_t* handshake, Key* key,
    NetworkManagementType networkManagementType)
{
    unsigned char responseBuf[0x1000] = { '\0' };
    short ret = EXIT_FAILURE;

    check(getNetworkDataHelper(responseBuf, sizeof(responseBuf) - 1, handshake,
              networkManagementType)
            == EXIT_SUCCESS,
        "Error Getting Network Data");

    check(parseGetKeyResponse(handshake, responseBuf, key) == EXIT_SUCCESS,
        "Parsing Error");

    check(validateKey(handshake, key, networkManagementType) == EXIT_SUCCESS,
        "Validation Error");

    ret = EXIT_SUCCESS;
error:
    return ret;
}

static short getNetworkData(
    Handshake_t* handshake, NetworkManagementType networkManagementType)
{
    unsigned char responseBuf[0x1000] = { '\0' };
    short ret = EXIT_FAILURE;

    check(getNetworkDataHelper(responseBuf, sizeof(responseBuf) - 1, handshake,
              networkManagementType)
            == EXIT_SUCCESS,
        "Error Getting Network Data");

    check(parseGetNetworkDataResponse(
              handshake, responseBuf, networkManagementType)
            == EXIT_SUCCESS,
        "Parsing Error");

    ret = EXIT_SUCCESS;
error:
    return ret;
}

static short getMasterKey(Handshake_t* handshake)
{
    debug("MASTER");
    return getKey(handshake, &handshake->networkManagementResponse.master,
        NETWORK_MANAGEMENT_MASTER_KEY);
}

static short getSessionKey(Handshake_t* handshake)
{
    debug("SESSION");
    return getKey(handshake, &handshake->networkManagementResponse.session,
        NETWORK_MANAGEMENT_SESSION_KEY);
}

static short getPinKey(Handshake_t* handshake)
{
    debug("PIN");
    return getKey(handshake, &handshake->networkManagementResponse.pin,
        NETWORK_MANAGEMENT_PIN_KEY);
}

static short getParameter(Handshake_t* handshake)
{
    debug("PARAMETER");
    return getNetworkData(handshake, NETWORK_MANAGEMENT_PARAMETER_DOWNLOAD);
}

static short doCallHome(Handshake_t* handshake)
{
    debug("CALL HOME");
    return getNetworkData(handshake, NETWORK_MANAGEMENT_CALL_HOME);
}

void bindNibss(Handshake_Internals* handshake_internals)
{
    handshake_internals->getMasterKey = getMasterKey;
    handshake_internals->getSessionKey = getSessionKey;
    handshake_internals->getPinKey = getPinKey;
    handshake_internals->getParameters = getParameter;
    handshake_internals->doCallHome = doCallHome;
}
