#include <ctype.h>
#include <string.h>
#include <time.h>

#include "../dbg.h"
#include "../rc4/rc4.h"
#include "../sha256/sha256.h"

#include "utils.h"

int getState(char* state, const size_t size)
{
    const char* str
        = "{\"ptad\": \"ITEX\",\"serial\": \"346228245\",\"bl\": 70,\"btemp\": "
          "30,\"ctime\": \"%s\",\"cs\": \"Charging\",\"ps\": "
          "\"PrinterAvailable\",\"tid\": \"2033GP24\",\"coms\": "
          "\"GSM/LTE\",\"sim\": \"\",\"simID\": "
          "\"621301234567890123456789\",\"imsi\": \"621301234567890\",\"ss\" : "
          "100,\"cloc\": "
          "\"{cid:\"0123\",lac:\"1234\",mcc:\"62130\",mnc:\"30\",ss:100dbm}\","
          "\"tmn\": \"LaptopPort\",\"tmanu\": \"Apple\",\"hb\": "
          "\"true\",\"lTxnAt\": \"%s\",\"sv\": \"0.0.1\",\"pads\": \"\"}";
    time_t now = time(NULL);
    struct tm now_t = *localtime(&now);
    char dateTimeBuff[64] = { '\0' };
    char lastTrans[16] = { '\0' };

    strftime(
        dateTimeBuff, sizeof(dateTimeBuff), "%a %d/%m/%Y %H:%M:%S", &now_t);
    strftime(lastTrans, sizeof(lastTrans), "%Y%m%d%H%M%S", &now_t);

    return snprintf(state, size, str, dateTimeBuff, lastTrans);
}

static unsigned char atoh(const char c)
{
    if (c >= '0' && c <= '9')
        return (c - '0');
    if (c >= 'A' && c <= 'F')
        return (c - 'A' + 10);
    if (c >= 'a' && c <= 'f')
        return (c - 'a' + 10);

    return 0;
}

void rightTrim(char* input, const char ch)
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
void splitStr(char* firstPart, size_t fLen, char* secondPart, size_t sLen,
    const char* data, int separator)
{
    const char* separatorIndex = strchr(data, separator);
    size_t len = 0;

    if (separatorIndex == NULL) {
        log_err("Error Splitting String");
        return;
    }

    len = separatorIndex - data;
    strncpy(firstPart, data, len > fLen ? fLen : len);
    strncpy(secondPart, &separatorIndex[1], sLen);
}

short ascToBcd(unsigned char* bcd, const short bcdLen, const char* asc)
{
    int ascLen, i, j;

    if (bcdLen == 0) {
        ascLen = strlen(asc);
    } else {
        ascLen = (bcdLen)*2;
        memset(bcd, 0x00, bcdLen);
    }

    for (i = 0, j = 0; j < ascLen; i++, j += 2) {
        bcd[i] = (atoh(asc[2 * i]) << 4) | atoh(asc[2 * i + 1]);
    }

    return i;
}

short bcdToAsc(unsigned char* asc, const int ascLen, const unsigned char* bcd,
    const int bcdLen)
{
    int i = 0;
    short pos = 0;

    if (bcdLen <= 0 || bcdLen * 2 > ascLen) {
        log_err("Error Converting to ASCII");
        return -1;
    }

    for (i = 0; i < bcdLen; i++) {
        pos += sprintf((char*)&asc[pos], "%02X", bcd[i]);
    }

    asc[pos] = '\0';

    return pos;
}

short isApprovedResponse(const char* responseCode)
{
    return strncmp(responseCode, "00", strlen(responseCode)) == 0;
}

short generateMac(unsigned char* mac, const unsigned char* key,
    const int keySize, const unsigned char* packet, const int packetSize)
{
    sha256_context Context;
    unsigned char keyBin[16];
    unsigned char digest[32];
    int i = 0;
    short pos = 0;
    (void)keySize;

    sha256_starts(&Context);

    ascToBcd(keyBin, sizeof(keyBin), (char*)key);

    sha256_update(&Context, keyBin, sizeof(keyBin));
    sha256_update(&Context, (unsigned char*)packet, packetSize);
    sha256_finish(&Context, digest);

    for (i = 0; i < 32; i++) {
        pos += sprintf((char*)&mac[pos], "%02X", digest[i]);
    }

    return pos;
}

static void strToLower(
    char* convertBuffer, const char* buffer, const int length)
{
    int index = 0;

    for (index = 0; index < length; index++) {
        convertBuffer[index]
            = isupper(buffer[index]) ? tolower(buffer[index]) : buffer[index];
    }
}

short get256Hash(
    char* hash, const int size, char* packet, const char* sessionKey)
{
    char buffer[65] = { '\0' };
    sha256_context Context;
    unsigned char keyBin[16];
    unsigned char digest[32];
    memset(hash, 0x00, size);

    sha256_starts(&Context);

    ascToBcd(keyBin, sizeof(keyBin), sessionKey);

    sha256_update(&Context, keyBin, sizeof(keyBin));
    sha256_update(&Context, (unsigned char*)packet, strlen(packet));
    sha256_finish(&Context, digest);

    memset(buffer, 0x00, sizeof(buffer));
    bcdToAsc((unsigned char*)buffer, sizeof(buffer), digest, sizeof(digest));

    memset(hash, 0x00, size);
    strToLower(hash, buffer, strlen(buffer));

    return 0;
}

short pad(char* inOutString, char symbol, short paddedLength, short padRight)
{
    char buffer[512] = { '\0' };
    char inString[512] = { '\0' };
    int len = strlen(inOutString);

    if (len >= paddedLength)
        return 0;

    sprintf(inString, "%s", inOutString);

    memset(buffer, symbol, paddedLength - len);
    memset(inOutString, '\0', strlen(inOutString));

    if (padRight) {
        sprintf(inOutString, "%s%s", inString, buffer);
    } else {
        sprintf(inOutString, "%s%s", buffer, inString);
    }

    return 0;
}

int hex2bin(const char* pcInBuffer, char* pcOutBuffer, int iLen)
{
    char* p;
    int iBytes = 0;
    const char* hextable = "0123456789ABCDEF";
    int nibble = 0;
    int nibble_val = 0;

    while (iBytes < iLen) {
        int c = *pcInBuffer++;
        if (c == 0)
            break;

        c = toupper(c);

        p = strchr((char*)hextable, c);
        if (p) {
            if (nibble & 1) {
                iBytes++;
                *pcOutBuffer = (nibble_val << 4 | (p - hextable));
                pcOutBuffer++;
            } else {
                nibble_val = (p - hextable);
            }
            nibble++;
        } else {
            nibble = 0;
        }
    }

    return iBytes;
}

static int bin2hex(unsigned char* pcInBuffer, char* pcOutBuffer, int iLen)
{

    int iCount;
    char* pcBuffer;
    unsigned char* pcTemp;

    memset(pcOutBuffer, 0, iLen);
    pcTemp = pcInBuffer;
    pcBuffer = pcOutBuffer;
    for (iCount = 0; iCount < iLen; iCount++) {
        unsigned char ucCh = *pcTemp;
        pcBuffer += sprintf(pcBuffer, "%02x", (int)ucCh);
        pcTemp++;
    } // while

    return 0;
}

int decryptTamsKey(
    char* clearKey, char* encryptedKey, const char* tid, const char* masterKey)
{
    unsigned char acKey[33];
    unsigned char keyBin[17];

    rc4_state state;
    char paddedTid[17] = { '\0' };

    memset(keyBin, 0, sizeof(keyBin));

    ascToBcd(keyBin, 16, masterKey);

    memcpy(&acKey[0], keyBin, 16);

    strncpy(paddedTid, tid, 8);

    pad(paddedTid, '0', 16, 0);
    sprintf((char*)&acKey[16], "%s", paddedTid);

    rc4_init(&state, acKey, 32);

    memset(keyBin, 0, sizeof(keyBin));

    hex2bin(encryptedKey, (char*)keyBin, 16);

    rc4_crypt(&state, keyBin, 16);

    bin2hex(keyBin, clearKey, 16);

    return 0;
}

/**
 * @brief Check for TAMS error
 *
 * @param message error message buffer
 * @param bufLen buffer length
 * @param root ezxml object
 * @return short 0 if no error is found, 1 otherwise
 */
short checkTamsError(char* message, size_t bufLen, ezxml_t root)
{
    ezxml_t msgTag, errorTag;

    errorTag = ezxml_child(root, "error");

    if (errorTag) {
        msgTag = ezxml_child(errorTag, "errmsg");
    } else {
        msgTag = ezxml_child(root, "errmsg");
    }

    if (msgTag) {
        log_err("%s", msgTag->txt);
        snprintf(message, bufLen, "%s", msgTag->txt);
        return 1;
    }

    return 0;
}
