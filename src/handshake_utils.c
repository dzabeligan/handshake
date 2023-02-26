/**
 * @file handshake_utils.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implements interface for Handshake Utils
 * @version 0.1
 * @date 2023-02-24
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <stdio.h>
#include <string.h>

#include "../dbg.h"
#include "../sha256/sha256.h"

#include "../inc/handshake_utils.h"

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
