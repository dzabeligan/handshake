/**
 * @file handshake_utils.h
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Declares interface for Handshake Utils
 * @version 0.1
 * @date 2023-02-24
 *
 * @copyright Copyright (c) 2023
 *
 */
#ifndef HANDSHAKE_UTILS_H
#define HANDSHAKE_UTILS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

short ascToBcd(unsigned char* bcd, const short bcdLen, const char* asc);
short bcdToAsc(unsigned char* asc, const int ascLen, const unsigned char* bcd,
    const int bcdLen);
void rightTrim(char* input, const char ch);
void splitStr(char* firstPart, size_t fLen, char* secondPart, size_t sLen,
    const char* data, int separator);
short isApprovedResponse(const char* responseCode);
short generateMac(unsigned char* mac, const unsigned char* key,
    const int keySize, const unsigned char* packet, const int packetSize);

#ifdef __cplusplus
}
#endif

#endif
