#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#include "../ezxml/ezxml.h"

int getState(char* data, const size_t len);
short ascToBcd(unsigned char* bcd, const short bcdLen, const char* asc);
short bcdToAsc(unsigned char* asc, const int ascLen, const unsigned char* bcd,
    const int bcdLen);
void rightTrim(char* input, const char ch);
void splitStr(char* firstPart, size_t fLen, char* secondPart, size_t sLen,
    const char* data, int separator);
short isApprovedResponse(const char* responseCode);
short generateMac(unsigned char* mac, const unsigned char* key,
    const int keySize, const unsigned char* packet, const int packetSize);
int decryptTamsKey(
    char* clearKey, char* encryptedKey, const char* tid, const char* masterKey);
short get256Hash(
    char* hash, const int size, char* packet, const char* sessionKey);
short checkTamsError(char* message, size_t bufLen, ezxml_t root);

#ifdef __cplusplus
}
#endif

#endif
