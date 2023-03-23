#ifndef UTILS_H
#define UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

#include "../ezxml/ezxml.h"
#include "../rc4/rc4.h"

short ascToBcd(unsigned char* bcd, const short bcdLen, const char* asc);
short bcdToAsc(unsigned char* asc, const int ascLen, const unsigned char* bcd,
               const int bcdLen);
void rightTrim(char* input, const char ch);
void splitStr(char* firstPart, size_t fLen, char* secondPart, size_t sLen,
              const char* data, int separator);
short isApprovedResponse(const char* responseCode);
short generateMac(unsigned char* mac, const unsigned char* key,
                  const int keySize, const unsigned char* packet,
                  const int packetSize);
int decryptTamsKey(char (*clearSessionKeys)[33],
                   char (*encryptedSessionKeys)[33], const char* tid,
                   const char* masterKey, const int keySize);
short get256Hash(char* hash, const int size, char* packet,
                 const char* sessionKey);
short checkTamsError(char* message, size_t bufLen, ezxml_t root);
short getTamsHash(char* hash, const char* data, const char* key);
char* url_encode_html5(unsigned char* s, char* enc);

#ifdef __cplusplus
}
#endif

#endif
