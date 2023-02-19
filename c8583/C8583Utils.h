/**
 * File: C8583Utils.h
 * ------------------
 */

#ifndef C8583_UTILS_INCLUDED
#define C8583_UTILS_INCLUDED

#include <stdio.h>

void dumpData(FILE* stream, const void* packet, const unsigned int size);
short c8583BcdToAsc(unsigned char* asc, unsigned char* bcd, const int bcdLen);
unsigned char c8583AscToBcd(
    unsigned char* bcd, const short bcdLen, const char* asc);
#endif
