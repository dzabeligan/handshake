/**
 * File: C8583Utils.c
 * ------------------
 */

#include "C8583Utils.h"

#include <stdlib.h>
#include <string.h>

short c8583BcdToAsc(unsigned char* asc, unsigned char* bcd, const int bcdLen)
{
    int i = 0;
    short pos = 0;

    if (bcdLen <= 0)
        return -1;

    for (i = 0; i < bcdLen; i++) {
        pos += sprintf((char*)&asc[pos], "%02X", bcd[i]);
    }

    return 0;
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

unsigned char c8583AscToBcd(
    unsigned char* bcd, const short bcdLen, const char* asc)
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

    return 1;
}

void dumpData(FILE* stream, const void* packet, const unsigned int size)
{
    unsigned int i;
    unsigned int r, c;

    if (!stream || !packet)
        return;

    fprintf(stream, "\n\n");

    for (r = 0, i = 0; r < (size / 16 + (size % 16 != 0)); r++, i += 16) {
        fprintf(stream, "%04X| ", i); /* location of first byte in line */

        for (c = i; c < i + 8; c++) /* left half of hex dump */
            if (c < size)
                fprintf(stream, "%02X ", ((unsigned char const*)packet)[c]);
            else
                fprintf(stream, "   "); /* pad if short line */

        for (c = i + 8; c < i + 16; c++) /* right half of hex dump */
            if (c < size)
                fprintf(stream, "%02X ", ((unsigned char const*)packet)[c]);
            else
                fprintf(stream, "   "); /* pad if short line */

        fprintf(stream, " "); // separator of the right half and Ascii dump

        for (c = i; c < i + 16; c++) /* ASCII dump */
            if (c < size)
                if (((unsigned char const*)packet)[c] >= 32
                    && ((unsigned char const*)packet)[c] < 127)
                    fprintf(stream, "%c", ((char const*)packet)[c]);
                else
                    fprintf(stream, "."); /* put this for non-printables */
            else
                fprintf(stream, " "); /* pad if short line */

        fprintf(stream, "\n");
    }

    fprintf(stream, "\n\n");
    fflush(stream);
}
