/**
 * File: C8583Config.h
 * --------------------
 * Configuration for C8583
 */

#ifndef _C8583_CONFIG_H
#define _C8583_CONFIG_H
#ifdef __cplusplus
extern "C" {
#endif

#include "FieldNames.h"

/*
 Len of track2(Z data) in asc was 38 which should be 19 in bcd, I had to use 38
 in bcd for EMP TITP spec, it might be a general requirement for iso 8583 Z data
 or I'm missing something
*/
#define EMP_Z_DATA_FIX

#define USE_BCD_LEN_FOR_ASC

struct IsoData {
    unsigned char* datum;
    unsigned int size;
    unsigned int jumper;
    char message[65];
};

enum FieldType {
    FIXED_LENGTH,
    LL_VAR,
    LLL_VAR,
    LLLL_VAR,
    LLLLL_VAR,
    LLLLLL_VAR,
};

enum FieldAttribute {
    ALPHANUMERIC,
    ALPHANUMERIC_SPECIAL,
    BINARY,
    HEX_NUMERICS, // x+n
    NUMERIC,
    NUMERIC_SPECIAL, // ns
    Z,
};

enum EncodingType {
    ASCII_ENCODING,
    BCD_ENCODING,
    BINARY_ENCODING,
};

struct C8583Config {
    enum Field field;
    enum FieldType type;
    enum FieldAttribute attribute;
    enum EncodingType inputEncoding;
    enum EncodingType outputEncoding;
    unsigned int length;
};

short isFieldInRange(const int field);
short isBcdToAsc(const struct C8583Config* config);
short isAscToBcd(const struct C8583Config* config);
void getC8583Config(struct C8583Config* config, const short field);
short getConfigSize(void);
struct IsoData* encodeDatum(const unsigned char* datum, const unsigned int size,
    const struct C8583Config* config, char* message);
struct IsoData* decodeDatum(const unsigned char* packet,
    const unsigned int size, const struct C8583Config* config, char* message);
void freeIsoData(struct IsoData* isoData);

#ifdef __cplusplus
}
#endif

#endif
