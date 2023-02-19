/**
 * File: C8583Config.c
 * -------------------
 */

// internal
#include "C8583Config.h"
#include "C8583Utils.h"

// std
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const struct C8583Config gC8583Config[] = {
    { MESSAGE_TYPE_INDICATOR_0, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 4 },
    { BITMAP_1, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        16 },
    { PRIMARY_ACCOUNT_NUMBER_2, LL_VAR, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        19 },
    { PROCESSING_CODE_3, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 6 },
    { TRANSACTION_AMOUNT_4, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { AMOUNT_SETTLEMENT_5, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { AMOUNT_CARDHOLDER_BILLING_6, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { TRANSACTION_DATE_TIME_7, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { AMOUNT_CARDHOLDER_BILLING_FEE_8, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 8 },
    { CONVERSION_RATE_SETTLEMENT_9, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 8 },
    { CONVERSION_RATE_CARDHOLDER_BILLING_10, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 8 },
    { SYSTEM_TRACE_AUDIT_NUMBER_11, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 6 },
    { LOCAL_TRANSACTION_TIME_12, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 6 },
    { LOCAL_TRANSACTION_DATE_13, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 4 },
    { EXPIRATION_DATE_14, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        4 },
    { SETTLEMENT_DATE_15, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        4 },
    { CURRENCY_CONVERSION_DATE_16, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 4 },
    { CAPTURE_DATE_17, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        4 },
    { MERCHANT_CATEGORY_CODE_18, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 4 },
    { ACQUIRING_INSTITUTION_19, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 3 },
    { PAN_EXTENDED_20, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        3 },
    { FORWARDING_INSTITUTION_21, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 3 },
    { POS_ENTRY_MODE_22, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        3 },
    { APPLICATION_PAN_SEQUENCE_NUMBER_23, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 3 },
    { NETWORK_INTERNATIONAL_IDENTIFIER_24, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 4 },
    // Function code (ISO 8583:1993), or network international identifier (NII)
    { POINT_OF_SERVICE_CONDITION_CODE_25, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 2 },
    { POINT_OF_SERVICE_CAPTURE_CODE_26, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 2 },
    { AUTHORIZATION_IDENTIFICATION_RESPONSE_LENGTH_27, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 1 },
    { AMOUNT_TRANSACTION_FEE_28, FIXED_LENGTH, HEX_NUMERICS, ASCII_ENCODING,
        ASCII_ENCODING, 9 },
    { AMOUNT_SETTLEMENT_FEE_29, FIXED_LENGTH, HEX_NUMERICS, ASCII_ENCODING,
        ASCII_ENCODING, 9 },
    { AMOUNT_TRANSACTION_PROCESSING_FEE_30, FIXED_LENGTH, HEX_NUMERICS,
        ASCII_ENCODING, ASCII_ENCODING, 9 },
    { AMOUNT_SETTLEMENT_PROCESSING_FEE_31, FIXED_LENGTH, HEX_NUMERICS,
        ASCII_ENCODING, ASCII_ENCODING, 9 },
    { ACQUIRING_INSTITUTION_IDENTIFICATION_CODE_32, LL_VAR, ALPHANUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 11 },
    { FORWARDING_INSTITUTION_IDENTIFICATION_CODE_33, LL_VAR, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 11 },
    { PRIMARY_ACCOUNT_NUMBER_EXTENDED_34, LL_VAR, NUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 28 },
    { TRACK2_DATA_35, LL_VAR, Z, ASCII_ENCODING, ASCII_ENCODING, 38 },
    { TRACK3_DATA_36, LLL_VAR, NUMERIC, ASCII_ENCODING, ASCII_ENCODING, 104 },
    { RETRIVAL_REFERENCE_NUMBER_37, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { AUTHORIZATION_IDENTIFICATION_RESPONSE_38, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 6 },
    { RESPONSE_CODE_39, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 2 },
    { SERVICE_RESTRICTION_CODE_40, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 3 },
    { CARD_ACCEPTOR_TERMINAL_IDENTIFICATION_41, FIXED_LENGTH,
        ALPHANUMERIC_SPECIAL, ASCII_ENCODING, ASCII_ENCODING, 8 },
    { CARD_ACCEPTOR_IDENTIFICATION_CODE_42, FIXED_LENGTH, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 15 },
    { CARD_ACCEPTOR_NAME_OR_LOCATION_43, FIXED_LENGTH, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 40 },
    //(1-23 street address, 24-36 city, 37-38 state, 39-40 country)
    { ADDITIONAL_RESPONSE_DATA_44, LL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 25 },
    { TRACK1_DATA_45, LL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 76 },
    { ADDITIONAL_DATA_ISO_46, LLL_VAR, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { ADDITIONAL_DATA_NATIONAL_47, LLL_VAR, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { ADDITIONAL_DATA_PRIVATE_48, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { CURRENCY_CODE_TRANSACTION_49, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 3 },
    { CURRENCY_CODE_SETTLEMENT_50, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 3 },
    { CURRENCY_CODE_CARDHOLDER_BILLING_51, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 3 },
    { PERSONAL_IDENTIFICATION_NUMBER_DATA_52, FIXED_LENGTH, BINARY,
        ASCII_ENCODING, ASCII_ENCODING, 16 },
    { SECURITY_RELATED_CONTROL_INFORMATION_53, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 96 },
    { ADDITIONAL_AMOUNTS_54, LLL_VAR, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 120 },
    { ICC_DATA_55, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_ISO_56, LLL_VAR, NUMERIC, ASCII_ENCODING, ASCII_ENCODING, 4 },
    { RESERVED_NATIONAL_57, LL_VAR, BINARY, ASCII_ENCODING, ASCII_ENCODING,
        999 },
    { RESERVED_NATIONAL_58, LLL_VAR, NUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 11 },
    { RESERVED_NATIONAL_59, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 255 },
    { RESERVED_NATIONAL_60, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_PRIVATE_61, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_PRIVATE_62, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_PRIVATE_63, LLLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 9999 },
    { MESSAGE_AUTHENTICATION_CODE_64, FIXED_LENGTH, ALPHANUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 64 },
    { EXTENDED_BITMAP_INDICATOR_65, FIXED_LENGTH, BINARY, ASCII_ENCODING,
        ASCII_ENCODING, 1 },
    { SETTLEMENT_CODE_66, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        1 },
    { EXTENDED_PAYMENT_CODE_67, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 2 },
    { RECEIVING_INSTITUTION_COUNTRY_CODE_68, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 3 },
    { SETTLEMENT_INSTITUTION_COUNTRY_CODE_69, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 3 },
    { NETWORK_MANAGEMENT_INFORMATION_CODE_70, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 3 },
    { MESSAGE_NUMBER_71, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        4 },
    { LAST_MESSAGE_NUMBER_72, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 4 },
    { ACTION_DATE_73, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        6 },
    { NUMBER_OF_CREDITS_74, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { CREDITS_REVERSAL_NUMBER_75, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { NUMBER_OF_DEBITS_76, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { DEBITS_REVERSAL_NUMBER_77, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { TRANSFER_NUMBER_78, FIXED_LENGTH, NUMERIC, ASCII_ENCODING, ASCII_ENCODING,
        10 },
    { TRANSFER_REVERSAL_NUMBER_79, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { NUMBER_OF_INQUIRIES_80, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { NUMBER_OF_AUTHORIZATIONS_81, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 10 },
    { CREDITS_PROCESSING_FEE_AMOUNT_82, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { CREDIT_TRANSACTION_FEE_AMOUNT_83, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { DEBITS_PROCESSING_FEE_AMOUNT_84, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { DEBITS_TRANSACTION_FEE_AMOUNT_85, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 12 },
    { TOTAL_AMOUNT_OF_CREDITS_86, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 16 },
    { CREDITS_REVERSAL_AMOUNT_87, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 16 },
    { TOTAL_AMOUNT_OF_DEBITS_88, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 16 },
    { DEBIT_REVESAL_AMOUNT_89, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 16 },
    { ORIGINAL_DATA_ELEMENTS_90, FIXED_LENGTH, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 42 },
    { FILE_UPDATE_CODE_91, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 1 },
    { FILE_SECURITY_CODE_92, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 2 },
    { RESPONSE_INDICATOR_93, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 5 },
    { SERVICE_INDICATOR_94, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 7 },
    { REPLACEMENT_AMOUNTS_95, FIXED_LENGTH, ALPHANUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 42 },
    { MESSAGE_SECURITY_CODE_96, FIXED_LENGTH, BINARY, BINARY_ENCODING,
        ASCII_ENCODING, 64 },
    { NET_SETTLEMENT_AMOUNT_97, FIXED_LENGTH, HEX_NUMERICS, ASCII_ENCODING,
        ASCII_ENCODING, 17 },
    { PAYEE_98, FIXED_LENGTH, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 25 },
    { SETTLEMENT_INSTITUTION_IDENTIFICATION_CODE_99, FIXED_LENGTH, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 11 },
    { RECEIVING_INSTITUTION_IDENTIFICATION_CODE_100, LL_VAR, NUMERIC,
        ASCII_ENCODING, ASCII_ENCODING, 11 },
    { FILE_NAME_101, FIXED_LENGTH, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 17 },
    { ACCOUNT_IDENTIFICATION1_102, LL_VAR, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 28 },
    { ACCOUNT_IDENTIFICATION2_103, LL_VAR, NUMERIC, ASCII_ENCODING,
        ASCII_ENCODING, 28 },
    { TRANSACTION_DESCRIPTION_104, FIXED_LENGTH, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 100 },
    { RESERVED_FOR_ISO_USE_105, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_FOR_ISO_USE_106, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_FOR_ISO_USE_107, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_FOR_ISO_USE_108, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_FOR_ISO_USE_109, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_FOR_ISO_USE_110, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_FOR_ISO_USE_111, LLL_VAR, ALPHANUMERIC_SPECIAL, ASCII_ENCODING,
        ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_112, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_113, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_114, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_115, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_116, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_117, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_118, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_119, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_120, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_121, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_122, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_123, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_124, LLLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 9999 },
    { RESERVED_FOR_NATIONAL_USE_125, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_126, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { RESERVED_FOR_NATIONAL_USE_127, LLL_VAR, ALPHANUMERIC_SPECIAL,
        ASCII_ENCODING, ASCII_ENCODING, 999 },
    { MESSAGE_AUTHENTICATION_CODE_128, FIXED_LENGTH, ALPHANUMERIC,
        BINARY_ENCODING, ASCII_ENCODING, 64 },
};

static short needToAppendF(const struct C8583Config* config)
{
    return (config->field == PRIMARY_ACCOUNT_NUMBER_2
               || config->field == TRACK2_DATA_35
               || config->field == TRACK1_DATA_45
               || config->field == TRACK3_DATA_36)
        ? 1
        : 0;
}

static short needToPrepend0(const struct C8583Config* config)
{
    return ((!needToAppendF(config)) && config->attribute == NUMERIC) ? 1 : 0;
}

static short equalEncoding(const struct C8583Config* config)
{
    return (config->inputEncoding == config->outputEncoding) ? 1 : 0;
}

static short isFixedLen(const struct C8583Config* config)
{
    return (config->type == FIXED_LENGTH) ? 1 : 0;
}

static struct IsoData* bcdToAscEncode(
    const unsigned char* datum, const unsigned int size)
{
    struct IsoData* encodedData = NULL;
    encodedData = (struct IsoData*)malloc(1 * sizeof(struct IsoData));

    encodedData->size = size * 2 + 1;
    // the extra one is only needed for bcdToAsc
    encodedData->datum
        = (unsigned char*)malloc(sizeof(char) * encodedData->size);
    c8583BcdToAsc(encodedData->datum, (unsigned char*)datum, size);
    encodedData->size -= 1;

    return encodedData;
}

static struct IsoData* ascToBcdEncode(const unsigned char* datum,
    const unsigned int size, const struct C8583Config* config)
{
    struct IsoData* encodedData = NULL;
    short isOddLen = size % 2;

    encodedData = (struct IsoData*)malloc(1 * sizeof(struct IsoData));
    encodedData->size = isOddLen ? (size + 1) / 2 : size / 2;
    encodedData->datum
        = (unsigned char*)malloc(sizeof(char) * encodedData->size);

    if (isOddLen) {
        int len = size + 1;

        char* buffer = (char*)calloc(len, sizeof(char));

        if (needToPrepend0(config)) {
            buffer[0] = '0';
            memcpy(&buffer[1], datum, size);
            c8583AscToBcd(encodedData->datum, encodedData->size, buffer);
        } else if (needToAppendF(config)) {
            memcpy(buffer, datum, size);
            buffer[size] = 'F';
            c8583AscToBcd(encodedData->datum, encodedData->size, buffer);
        } else {
            c8583AscToBcd(encodedData->datum, encodedData->size, (char*)datum);
        }

        free(buffer);
    } else {
        c8583AscToBcd(encodedData->datum, encodedData->size, (char*)datum);
    }

    return encodedData;
}

static struct IsoData* equalInputAndOutPutEncode(
    const unsigned char* datum, const unsigned int size)
{
    struct IsoData* encodedData = NULL;
    encodedData = (struct IsoData*)malloc(1 * sizeof(struct IsoData));

    encodedData->size = size;
    encodedData->datum = (unsigned char*)malloc(sizeof(char) * size);
    memcpy(encodedData->datum, datum, size);

    return encodedData;
}

static struct IsoData* encodeFixedLenPart(const unsigned char* datum,
    const unsigned int size, const struct C8583Config* config, char* message)
{

    if (isAscToBcd(config)) {
        return ascToBcdEncode(datum, size, config);
    } else if (isBcdToAsc(config)) {
        return bcdToAscEncode(datum, size);
    } else if (equalEncoding(config)) {
        return equalInputAndOutPutEncode(datum, size);
    } else {
        strcpy(message, "Unknown encoding type");
        return NULL;
    }
}

static short outputIsBcd(const struct C8583Config* config)
{
    return (config->outputEncoding == BCD_ENCODING) ? 1 : 0;
}

static short outputIsAsc(const struct C8583Config* config)
{
    return (config->outputEncoding == ASCII_ENCODING) ? 1 : 0;
}

#if 1
static short lenToStr(unsigned char* ascLen, const int length,
    const enum FieldType fieldType, const short isBcd)
{
    switch (fieldType) {
    case LL_VAR:
        return sprintf((char*)ascLen, "%02d", length);

    case LLL_VAR:
        return sprintf((char*)ascLen, isBcd ? "%04d" : "%03d", length);

    case LLLL_VAR:
        return sprintf((char*)ascLen, "%04d", length);

    case LLLLL_VAR:
        return sprintf((char*)ascLen, isBcd ? "%06d" : "%05d", length);

    case LLLLLL_VAR:
        return sprintf((char*)ascLen, "%06d", length);

    default:
        return 0;
    }
}

static short isBinary(const struct C8583Config* config)
{
    return (config->attribute == BINARY);
}

static short getBinaryVarLen(
    unsigned char* varLen, const int fieldLen, const struct C8583Config* config)
{
    unsigned char lenStr[9] = { '\0' };
    short width = lenToStr(lenStr, fieldLen, config->type, 1);
    int size = width / 2;
    c8583AscToBcd(varLen, size, (const char*)lenStr);

    return size;
}

static short getBcdVarLen(
    unsigned char* varLen, const int fieldLen, const struct C8583Config* config)
{
    unsigned char lenStr[9] = { '\0' };
    short width = lenToStr(lenStr, fieldLen, config->type, 1);
    int size = width / 2;

    c8583AscToBcd(varLen, size, (const char*)lenStr);

    return size;
}

static short getAscVarLen(
    unsigned char* varLen, const int fieldLen, const struct C8583Config* config)
{
    short width = lenToStr(varLen, fieldLen, config->type, 0);
    return width;
}

static short getDatumVarLen(
    unsigned char* varLen, const int fieldLen, const struct C8583Config* config)
{
    if (outputIsBcd(config)) {
        if (isBinary(config)) {
            return getBinaryVarLen(varLen, fieldLen, config);
        } else {
            return getBcdVarLen(varLen, fieldLen * 2, config);
        }
    } else if (config->inputEncoding == ASCII_ENCODING
        && config->outputEncoding == ASCII_ENCODING) {
        return getAscVarLen(varLen, fieldLen, config);
    }
#ifdef USE_BCD_LEN_FOR_ASC
    else if (isBcdToAsc(config)) {
        return getBcdVarLen(varLen, fieldLen, config);
    } else {
        return getBcdVarLen(varLen, fieldLen, config);
    }
#else
    return getAscVarLen(varLen, fieldLen, config);
#endif
}
#endif

static struct IsoData* encodeDatumWithVarLen(const unsigned char* datum,
    const unsigned int size, const struct C8583Config* config)
{
    int width = 0;
    unsigned char varLen[12] = { '\0' };
    struct IsoData* varDatum
        = (struct IsoData*)calloc(1, sizeof(struct IsoData));

    width = getDatumVarLen(varLen, size, config);

    varDatum->size = width + size;
    varDatum->datum = (unsigned char*)calloc(varDatum->size, sizeof(char));
    memcpy(varDatum->datum, varLen, width);
    memcpy(&varDatum->datum[width], datum, size);

    return varDatum;
}

short isFieldInRange(const int field)
{
    return (field >= PRIMARY_ACCOUNT_NUMBER_2 && field < FIELD_END) ? 1 : 0;
}

short getConfigSize(void)
{
    return sizeof(gC8583Config) / sizeof(struct C8583Config);
}

void getC8583Config(struct C8583Config* config, const short field)
{
    memcpy(config, &gC8583Config[field], sizeof(struct C8583Config));
}

struct IsoData* encodeDatum(const unsigned char* datum, const unsigned int size,
    const struct C8583Config* config, char* message)
{
    struct IsoData* fixedDatum = NULL;
    struct IsoData* varDatum = NULL;

    if (isFixedLen(config) && size != config->length) {
        sprintf(message, "F[%d], Len(expected: %u, actual: %u)", config->field,
            config->length, size);
        return NULL;
    }

    fixedDatum = encodeFixedLenPart(datum, size, config, message);
    if (fixedDatum == NULL)
        return NULL;

    if (isFixedLen(config))
        return fixedDatum;
    varDatum
        = encodeDatumWithVarLen(fixedDatum->datum, fixedDatum->size, config);

    freeIsoData(fixedDatum);

    return varDatum;
}

static short isEnoughBuffer(
    char* message, const int field, unsigned int size, unsigned int remaining)
{
    if (remaining < size) {
        sprintf(message, "Can't decode F[%d], Incomplete packet", field);
        return 0;
    }

    return 1;
}

static struct IsoData* decodeFixedLenDatum(const unsigned char* packet,
    const unsigned int size, const struct C8583Config* config, char* message)
{
    struct IsoData* data = NULL;

    data = (struct IsoData*)malloc(sizeof(struct IsoData));

    if (config->inputEncoding == ASCII_ENCODING
        && config->outputEncoding == ASCII_ENCODING) {
        data->size = config->length;

        if (!isEnoughBuffer(message, config->field, data->size, size)) {
            free(data);
            return NULL;
        }

        data->datum = (unsigned char*)malloc(
            (data->size + 1) * sizeof(char)); //+1 for '\0'
        memcpy(data->datum, packet, data->size);
        data->datum[data->size] = 0;
    } else if (isAscToBcd(config)) {
        data->size = (config->length + 1)
            / 2; //+1 needed when len of input encoding is odd.

        if (!isEnoughBuffer(message, config->field, data->size, size)) {
            free(data);
            return NULL;
        }

        data->datum = (unsigned char*)malloc(data->size * sizeof(char));
        memcpy(data->datum, packet, data->size);
    } else if (isBcdToAsc(config)) {
        data->size = config->length * 2;

        if (!isEnoughBuffer(message, config->field, data->size, size)) {
            free(data);
            return NULL;
        }

        data->datum = (unsigned char*)malloc(
            (data->size + 1) * sizeof(char)); //+1 for '\0'
        memcpy(data->datum, packet, data->size);
        data->datum[data->size] = 0;
    } else if (config->inputEncoding == BCD_ENCODING
        && config->outputEncoding == BCD_ENCODING) {
        data->size = config->length;

        if (!isEnoughBuffer(message, config->field, data->size, size)) {
            free(data);
            return NULL;
        }

        data->datum
            = (unsigned char*)malloc(data->size * sizeof(char)); //+1 for '\0'
        memcpy(data->datum, packet, data->size);
    }

    data->jumper = data->size;

    (void)message;

    return data;
}

static short getFieldVarWidth(const struct C8583Config* config)
{
    short isBcd = outputIsBcd(config);

    switch (config->type) {
    case LL_VAR:
        return isBcd ? 1 : 2;

    case LLL_VAR:
        return isBcd ? 2 : 3;

    case LLLL_VAR:
        return isBcd ? 2 : 4;

    case LLLLL_VAR:
        return isBcd ? 3 : 5;

    case LLLLLL_VAR:
        return isBcd ? 3 : 6;

    default:
        return 0;
    }
}

static short bcdLenToInt(const unsigned char* bcdLen, const int lenSize)
{
    unsigned char buffer[21] = { '\0' };
    unsigned char bcd[21];

    memcpy(bcd, bcdLen, lenSize);

    c8583BcdToAsc(buffer, bcd, lenSize);

    return atoi((char*)buffer);
}

static short getVarDatumLen(const unsigned char* packet, const short width,
    const struct C8583Config* config)
{

    if (config->attribute == BINARY) {
        return bcdLenToInt(packet, width);
    } else if (outputIsBcd(config)) {
        return bcdLenToInt(packet, width) / 2;
    } else {
        char buff[10] = { 0 };

        memcpy(buff, packet, width);
        return atoi(buff);
    }
}

short isAscToBcd(const struct C8583Config* config)
{
    return (config->inputEncoding == ASCII_ENCODING
               && config->outputEncoding == BCD_ENCODING)
        ? 1
        : 0;
}

short isBcdToAsc(const struct C8583Config* config)
{
    return (config->inputEncoding == BCD_ENCODING
               && config->outputEncoding == ASCII_ENCODING)
        ? 1
        : 0;
}

static struct IsoData* decodeVarLenDatum(const unsigned char* packet,
    const unsigned int size, const struct C8583Config* config, char* message)
{
    struct IsoData* data = NULL;
    unsigned int width = 0;
    int len = 0;

    width = getFieldVarWidth(config);

    if (width > size) {
        sprintf(message, "Not enough buffer, stopping F[%d]", config->field);
        return NULL;
    }

    len = getVarDatumLen(packet, width, config);

    if (len < 0) {
        sprintf(message, "Can't get len of F[%d]", config->field);
        return NULL;
    }

    data = (struct IsoData*)malloc(sizeof(struct IsoData));

    data->size = len;

    if (outputIsAsc(config)) {
        data->datum = (unsigned char*)malloc(
            (data->size + 1) * sizeof(char)); //+1 for '\0'
        data->datum[data->size] = 0;
    } else {
        data->datum = (unsigned char*)malloc(data->size * sizeof(char));
    }

    memcpy(data->datum, &packet[width], data->size);

    data->jumper = width + data->size;

    return data;
}

struct IsoData* decodeDatum(const unsigned char* packet,
    const unsigned int size, const struct C8583Config* config, char* message)
{
    return (config->type == FIXED_LENGTH)
        ? decodeFixedLenDatum(packet, size, config, message)
        : decodeVarLenDatum(packet, size, config, message);
}

void freeIsoData(struct IsoData* isoData)
{
    if (isoData->datum)
        free(isoData->datum);
    if (isoData)
        free(isoData);
}
