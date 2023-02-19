/**
 * File: C8583.c
 * -------------
 * Implements C8583.h's interface.
 */

#include "C8583.h"

#include "C8583.h"
#include "C8583Algorithm.h"
#include "C8583Bitmap.h"
#include "C8583Config.h"
#include "C8583Utils.h"

#include <stdlib.h>
#include <string.h>

struct C8583Struct {
    short allocated;
    unsigned char mti[5];
    unsigned char bitmap[16];
    char message[65];
    char isRequest;
    struct DataElement* dataElements;
};

static short setMti(
    IsoMsg isoMsg, const unsigned char* datum, const unsigned int datumSize)
{
    struct C8583Config config;
    getC8583Config(&config, MESSAGE_TYPE_INDICATOR_0);
    if (datumSize < config.length) {
        sprintf(isoMsg->message, "Can't set mti with len %u", datumSize);
        return -1;
    }

    memcpy(isoMsg->mti, datum, config.length);

    return 0;
}

static short getMtiFromIsoMsg(
    IsoMsg isoMsg, unsigned char* datum, const unsigned int datumSize)
{
    struct C8583Config config;
    getC8583Config(&config, MESSAGE_TYPE_INDICATOR_0);
    if (datumSize < config.length) {
        sprintf(
            isoMsg->message, "buffer of %u isn't enough for MTI", datumSize);
        return -1;
    }
    memcpy(datum, isoMsg->mti, config.length);

    return config.length;
}

static short isValidFixLenDatum(IsoMsg isoMsg, const struct C8583Config* config,
    const unsigned char* datum, const unsigned int datumSize)
{
    (void)datum;
    if (config->length == datumSize)
        return 1;
    sprintf(isoMsg->message, "F[%d], Len(expected: %u, actual: %u)",
        config->field, config->length, datumSize);
    return 0;
}

static short isValidVarLenDatum(IsoMsg isoMsg, const struct C8583Config* config,
    const unsigned char* datum, const unsigned int datumSize)
{
    (void)datum;

    if (datumSize <= config->length)
        return 1;
    sprintf(isoMsg->message, "F[%d], Len(expected: < %u, actual: %u)",
        config->field, config->length, datumSize);
    return 0;
}

static short isValidDatum(IsoMsg isoMsg, const int field,
    const unsigned char* datum, const int datumSize)
{
    struct C8583Config config;
    getC8583Config(&config, field);

    if (config.type == FIXED_LENGTH) {
        return isValidFixLenDatum(isoMsg, &config, datum, datumSize);
    } else {
        return isValidVarLenDatum(isoMsg, &config, datum, datumSize);
    }
}

static short encodeNextDataElement(const struct DataElement* node,
    unsigned char* packet, const int size, char* message)
{
    struct C8583Config config;
    struct IsoData* encodedData = NULL;
    int result = 0;

    getC8583Config(&config, node->field);
    encodedData = encodeDatum(node->datum, node->size, &config, message);

    if (encodedData == NULL) {
        return 0;
    }

    result = encodedData->size;

    if (size < result) {
        sprintf(
            message, "not enough buffer to pack F[%d] and others", node->field);
        freeIsoData(encodedData);
        return 0;
    }

    memcpy(packet, encodedData->datum, result);

    freeIsoData(encodedData);

    return result;
}

static int addMtiToPacket(
    const IsoMsg isoMsg, unsigned char* packet, const int size)
{
    struct C8583Config config;
    int len = 0;

    getC8583Config(&config, MESSAGE_TYPE_INDICATOR_0);
    len = config.length;

    if (size < len) {
        strcpy(isoMsg->message, "Not enough buffer to add MTI");
        return 0;
    }

    if (isBcdToAsc(&config)) {
        c8583BcdToAsc(packet, isoMsg->mti, len);
        len *= 2;
    } else if (isAscToBcd(&config)) {
        char mtiAsc[7] = { '\0' };
        memcpy(mtiAsc, isoMsg->mti, len);
        len /= 2;
        c8583AscToBcd(packet, len, mtiAsc);
    } else {
        memcpy(packet, isoMsg->mti, len);
    }

    return len;
}

static int addBitmapToPacket(
    const IsoMsg isoMsg, unsigned char* packet, const int size)
{
    struct C8583Config config;
    int len = isSecondaryBitmap(isoMsg->bitmap) ? 16 : 8;

    getC8583Config(&config, BITMAP_1);

    if (size < len) {
        strcpy(isoMsg->message, "Not enough buffer to pack bitmap");
        return 0;
    }

    if (config.outputEncoding == BCD_ENCODING) {
        memcpy(packet, isoMsg->bitmap, len);
    } else {
        c8583BcdToAsc(packet, isoMsg->bitmap, len);
        len *= 2;
    }

    if (!len)
        strcpy(isoMsg->message, "Unable to add bitmap to packet");

    return len;
}

static int generatePacket(const IsoMsg isoMsg, unsigned char* packet,
    const int size, const unsigned char* sessionKey, const int keySize,
    MacFunc macFunc)
{
    int result = 0;
    short status = 0;
    struct DataElement* node = isoMsg->dataElements;
    char message[65] = { '\0' };
    int macField = -1;

    status = addMtiToPacket(isoMsg, &packet[result], size);
    if (!status)
        return status;
    result += status;

    if (macFunc != NULL) {
        macField = isSecondaryBitmap(isoMsg->bitmap) ? 128 : 64;
        setFieldBit(isoMsg->bitmap, macField);
    }

    status = addBitmapToPacket(isoMsg, &packet[result], size - result);
    if (!status)
        return status;
    result += status;

    while (node != NULL) {
        status = encodeNextDataElement(
            node, &packet[result], size - result, message);
        if (!status) {
            memcpy(isoMsg->message, message, sizeof(isoMsg->message) - 1);
            return 0;
        }

        node = node->next;
        result += status;
    }

    if (macFunc != NULL) {
        unsigned char mac[65] = { 0x00 };
        int macSize = (*macFunc)(mac, sessionKey, keySize, packet, result);

        if (macSize <= 0) {
            // error generating back
            return 0;
        }

        // push it for logging purpose.
        pushElement(&isoMsg->dataElements, macField, mac, macSize);
        memcpy(&packet[result], mac, macSize);
        result += macSize;
    }

    return result;
}

short isEmptyMti(const IsoMsg isoMsg)
{
    unsigned char buffer[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    return (memcmp(buffer, isoMsg->mti, sizeof(isoMsg->mti)) == 0) ? 1 : 0;
}

short isEmptyBitmap(const IsoMsg isoMsg)
{
    unsigned char emptyBitmap[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    return (memcmp(emptyBitmap, isoMsg->bitmap, sizeof(isoMsg->bitmap)) == 0)
        ? 1
        : 0;
}

#ifdef C8583_SPY

unsigned char* getMti(const IsoMsg isoMsg) { return isoMsg->mti; }

unsigned char* getBitmap(const IsoMsg isoMsg) { return isoMsg->bitmap; }

#endif

static unsigned int getOutputLen(const struct C8583Config* config)
{
    short len = config->length;

    if (isBcdToAsc(config)) {
        len *= 2;
    } else if (isAscToBcd(config)) {
        len /= 2;
    }

    return len;
}

static int getMtiFromPacket(
    const IsoMsg isoMsg, const unsigned char* packet, const int size)
{
    struct C8583Config config;
    int len = 0;

    getC8583Config(&config, MESSAGE_TYPE_INDICATOR_0);
    len = getOutputLen(&config);

    if (size < len) {
        strcpy(isoMsg->message, "Not enough buffer, mti absent");
        return 0;
    }

    memcpy(isoMsg->mti, packet, len);

    return len;
}

static short isSecondaryBitmapAsc(const char* bitmapAsc)
{
    char twoNibbles[3] = { '\0' };
    unsigned char oneByte[16];

    strncpy(twoNibbles, bitmapAsc, 2);

    c8583AscToBcd(oneByte, 1, twoNibbles);
    return isFieldBitSet(oneByte, 1);
}

static int getBitmapFromPacket(
    const IsoMsg isoMsg, const unsigned char* packet, const int size)
{
    struct C8583Config config;
    int len = 0;

    getC8583Config(&config, BITMAP_1);
    len = config.length;

    if (config.outputEncoding == ASCII_ENCODING) {
        char ascBitmap[33];
        len = isSecondaryBitmapAsc((const char*)packet)
            ? 32
            : 16; // actual len coped

        memcpy(ascBitmap, packet, len);
        ascBitmap[len] = '\0';
        c8583AscToBcd(isoMsg->bitmap, len / 2, ascBitmap);

    } else {
        if (isBcdToAsc(&config)) {
            len *= 2;
        } else if (isAscToBcd(&config)) {
            len /= 2;
        }

        memcpy(isoMsg->bitmap, packet, len);
    }

    if (size < len) {
        strcpy(isoMsg->message, "Bitmap is absent or incomplete");
        return 0;
    }

    return len;
}

static int getNextDatumFromPacket(IsoMsg isoMsg,
    const struct C8583Config* config, const unsigned char* packet,
    const int size)
{
    int result = 0;
    struct IsoData* decodedDatum
        = decodeDatum(packet, size, config, isoMsg->message);

    if (decodedDatum == NULL) {
        return result;
    }

    result = decodedDatum->jumper;

    pushElement(&isoMsg->dataElements, config->field, decodedDatum->datum,
        decodedDatum->size);
    freeIsoData(decodedDatum);

    return result;
}

static void c8583Debug(IsoMsg isoMsg, const struct C8583Config* config,
    unsigned char* datum, const int size, FILE* stream)
{
    unsigned char* asc = NULL;
    short isBcd;

    if (config->field == BITMAP_1) {
        isBcd = 1;
    } else {
        isBcd = (isoMsg->isRequest == 'Y')
            ? config->inputEncoding == BCD_ENCODING
            : config->outputEncoding == BCD_ENCODING;
    }

    if (isBcd) {
        asc = (unsigned char*)calloc(size * 2 + 1, sizeof(char));
        c8583BcdToAsc(asc, datum, size);

    } else {
        asc = (unsigned char*)calloc(size + 1, sizeof(char));
        memcpy(asc, datum, size);
    }

    if (config->field == MESSAGE_TYPE_INDICATOR_0) {
        fprintf(stream, "MTI -> %s\n", asc);
    } else if (config->field == BITMAP_1) {
        if (isSecondaryBitmap(datum)) {
            char primaryBitmap[17] = { '\0' };
            strncpy(primaryBitmap, (char*)asc, 16);
            fprintf(stream, "Primary Bitmap -> %s\n", primaryBitmap);
            fprintf(stream, "Secondary Bitmap -> %s\n", &asc[16]);
        } else {
            fprintf(stream, "Primary Bitmap -> %s\n", asc);
        }
    } else {
        fprintf(stream, "DE[%03d] -> %s\n", config->field, asc);
    }

    free(asc);
}

DllSpec const char* getMessage(const IsoMsg isoMsg) { return isoMsg->message; }

DllSpec short packDataWithMac(const IsoMsg isoMsg, unsigned char* packet,
    const int size, const unsigned char* key, const int keySize,
    MacFunc macFunc)
{
    if (isoMsg == NULL)
        return 0;
    isoMsg->isRequest = 'Y';

    if (isEmptyBitmap(isoMsg)) {
        strcpy(isoMsg->message, "No field is set, nothing to pack");
        return 0;
    }

    if (isEmptyMti(isoMsg)) {
        strcpy(isoMsg->message, "Can't pack message without MTI");
        return 0;
    }

    return generatePacket(isoMsg, packet, size, key, keySize, macFunc);
}

DllSpec short packData(
    const IsoMsg isoMsg, unsigned char* packet, const int size)
{
    return packDataWithMac(isoMsg, packet, size, NULL, 0, NULL);
}

DllSpec void logIsoMsg(const IsoMsg isoMsg, FILE* stream)
{
    struct C8583Config config;
    struct DataElement* node = NULL;
    unsigned int len;
    char binaryLiteral[129] = { '\0' };

    if (isoMsg == NULL)
        return;

    node = isoMsg->dataElements;
    bitmapToBinLiteral(binaryLiteral, isoMsg->bitmap);

    fprintf(stream, "\n\n");

    getC8583Config(&config, MESSAGE_TYPE_INDICATOR_0);
    len = (isoMsg->isRequest == 'Y') ? config.length : getOutputLen(&config);
    c8583Debug(isoMsg, &config, isoMsg->mti, len, stream);

    getC8583Config(&config, BITMAP_1);

    if (isoMsg->isRequest == 'Y') {
        len = isSecondaryBitmap(isoMsg->bitmap) ? 16 : 8;
    } else {
        len = getOutputLen(&config);
    }

    c8583Debug(isoMsg, &config, isoMsg->bitmap, len, stream);

    while (node != NULL) {
        getC8583Config(&config, node->field);
        c8583Debug(isoMsg, &config, node->datum, node->size, stream);
        node = node->next;
    }

    fprintf(stream, "\n\n");
    fflush(stream);
}

DllSpec void dumpPacket(
    FILE* stream, const void* packet, const unsigned int size)
{
    dumpData(stream, packet, size);
}

static int getDataInBitmapFromPacket(
    IsoMsg isoMsg, const unsigned char* packet, const int size)
{
    int nextField, lastField;
    int status, result;
    struct C8583Config config;

    result = 0;
    lastField
        = isSecondaryBitmap(isoMsg->bitmap) ? SECONDARY_BITMAP : PRIMARY_BITMAP;

    for (nextField = PRIMARY_ACCOUNT_NUMBER_2; nextField < lastField;
         nextField++) {
        if (!isFieldBitSet(isoMsg->bitmap, nextField))
            continue;
        getC8583Config(&config, nextField);
        status = getNextDatumFromPacket(
            isoMsg, &config, &packet[result], size - result);
        if (!status)
            return 0;
        result += status;
    }

    return result;
}

DllSpec short unpackData(
    const IsoMsg isoMsg, const unsigned char* packet, const int size)
{
    int pos = 0;
    short status = 0;
    const unsigned char* current = packet;

    if (isoMsg == NULL)
        return 0;
    isoMsg->isRequest = 'N';
    status = getMtiFromPacket(isoMsg, &current[pos], size);

    if (!status)
        return 0;
    pos += status;

    status = getBitmapFromPacket(isoMsg, &current[pos], size - pos);
    if (!status)
        return 0;
    pos += status;

    if (isEmptyBitmap(isoMsg)) {
        strcpy(isoMsg->message, "Empty bitmap");
        return 0;
    }

    status = getDataInBitmapFromPacket(isoMsg, &current[pos], size - pos);
    if (!status)
        return 0;
    pos += status;

    return pos;
}

DllSpec const char* getC8583Version() { return "0.0.1"; }

DllSpec IsoMsg createIso8583(void)
{
    IsoMsg isoMsg = (IsoMsg)calloc(1, sizeof(struct C8583Struct));

    isoMsg->allocated = 1;
    return isoMsg;
}

DllSpec void destroyIso8583(const IsoMsg isoMsg)
{
    if (isoMsg == NULL)
        return;
    if (isoMsg->allocated == 0)
        return;

    if (isoMsg->dataElements != NULL) {
        freeDataElement(&isoMsg->dataElements);
        isoMsg->dataElements = NULL;
    }

    isoMsg->allocated = 0;
    free(isoMsg);
}

DllSpec short setDatum(const IsoMsg isoMsg, const int field,
    const unsigned char* datum, const int datumSize)
{

    if (isoMsg == NULL)
        return -1;

    if (field == MESSAGE_TYPE_INDICATOR_0) {
        if (!isEmptyMti(isoMsg)) {
            strcpy(isoMsg->message, "Can't set MTI twice");
        }

        return setMti(isoMsg, datum, datumSize);
    }

    if (!isFieldInRange(field)) {
        sprintf(isoMsg->message, "F[%d] isn't valid", field);
        return -2;
    }

    if (!isValidDatum(isoMsg, field, datum, datumSize)) {
        return -3;
    }

    if (isFieldBitSet(isoMsg->bitmap, field)) {
        sprintf(isoMsg->message, "Can't set F[%d] twice", field);
        return -4;
    }

    pushElement(&isoMsg->dataElements, field, datum, datumSize);

    setFieldBit(isoMsg->bitmap, field);

    return 0;
}

DllSpec short getDatum(const IsoMsg isoMsg, const int field,
    unsigned char* datum, const int datumSize)
{
    int ret;

    if (isoMsg == NULL)
        return 0;

    if (field == MESSAGE_TYPE_INDICATOR_0)
        return getMtiFromIsoMsg(isoMsg, datum, datumSize);

    if (!isFieldInRange(field)) {
        sprintf(isoMsg->message, "F[%d] isn't a valid DE", field);
        return 0;
    }

    ret = getElement(isoMsg->dataElements, field, datum, datumSize);

    if (ret == 0) {
        sprintf(isoMsg->message, "Can't find DE[%d]", field);
    }

    return ret;
}
