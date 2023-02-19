/**
 * File: C8583.h
 * -------------
 * Defines a new interface for Iso 8583 packer and unpacker.
 */

#ifndef C8583_INCLUDED
#define C8583_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _VRXEVO
#ifdef VDE_ENTRY_EXPORT
#define DllSpec __declspec(dllexport)
#endif
#ifdef VDE_ENTRY_IMPORT
#define DllSpec __declspec(dllimport)
#endif
#endif
#ifndef DllSpec
#define DllSpec
#endif

#define C8583_SPY

#include <stdio.h>

/**
 * New Type: IsoMsg
 * ----------------
 * Defines a First class ADT type for C8583Struct
 * @author Opeyemi Adeyemi.
 */

typedef struct C8583Struct* IsoMsg;

/**
 * Function Pointer: MacFunc
 * Usage: See unpackDataWithMac
 * ----------------------------
 * Function pointer for calculating MAC of the msg.
 * @return mac The MAC of the message.
 * @param macSize Size of the MAC
 * @param packet Packet or data for generating the mac
 * @param packetSize Size of packet.
 * @author Opeyemi Adeyemi Sunday.
 */

typedef short (*MacFunc)(unsigned char* mac, const unsigned char* key,
    const int keySize, const unsigned char* packet, const int packetSize);

/**
 * Function: createIso8583
 * Usage: IsoMsg isoMsg = createIso8583();
 * ---------------------------------------
 * Initializes a new IsoMsg type
 * @return isoMsg Initilized IsoMsg data type
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec IsoMsg createIso8583(void);

/**
 * Function: destroyIso8583
 * Usage: destroyIso8583(isoMsg);
 * ------------------------------
 * Destroy isoMsg datastructure data type
 * @param isoMsg IsoMsg message created by createIso8583.
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec void destroyIso8583(const IsoMsg isoMsg);

/**
 * Function: setDatum
 * Usage: short result = setDatum(isoMsg, field, datum, datumSize);
 * ----------------------------------------------------------------
 * @param isoMsg IsoMsg type, see createIso8583
 * @param field Iso 8583 field to set.
 * @param datum value of field to set
 * @param datumSize The size of datum to set.
 * @return result Returns 0 if successful, othewise returns other numbers.
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec short setDatum(const IsoMsg isoMsg, const int field,
    const unsigned char* datum, const int datumSize);

/**
 * Function: getDatum
 * Usage: short result = getDatum(isoMsg, field, datum, datumSize);
 * ----------------------------------------------------------------
 * @param isoMsg IsoMsg type, see createIso8583
 * @param field Iso 8583 field to get.
 * @return datum value of field
 * @param datumSize the size of datum buffer
 * @return result Returns 0 if failed, othewise returns positive number
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec short getDatum(const IsoMsg isoMsg, const int field,
    unsigned char* datum, const int datumSize);

/**
 * Function: packData
 * Usage: short result = packData(isoMsg, packet, size);
 * ----------------------------------------------------------------
 * @param isoMsg IsoMsg type, see createIso8583
 * @return packet packed Iso8583 message
 * @param size The size of packet buffer
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec short packData(
    const IsoMsg isoMsg, unsigned char* packet, const int size);

/**
 * Function: unpackData
 * Usage: short result = unpackData(isoMsg, packet, size);
 * ----------------------------------------------------------------
 * @return isoMsg IsoMsg type, see createIso8583
 * @return packet Iso8583 packet to unpack
 * @param size Size of packet to unpack.
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec short unpackData(
    const IsoMsg isoMsg, const unsigned char* packet, const int size);

/**
 * Function: unpackDataWithMac
 * Usage: short result = unpackData(isoMsg, packet, size, macFunc);
 * ----------------------------------------------------------------
 * For calculating the mac of the message at runtime, equivalent to packData if
 * macFunc is NULL.
 * @return isoMsg IsoMsg type, see createIso8583
 * @return packet Iso8583 packet to unpack
 * @param size Size of packet to unpack.
 * @param macFunc Function pointer to a functioin for for calculating the MAC(DE
 * 64 or 128) of the message.
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec short packDataWithMac(const IsoMsg isoMsg, unsigned char* packet,
    const int size, const unsigned char* key, const int keySize,
    MacFunc macFunc);

/**
 * Function: logIsoMsg
 * Usage: logIsoMsg(isoMsg, stream)
 * --------------------------------
 * Send isoMsg to stream in pretty format.
 * @param isoMsg, see createIso8583 for more details.
 * @param stream, stdin, or stdout, or stderr or any other FILE stream.
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec void logIsoMsg(const IsoMsg isoMsg, FILE* stream);

/**
 * Function: dumpPacket
 * Usage: dumpPacket(stream, packet, size);
 * ----------------------------------------
 * Dump packet to stream in network hex data format.
 * @param stream stdin, stdout, or stderr.
 * @param packet Iso8583 packet to dump.
 * @param size the size of the packet.
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec void dumpPacket(
    FILE* stream, const void* packet, const unsigned int size);

/**
 * Function: getMessage
 * Usage: char * error = getMessage(isoMsg);
 * -----------------------------------------
 * @param isoMsg, see createIso8583
 * @return error, error generated during IsoMsg's operation.
 * @author Opeyemi Adeyemi Sunday.
 */

DllSpec const char* getMessage(const IsoMsg isoMsg);

DllSpec const char* getC8583Version();

short isEmptyMti(const IsoMsg isoMsg);

#ifdef C8583_SPY
short isEmptyBitmap(const IsoMsg isoMsg);
unsigned char* getMti(const IsoMsg isoMsg);
unsigned char* getBitmap(const IsoMsg isoMsg);
#endif

#ifdef __cplusplus
}
#endif
#endif
