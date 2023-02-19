/**
 * File: C8583Bitmap.h
 * -------------------
 * @author Opeyemi Adeyemi
 */

#ifndef C8583_BITMAP_INCLUDED
#define C8583_BITMAP_INCLUDED

#define PRIMARY_BITMAP 64
#define SECONDARY_BITMAP 128
#define BITMAP_SIZE 16

void setFieldBit(unsigned char bitmap[16], const int field);
short isFieldBitSet(const unsigned char bitmap[16], const int field);
short isSecondaryBitmap(const unsigned char bitmap[16]);
void bitmapToBinLiteral(char* binaryLiteral, const unsigned char bitmap[16]);

#endif
