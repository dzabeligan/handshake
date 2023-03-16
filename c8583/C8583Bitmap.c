/**
 * File: C8583Bitmap.c
 * -------------------
 */

#include "C8583Bitmap.h"

#include <stdio.h>

#define BYTE_WIDTH 8

static void charToBinLiteral(char buffer[9], char input) {
  int i;
  for (i = 0; i < 8; i++) {
    char shift_byte = 0x01 << (7 - i);
    buffer[i] = (shift_byte & input) ? '1' : '0';
  }
  buffer[i] = '\0';
}

void bitmapToBinLiteral(char* binaryLiteral, const unsigned char bitmap[16]) {
  const int size = isSecondaryBitmap(bitmap) ? 16 : 8;
  int i;
  char buffer[9];
  short pos = 0;

  for (i = 0; i < size; i++) {
    charToBinLiteral(buffer, bitmap[i]);
    pos += sprintf(&binaryLiteral[pos], "%s", buffer);
  }

  binaryLiteral[pos] = '\0';
}

static short fieldToBitIndex(const int field) {
  const int remainder = field % BYTE_WIDTH;
  return remainder ? BYTE_WIDTH - remainder : remainder;
}

static short fieldToByteIndex(const int field) {
  return (field - 1) / BYTE_WIDTH;
}

static unsigned char convertFieldToBit(const int field) { return 1 << field; }

void setFieldBit(unsigned char bitmap[16], const int field) {
  if (!field) return;

  bitmap[fieldToByteIndex(field)] |= convertFieldToBit(fieldToBitIndex(field));

  if (field > PRIMARY_BITMAP && !isFieldBitSet(bitmap, 1)) {
    bitmap[fieldToByteIndex(1)] |= convertFieldToBit(fieldToBitIndex(1));
  }
}

short isFieldBitSet(const unsigned char bitmap[16], const int field) {
  if (!field) return 0;

  return (bitmap[fieldToByteIndex(field)] >> fieldToBitIndex(field)) & 1;
}

short isSecondaryBitmap(const unsigned char bitmap[16]) {
  return isFieldBitSet(bitmap, 1);
}
