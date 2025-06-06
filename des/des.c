/*
 *  FIPS-46-3 compliant Triple-DES implementation
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: GPL-2.0
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  DES, on which TDES is based, was originally designed by Horst Feistel
 *  at IBM in 1974, and was adopted as a standard by NIST (formerly NBS).
 *
 *  http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf
 */
// #include "stdafx.h"

#define DES_C

#if defined(DES_C)

#include "des.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !defined(DES_ALT)

/* Implementation that should never be optimized out by the compiler */
static void zeroize(void* v, size_t n) {
  volatile unsigned char* p = (unsigned char*)v;
  while (n--) *p++ = 0;
}

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n, b, i)                                          \
  {                                                                     \
    (n) = ((uint32_t)(b)[(i)] << 24) | ((uint32_t)(b)[(i) + 1] << 16) | \
          ((uint32_t)(b)[(i) + 2] << 8) | ((uint32_t)(b)[(i) + 3]);     \
  }
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n, b, i)                 \
  {                                            \
    (b)[(i)] = (unsigned char)((n) >> 24);     \
    (b)[(i) + 1] = (unsigned char)((n) >> 16); \
    (b)[(i) + 2] = (unsigned char)((n) >> 8);  \
    (b)[(i) + 3] = (unsigned char)((n));       \
  }
#endif

/*
 * Expanded DES S-boxes
 */
static const uint32_t SB1[64] = {
    0x01010400, 0x00000000, 0x00010000, 0x01010404, 0x01010004, 0x00010404,
    0x00000004, 0x00010000, 0x00000400, 0x01010400, 0x01010404, 0x00000400,
    0x01000404, 0x01010004, 0x01000000, 0x00000004, 0x00000404, 0x01000400,
    0x01000400, 0x00010400, 0x00010400, 0x01010000, 0x01010000, 0x01000404,
    0x00010004, 0x01000004, 0x01000004, 0x00010004, 0x00000000, 0x00000404,
    0x00010404, 0x01000000, 0x00010000, 0x01010404, 0x00000004, 0x01010000,
    0x01010400, 0x01000000, 0x01000000, 0x00000400, 0x01010004, 0x00010000,
    0x00010400, 0x01000004, 0x00000400, 0x00000004, 0x01000404, 0x00010404,
    0x01010404, 0x00010004, 0x01010000, 0x01000404, 0x01000004, 0x00000404,
    0x00010404, 0x01010400, 0x00000404, 0x01000400, 0x01000400, 0x00000000,
    0x00010004, 0x00010400, 0x00000000, 0x01010004};

static const uint32_t SB2[64] = {
    0x80108020, 0x80008000, 0x00008000, 0x00108020, 0x00100000, 0x00000020,
    0x80100020, 0x80008020, 0x80000020, 0x80108020, 0x80108000, 0x80000000,
    0x80008000, 0x00100000, 0x00000020, 0x80100020, 0x00108000, 0x00100020,
    0x80008020, 0x00000000, 0x80000000, 0x00008000, 0x00108020, 0x80100000,
    0x00100020, 0x80000020, 0x00000000, 0x00108000, 0x00008020, 0x80108000,
    0x80100000, 0x00008020, 0x00000000, 0x00108020, 0x80100020, 0x00100000,
    0x80008020, 0x80100000, 0x80108000, 0x00008000, 0x80100000, 0x80008000,
    0x00000020, 0x80108020, 0x00108020, 0x00000020, 0x00008000, 0x80000000,
    0x00008020, 0x80108000, 0x00100000, 0x80000020, 0x00100020, 0x80008020,
    0x80000020, 0x00100020, 0x00108000, 0x00000000, 0x80008000, 0x00008020,
    0x80000000, 0x80100020, 0x80108020, 0x00108000};

static const uint32_t SB3[64] = {
    0x00000208, 0x08020200, 0x00000000, 0x08020008, 0x08000200, 0x00000000,
    0x00020208, 0x08000200, 0x00020008, 0x08000008, 0x08000008, 0x00020000,
    0x08020208, 0x00020008, 0x08020000, 0x00000208, 0x08000000, 0x00000008,
    0x08020200, 0x00000200, 0x00020200, 0x08020000, 0x08020008, 0x00020208,
    0x08000208, 0x00020200, 0x00020000, 0x08000208, 0x00000008, 0x08020208,
    0x00000200, 0x08000000, 0x08020200, 0x08000000, 0x00020008, 0x00000208,
    0x00020000, 0x08020200, 0x08000200, 0x00000000, 0x00000200, 0x00020008,
    0x08020208, 0x08000200, 0x08000008, 0x00000200, 0x00000000, 0x08020008,
    0x08000208, 0x00020000, 0x08000000, 0x08020208, 0x00000008, 0x00020208,
    0x00020200, 0x08000008, 0x08020000, 0x08000208, 0x00000208, 0x08020000,
    0x00020208, 0x00000008, 0x08020008, 0x00020200};

static const uint32_t SB4[64] = {
    0x00802001, 0x00002081, 0x00002081, 0x00000080, 0x00802080, 0x00800081,
    0x00800001, 0x00002001, 0x00000000, 0x00802000, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00800080, 0x00800001, 0x00000001, 0x00002000,
    0x00800000, 0x00802001, 0x00000080, 0x00800000, 0x00002001, 0x00002080,
    0x00800081, 0x00000001, 0x00002080, 0x00800080, 0x00002000, 0x00802080,
    0x00802081, 0x00000081, 0x00800080, 0x00800001, 0x00802000, 0x00802081,
    0x00000081, 0x00000000, 0x00000000, 0x00802000, 0x00002080, 0x00800080,
    0x00800081, 0x00000001, 0x00802001, 0x00002081, 0x00002081, 0x00000080,
    0x00802081, 0x00000081, 0x00000001, 0x00002000, 0x00800001, 0x00002001,
    0x00802080, 0x00800081, 0x00002001, 0x00002080, 0x00800000, 0x00802001,
    0x00000080, 0x00800000, 0x00002000, 0x00802080};

static const uint32_t SB5[64] = {
    0x00000100, 0x02080100, 0x02080000, 0x42000100, 0x00080000, 0x00000100,
    0x40000000, 0x02080000, 0x40080100, 0x00080000, 0x02000100, 0x40080100,
    0x42000100, 0x42080000, 0x00080100, 0x40000000, 0x02000000, 0x40080000,
    0x40080000, 0x00000000, 0x40000100, 0x42080100, 0x42080100, 0x02000100,
    0x42080000, 0x40000100, 0x00000000, 0x42000000, 0x02080100, 0x02000000,
    0x42000000, 0x00080100, 0x00080000, 0x42000100, 0x00000100, 0x02000000,
    0x40000000, 0x02080000, 0x42000100, 0x40080100, 0x02000100, 0x40000000,
    0x42080000, 0x02080100, 0x40080100, 0x00000100, 0x02000000, 0x42080000,
    0x42080100, 0x00080100, 0x42000000, 0x42080100, 0x02080000, 0x00000000,
    0x40080000, 0x42000000, 0x00080100, 0x02000100, 0x40000100, 0x00080000,
    0x00000000, 0x40080000, 0x02080100, 0x40000100};

static const uint32_t SB6[64] = {
    0x20000010, 0x20400000, 0x00004000, 0x20404010, 0x20400000, 0x00000010,
    0x20404010, 0x00400000, 0x20004000, 0x00404010, 0x00400000, 0x20000010,
    0x00400010, 0x20004000, 0x20000000, 0x00004010, 0x00000000, 0x00400010,
    0x20004010, 0x00004000, 0x00404000, 0x20004010, 0x00000010, 0x20400010,
    0x20400010, 0x00000000, 0x00404010, 0x20404000, 0x00004010, 0x00404000,
    0x20404000, 0x20000000, 0x20004000, 0x00000010, 0x20400010, 0x00404000,
    0x20404010, 0x00400000, 0x00004010, 0x20000010, 0x00400000, 0x20004000,
    0x20000000, 0x00004010, 0x20000010, 0x20404010, 0x00404000, 0x20400000,
    0x00404010, 0x20404000, 0x00000000, 0x20400010, 0x00000010, 0x00004000,
    0x20400000, 0x00404010, 0x00004000, 0x00400010, 0x20004010, 0x00000000,
    0x20404000, 0x20000000, 0x00400010, 0x20004010};

static const uint32_t SB7[64] = {
    0x00200000, 0x04200002, 0x04000802, 0x00000000, 0x00000800, 0x04000802,
    0x00200802, 0x04200800, 0x04200802, 0x00200000, 0x00000000, 0x04000002,
    0x00000002, 0x04000000, 0x04200002, 0x00000802, 0x04000800, 0x00200802,
    0x00200002, 0x04000800, 0x04000002, 0x04200000, 0x04200800, 0x00200002,
    0x04200000, 0x00000800, 0x00000802, 0x04200802, 0x00200800, 0x00000002,
    0x04000000, 0x00200800, 0x04000000, 0x00200800, 0x00200000, 0x04000802,
    0x04000802, 0x04200002, 0x04200002, 0x00000002, 0x00200002, 0x04000000,
    0x04000800, 0x00200000, 0x04200800, 0x00000802, 0x00200802, 0x04200800,
    0x00000802, 0x04000002, 0x04200802, 0x04200000, 0x00200800, 0x00000000,
    0x00000002, 0x04200802, 0x00000000, 0x00200802, 0x04200000, 0x00000800,
    0x04000002, 0x04000800, 0x00000800, 0x00200002};

static const uint32_t SB8[64] = {
    0x10001040, 0x00001000, 0x00040000, 0x10041040, 0x10000000, 0x10001040,
    0x00000040, 0x10000000, 0x00040040, 0x10040000, 0x10041040, 0x00041000,
    0x10041000, 0x00041040, 0x00001000, 0x00000040, 0x10040000, 0x10000040,
    0x10001000, 0x00001040, 0x00041000, 0x00040040, 0x10040040, 0x10041000,
    0x00001040, 0x00000000, 0x00000000, 0x10040040, 0x10000040, 0x10001000,
    0x00041040, 0x00040000, 0x00041040, 0x00040000, 0x10041000, 0x00001000,
    0x00000040, 0x10040040, 0x00001000, 0x00041040, 0x10001000, 0x00000040,
    0x10000040, 0x10040000, 0x10040040, 0x10000000, 0x00040000, 0x10001040,
    0x00000000, 0x10041040, 0x00040040, 0x10000040, 0x10040000, 0x10001000,
    0x10001040, 0x00000000, 0x10041040, 0x00041000, 0x00041000, 0x00001040,
    0x00001040, 0x00040040, 0x10000000, 0x10041000};

/*
 * PC1: left and right halves bit-swap
 */
static const uint32_t LHs[16] = {
    0x00000000, 0x00000001, 0x00000100, 0x00000101, 0x00010000, 0x00010001,
    0x00010100, 0x00010101, 0x01000000, 0x01000001, 0x01000100, 0x01000101,
    0x01010000, 0x01010001, 0x01010100, 0x01010101};

static const uint32_t RHs[16] = {
    0x00000000, 0x01000000, 0x00010000, 0x01010000, 0x00000100, 0x01000100,
    0x00010100, 0x01010100, 0x00000001, 0x01000001, 0x00010001, 0x01010001,
    0x00000101, 0x01000101, 0x00010101, 0x01010101,
};

/*
 * Initial Permutation macro
 */
#define DES_IP(X, Y)                         \
  {                                          \
    T = ((X >> 4) ^ Y) & 0x0F0F0F0F;         \
    Y ^= T;                                  \
    X ^= (T << 4);                           \
    T = ((X >> 16) ^ Y) & 0x0000FFFF;        \
    Y ^= T;                                  \
    X ^= (T << 16);                          \
    T = ((Y >> 2) ^ X) & 0x33333333;         \
    X ^= T;                                  \
    Y ^= (T << 2);                           \
    T = ((Y >> 8) ^ X) & 0x00FF00FF;         \
    X ^= T;                                  \
    Y ^= (T << 8);                           \
    Y = ((Y << 1) | (Y >> 31)) & 0xFFFFFFFF; \
    T = (X ^ Y) & 0xAAAAAAAA;                \
    Y ^= T;                                  \
    X ^= T;                                  \
    X = ((X << 1) | (X >> 31)) & 0xFFFFFFFF; \
  }

/*
 * Final Permutation macro
 */
#define DES_FP(X, Y)                         \
  {                                          \
    X = ((X << 31) | (X >> 1)) & 0xFFFFFFFF; \
    T = (X ^ Y) & 0xAAAAAAAA;                \
    X ^= T;                                  \
    Y ^= T;                                  \
    Y = ((Y << 31) | (Y >> 1)) & 0xFFFFFFFF; \
    T = ((Y >> 8) ^ X) & 0x00FF00FF;         \
    X ^= T;                                  \
    Y ^= (T << 8);                           \
    T = ((Y >> 2) ^ X) & 0x33333333;         \
    X ^= T;                                  \
    Y ^= (T << 2);                           \
    T = ((X >> 16) ^ Y) & 0x0000FFFF;        \
    Y ^= T;                                  \
    X ^= (T << 16);                          \
    T = ((X >> 4) ^ Y) & 0x0F0F0F0F;         \
    Y ^= T;                                  \
    X ^= (T << 4);                           \
  }

/*
 * DES round macro
 */
#define DES_ROUND(X, Y)                                                 \
  {                                                                     \
    T = *SK++ ^ X;                                                      \
    Y ^= SB8[(T)&0x3F] ^ SB6[(T >> 8) & 0x3F] ^ SB4[(T >> 16) & 0x3F] ^ \
         SB2[(T >> 24) & 0x3F];                                         \
                                                                        \
    T = *SK++ ^ ((X << 28) | (X >> 4));                                 \
    Y ^= SB7[(T)&0x3F] ^ SB5[(T >> 8) & 0x3F] ^ SB3[(T >> 16) & 0x3F] ^ \
         SB1[(T >> 24) & 0x3F];                                         \
  }

#define SWAP(a, b)  \
  {                 \
    uint32_t t = a; \
    a = b;          \
    b = t;          \
    t = 0;          \
  }

void des_init(des_context* ctx) { memset(ctx, 0, sizeof(des_context)); }

void des_free(des_context* ctx) {
  if (ctx == NULL) return;

  zeroize(ctx, sizeof(des_context));
}

void des3_init(des3_context* ctx) { memset(ctx, 0, sizeof(des3_context)); }

void des3_free(des3_context* ctx) {
  if (ctx == NULL) return;

  zeroize(ctx, sizeof(des3_context));
}

static const unsigned char odd_parity_table[128] = {
    1,   2,   4,   7,   8,   11,  13,  14,  16,  19,  21,  22,  25,  26,  28,
    31,  32,  35,  37,  38,  41,  42,  44,  47,  49,  50,  52,  55,  56,  59,
    61,  62,  64,  67,  69,  70,  73,  74,  76,  79,  81,  82,  84,  87,  88,
    91,  93,  94,  97,  98,  100, 103, 104, 107, 109, 110, 112, 115, 117, 118,
    121, 122, 124, 127, 128, 131, 133, 134, 137, 138, 140, 143, 145, 146, 148,
    151, 152, 155, 157, 158, 161, 162, 164, 167, 168, 171, 173, 174, 176, 179,
    181, 182, 185, 186, 188, 191, 193, 194, 196, 199, 200, 203, 205, 206, 208,
    211, 213, 214, 217, 218, 220, 223, 224, 227, 229, 230, 233, 234, 236, 239,
    241, 242, 244, 247, 248, 251, 253, 254};

void des_key_set_parity(unsigned char key[DES_KEY_SIZE]) {
  int i;

  for (i = 0; i < DES_KEY_SIZE; i++) key[i] = odd_parity_table[key[i] / 2];
}

/*
 * Check the given key's parity, returns 1 on failure, 0 on SUCCESS
 */
int des_key_check_key_parity(const unsigned char key[DES_KEY_SIZE]) {
  int i;

  for (i = 0; i < DES_KEY_SIZE; i++)
    if (key[i] != odd_parity_table[key[i] / 2]) return (1);

  return (0);
}

/*
 * Table of weak and semi-weak keys
 *
 * Source: http://en.wikipedia.org/wiki/Weak_key
 *
 * Weak:
 * Alternating ones + zeros (0x0101010101010101)
 * Alternating 'F' + 'E' (0xFEFEFEFEFEFEFEFE)
 * '0xE0E0E0E0F1F1F1F1'
 * '0x1F1F1F1F0E0E0E0E'
 *
 * Semi-weak:
 * 0x011F011F010E010E and 0x1F011F010E010E01
 * 0x01E001E001F101F1 and 0xE001E001F101F101
 * 0x01FE01FE01FE01FE and 0xFE01FE01FE01FE01
 * 0x1FE01FE00EF10EF1 and 0xE01FE01FF10EF10E
 * 0x1FFE1FFE0EFE0EFE and 0xFE1FFE1FFE0EFE0E
 * 0xE0FEE0FEF1FEF1FE and 0xFEE0FEE0FEF1FEF1
 *
 */

#define WEAK_KEY_COUNT 16

static const unsigned char weak_key_table[WEAK_KEY_COUNT][DES_KEY_SIZE] = {
    {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01},
    {0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
    {0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E},
    {0xE0, 0xE0, 0xE0, 0xE0, 0xF1, 0xF1, 0xF1, 0xF1},

    {0x01, 0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E},
    {0x1F, 0x01, 0x1F, 0x01, 0x0E, 0x01, 0x0E, 0x01},
    {0x01, 0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1},
    {0xE0, 0x01, 0xE0, 0x01, 0xF1, 0x01, 0xF1, 0x01},
    {0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE},
    {0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01, 0xFE, 0x01},
    {0x1F, 0xE0, 0x1F, 0xE0, 0x0E, 0xF1, 0x0E, 0xF1},
    {0xE0, 0x1F, 0xE0, 0x1F, 0xF1, 0x0E, 0xF1, 0x0E},
    {0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E, 0xFE},
    {0xFE, 0x1F, 0xFE, 0x1F, 0xFE, 0x0E, 0xFE, 0x0E},
    {0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE},
    {0xFE, 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1}};

int des_key_check_weak(const unsigned char key[DES_KEY_SIZE]) {
  int i;

  for (i = 0; i < WEAK_KEY_COUNT; i++)
    if (memcmp(weak_key_table[i], key, DES_KEY_SIZE) == 0) return (1);

  return (0);
}

void des_setkey(uint32_t SK[32], const unsigned char key[DES_KEY_SIZE]) {
  int i;
  uint32_t X, Y, T;

  GET_UINT32_BE(X, key, 0);
  GET_UINT32_BE(Y, key, 4);

  /*
   * Permuted Choice 1
   */
  T = ((Y >> 4) ^ X) & 0x0F0F0F0F;
  X ^= T;
  Y ^= (T << 4);
  T = ((Y) ^ X) & 0x10101010;
  X ^= T;
  Y ^= (T);

  X = (LHs[(X)&0xF] << 3) | (LHs[(X >> 8) & 0xF] << 2) |
      (LHs[(X >> 16) & 0xF] << 1) | (LHs[(X >> 24) & 0xF]) |
      (LHs[(X >> 5) & 0xF] << 7) | (LHs[(X >> 13) & 0xF] << 6) |
      (LHs[(X >> 21) & 0xF] << 5) | (LHs[(X >> 29) & 0xF] << 4);

  Y = (RHs[(Y >> 1) & 0xF] << 3) | (RHs[(Y >> 9) & 0xF] << 2) |
      (RHs[(Y >> 17) & 0xF] << 1) | (RHs[(Y >> 25) & 0xF]) |
      (RHs[(Y >> 4) & 0xF] << 7) | (RHs[(Y >> 12) & 0xF] << 6) |
      (RHs[(Y >> 20) & 0xF] << 5) | (RHs[(Y >> 28) & 0xF] << 4);

  X &= 0x0FFFFFFF;
  Y &= 0x0FFFFFFF;

  /*
   * calculate subkeys
   */
  for (i = 0; i < 16; i++) {
    if (i < 2 || i == 8 || i == 15) {
      X = ((X << 1) | (X >> 27)) & 0x0FFFFFFF;
      Y = ((Y << 1) | (Y >> 27)) & 0x0FFFFFFF;
    } else {
      X = ((X << 2) | (X >> 26)) & 0x0FFFFFFF;
      Y = ((Y << 2) | (Y >> 26)) & 0x0FFFFFFF;
    }

    *SK++ = ((X << 4) & 0x24000000) | ((X << 28) & 0x10000000) |
            ((X << 14) & 0x08000000) | ((X << 18) & 0x02080000) |
            ((X << 6) & 0x01000000) | ((X << 9) & 0x00200000) |
            ((X >> 1) & 0x00100000) | ((X << 10) & 0x00040000) |
            ((X << 2) & 0x00020000) | ((X >> 10) & 0x00010000) |
            ((Y >> 13) & 0x00002000) | ((Y >> 4) & 0x00001000) |
            ((Y << 6) & 0x00000800) | ((Y >> 1) & 0x00000400) |
            ((Y >> 14) & 0x00000200) | ((Y)&0x00000100) |
            ((Y >> 5) & 0x00000020) | ((Y >> 10) & 0x00000010) |
            ((Y >> 3) & 0x00000008) | ((Y >> 18) & 0x00000004) |
            ((Y >> 26) & 0x00000002) | ((Y >> 24) & 0x00000001);

    *SK++ = ((X << 15) & 0x20000000) | ((X << 17) & 0x10000000) |
            ((X << 10) & 0x08000000) | ((X << 22) & 0x04000000) |
            ((X >> 2) & 0x02000000) | ((X << 1) & 0x01000000) |
            ((X << 16) & 0x00200000) | ((X << 11) & 0x00100000) |
            ((X << 3) & 0x00080000) | ((X >> 6) & 0x00040000) |
            ((X << 15) & 0x00020000) | ((X >> 4) & 0x00010000) |
            ((Y >> 2) & 0x00002000) | ((Y << 8) & 0x00001000) |
            ((Y >> 14) & 0x00000808) | ((Y >> 9) & 0x00000400) |
            ((Y)&0x00000200) | ((Y << 7) & 0x00000100) |
            ((Y >> 7) & 0x00000020) | ((Y >> 3) & 0x00000011) |
            ((Y << 2) & 0x00000004) | ((Y >> 21) & 0x00000002);
  }
}

/*
 * DES key schedule (56-bit, encryption)
 */
int des_setkey_enc(des_context* ctx, const unsigned char key[DES_KEY_SIZE]) {
  des_setkey(ctx->sk, key);

  return (0);
}

/*
 * DES key schedule (56-bit, decryption)
 */
int des_setkey_dec(des_context* ctx, const unsigned char key[DES_KEY_SIZE]) {
  int i;

  des_setkey(ctx->sk, key);

  for (i = 0; i < 16; i += 2) {
    SWAP(ctx->sk[i], ctx->sk[30 - i]);
    SWAP(ctx->sk[i + 1], ctx->sk[31 - i]);
  }

  return (0);
}

static void des3_set2key(uint32_t esk[96], uint32_t dsk[96],
                         const unsigned char key[DES_KEY_SIZE * 2]) {
  int i;

  des_setkey(esk, key);
  des_setkey(dsk + 32, key + 8);

  for (i = 0; i < 32; i += 2) {
    dsk[i] = esk[30 - i];
    dsk[i + 1] = esk[31 - i];

    esk[i + 32] = dsk[62 - i];
    esk[i + 33] = dsk[63 - i];

    esk[i + 64] = esk[i];
    esk[i + 65] = esk[i + 1];

    dsk[i + 64] = dsk[i];
    dsk[i + 65] = dsk[i + 1];
  }
}

/*
 * Triple-DES key schedule (112-bit, encryption)
 */
int des3_set2key_enc(des3_context* ctx,
                     const unsigned char key[DES_KEY_SIZE * 2]) {
  uint32_t sk[96];

  des3_set2key(ctx->sk, sk, key);
  zeroize(sk, sizeof(sk));

  return (0);
}

/*
 * Triple-DES key schedule (112-bit, decryption)
 */
int des3_set2key_dec(des3_context* ctx,
                     const unsigned char key[DES_KEY_SIZE * 2]) {
  uint32_t sk[96];

  des3_set2key(sk, ctx->sk, key);
  zeroize(sk, sizeof(sk));

  return (0);
}

static void des3_set3key(uint32_t esk[96], uint32_t dsk[96],
                         const unsigned char key[24]) {
  int i;

  des_setkey(esk, key);
  des_setkey(dsk + 32, key + 8);
  des_setkey(esk + 64, key + 16);

  for (i = 0; i < 32; i += 2) {
    dsk[i] = esk[94 - i];
    dsk[i + 1] = esk[95 - i];

    esk[i + 32] = dsk[62 - i];
    esk[i + 33] = dsk[63 - i];

    dsk[i + 64] = esk[30 - i];
    dsk[i + 65] = esk[31 - i];
  }
}

/*
 * Triple-DES key schedule (168-bit, encryption)
 */
int des3_set3key_enc(des3_context* ctx,
                     const unsigned char key[DES_KEY_SIZE * 3]) {
  uint32_t sk[96];

  des3_set3key(ctx->sk, sk, key);
  zeroize(sk, sizeof(sk));

  return (0);
}

/*
 * Triple-DES key schedule (168-bit, decryption)
 */
int des3_set3key_dec(des3_context* ctx,
                     const unsigned char key[DES_KEY_SIZE * 3]) {
  uint32_t sk[96];

  des3_set3key(sk, ctx->sk, key);
  zeroize(sk, sizeof(sk));

  return (0);
}

/*
 * DES-ECB block encryption/decryption
 */

int des_crypt_ecb(des_context* ctx, const unsigned char input[8],
                  unsigned char output[8]) {
  int i;
  uint32_t X, Y, T, *SK;

  SK = ctx->sk;

  GET_UINT32_BE(X, input, 0);
  GET_UINT32_BE(Y, input, 4);

  DES_IP(X, Y);

  for (i = 0; i < 8; i++) {
    DES_ROUND(Y, X);
    DES_ROUND(X, Y);
  }

  DES_FP(Y, X);

  PUT_UINT32_BE(Y, output, 0);
  PUT_UINT32_BE(X, output, 4);

  return (0);
}

/*
 * DES-CBC buffer encryption/decryption
 */
int des_crypt_cbc(des_context* ctx, int mode, size_t length,
                  unsigned char iv[8], const unsigned char* input,
                  unsigned char* output) {
  int i;
  unsigned char temp[8];

  if (length % 8) return (ERR_DES_INVALID_INPUT_LENGTH);

  if (mode == DES_ENCRYPT) {
    while (length > 0) {
      for (i = 0; i < 8; i++) output[i] = (unsigned char)(input[i] ^ iv[i]);

      des_crypt_ecb(ctx, output, output);
      memcpy(iv, output, 8);

      input += 8;
      output += 8;
      length -= 8;
    }
  } else /* DES_DECRYPT */
  {
    while (length > 0) {
      memcpy(temp, input, 8);
      des_crypt_ecb(ctx, input, output);

      for (i = 0; i < 8; i++) output[i] = (unsigned char)(output[i] ^ iv[i]);

      memcpy(iv, temp, 8);

      input += 8;
      output += 8;
      length -= 8;
    }
  }

  return (0);
}

/*
 * 3DES-ECB block encryption/decryption
 */

int des3_crypt_ecb(des3_context* ctx, const unsigned char input[8],
                   unsigned char output[8]) {
  int i;
  uint32_t X, Y, T, *SK;

  SK = ctx->sk;

  GET_UINT32_BE(X, input, 0);
  GET_UINT32_BE(Y, input, 4);

  DES_IP(X, Y);

  for (i = 0; i < 8; i++) {
    DES_ROUND(Y, X);
    DES_ROUND(X, Y);
  }

  for (i = 0; i < 8; i++) {
    DES_ROUND(X, Y);
    DES_ROUND(Y, X);
  }

  for (i = 0; i < 8; i++) {
    DES_ROUND(Y, X);
    DES_ROUND(X, Y);
  }

  DES_FP(Y, X);

  PUT_UINT32_BE(Y, output, 0);
  PUT_UINT32_BE(X, output, 4);

  return (0);
}

/*
 * 3DES-CBC buffer encryption/decryption
 */
int des3_crypt_cbc(des3_context* ctx, int mode, size_t length,
                   unsigned char iv[8], const unsigned char* input,
                   unsigned char* output) {
  int i;
  unsigned char temp[8];

  if (length % 8) return (ERR_DES_INVALID_INPUT_LENGTH);

  if (mode == DES_ENCRYPT) {
    while (length > 0) {
      for (i = 0; i < 8; i++) output[i] = (unsigned char)(input[i] ^ iv[i]);

      des3_crypt_ecb(ctx, output, output);
      memcpy(iv, output, 8);

      input += 8;
      output += 8;
      length -= 8;
    }
  } else /* DES_DECRYPT */
  {
    while (length > 0) {
      memcpy(temp, input, 8);
      des3_crypt_ecb(ctx, input, output);

      for (i = 0; i < 8; i++) output[i] = (unsigned char)(output[i] ^ iv[i]);

      memcpy(iv, temp, 8);

      input += 8;
      output += 8;
      length -= 8;
    }
  }

  return (0);
}

#endif /* !DES_ALT */

#endif /* DES_C */

/*
 * DES-ECB buffer encryption API
 */
unsigned int des_ecb_encrypt(unsigned char* pout, unsigned char* pdata,
                             unsigned int nlen, unsigned char* pkey) {
  unsigned char* tmp;
  unsigned int len, i;
  unsigned char ch = '\0';
  des_context ctx;

  des_setkey_enc(&ctx, pkey);

  len = (nlen / 8 + (nlen % 8 ? 1 : 0)) * 8;

  // ch = 8 - nlen % 8;
  for (i = 0; i < nlen; i += 8) {
    des_crypt_ecb(&ctx, (pdata + i), (pout + i));
  }
  if (len > nlen) {
    tmp = (unsigned char*)malloc(len);
    i -= 8;
    memcpy(tmp, pdata + i, nlen - i);
    memset(tmp + nlen % 8, ch, (8 - nlen % 8) % 8);
    des_crypt_ecb(&ctx, tmp, (pout + i));
    free(tmp);
  }

  des_free(&ctx);
  return len;
}
/*
 * DES-ECB buffer decryption API
 */
unsigned int des_ecb_decrypt(unsigned char* pout, unsigned char* pdata,
                             unsigned int nlen, unsigned char* pkey) {
  unsigned int i;
  des_context ctx;

  if (nlen % 8) return 1;

  des_setkey_dec(&ctx, pkey);

  for (i = 0; i < nlen; i += 8) {
    des_crypt_ecb(&ctx, (pdata + i), (pout + i));
  }
  des_free(&ctx);
  return 0;
}

/*
 * DES-CBC buffer encryption API
 */
unsigned int des_cbc_encrypt(unsigned char* pout, unsigned char* pdata,
                             unsigned int nlen, unsigned char* pkey,
                             unsigned char* piv) {
  des_context ctx;
  unsigned char iv[8] = {0};
  unsigned char* pivb;

  if (piv == NULL)
    pivb = iv;
  else
    pivb = piv;

  des_setkey_enc(&ctx, pkey);

  des_crypt_cbc(&ctx, 1, nlen, pivb, pdata, (pout));

  des_free(&ctx);

  return nlen;
}
/*
 * DES-CBC buffer decryption API
 */
unsigned int des_cbc_decrypt(unsigned char* pout, unsigned char* pdata,
                             unsigned int nlen, unsigned char* pkey,
                             unsigned char* piv) {
  des_context ctx;
  unsigned char iv[8] = {0};
  unsigned char* pivb;

  if (piv == NULL)
    pivb = iv;
  else
    pivb = piv;

  des_setkey_dec(&ctx, pkey);

  des_crypt_cbc(&ctx, 0, nlen, pivb, pdata, (pout));

  des_free(&ctx);

  return 0;
}
/*
 * 3DES-ECB buffer encryption API
 */
unsigned int des3_ecb_encrypt(unsigned char* pout, unsigned char* pdata,
                              unsigned int nlen, unsigned char* pkey,
                              unsigned int klen) {
  unsigned char* tmp;
  unsigned int len, i;
  unsigned char ch = '\0';
  des3_context ctx3;

  //<<<<<<< HEAD
  if (klen == DES3_KEY2_SIZE) {         // 16字节
    des3_set2key_enc(&ctx3, pkey);      // 根据长度设置key
  } else if (klen == DES3_KEY3_SIZE) {  // 24字节
    //=======
    if (klen == DES3_KEY2_SIZE) {         // 16�ֽ�
      des3_set2key_enc(&ctx3, pkey);      // ���ݳ�������key
    } else if (klen == DES3_KEY3_SIZE) {  // 24�ֽ�
      //>>>>>>> add all file
      des3_set3key_enc(&ctx3, pkey);
    }
  }

  len = (nlen / 8 + (nlen % 8 ? 1 : 0)) * 8;

  //<<<<<<< HEAD
  // ch = 8 - nlen % 8;//可以设置补齐内容，常用0或0xFF
  //=======
  // ch = 8 - nlen % 8;//�������ò������ݣ�����0��0xFF
  //>>>>>>> add all file
  for (i = 0; i < nlen; i += 8) {
    des3_crypt_ecb(&ctx3, (pdata + i), (pout + i));
  }
  //<<<<<<< HEAD
  if (len > nlen)  // 不足8字节补齐
    //=======
    if (len > nlen)  // ����8�ֽڲ���
    //>>>>>>> add all file
    {
      tmp = (unsigned char*)malloc(len);
      i -= 8;
      memcpy(tmp, pdata + i, nlen - i);
      memset(tmp + nlen % 8, ch, (8 - nlen % 8) % 8);
      des3_crypt_ecb(&ctx3, tmp, (pout + i));
      free(tmp);
    }

  des3_free(&ctx3);
  return len;
}
/*
 * 3DES-ECB buffer decryption API
 */
unsigned int des3_ecb_decrypt(unsigned char* pout, unsigned char* pdata,
                              unsigned int nlen, unsigned char* pkey,
                              unsigned int klen) {
  unsigned int i;
  des3_context ctx3;

  if (nlen % 8) return 1;

  if (klen == DES3_KEY2_SIZE)
    des3_set2key_dec(&ctx3, pkey);
  else if (klen == DES3_KEY3_SIZE)
    des3_set3key_dec(&ctx3, pkey);

  for (i = 0; i < nlen; i += 8) {
    des3_crypt_ecb(&ctx3, (pdata + i), (pout + i));
  }
  des3_free(&ctx3);
  return 0;
}
/*
 * 3DES-CBC buffer encryption API
 */
unsigned int des3_cbc_encrypt(unsigned char* pout, unsigned char* pdata,
                              unsigned int nlen, unsigned char* pkey,
                              unsigned int klen, unsigned char* piv) {
  des3_context ctx;
  unsigned char iv[8] = {0};
  unsigned char* pivb;

  if (piv == NULL)
    pivb = iv;
  else
    pivb = piv;

  if (klen == DES3_KEY2_SIZE)
    des3_set2key_enc(&ctx, pkey);
  else if (klen == DES3_KEY3_SIZE)
    des3_set3key_enc(&ctx, pkey);

  des3_crypt_cbc(&ctx, 1, nlen, pivb, pdata, (pout));

  des3_free(&ctx);

  return nlen;
}
/*
 * 3DES-CBC buffer decryption API
 */
unsigned int des3_cbc_decrypt(unsigned char* pout, unsigned char* pdata,
                              unsigned int nlen, unsigned char* pkey,
                              unsigned int klen, unsigned char* piv) {
  des3_context ctx;
  unsigned char iv[8] = {0};
  unsigned char* pivb;

  if (piv == NULL)
    pivb = iv;
  else
    pivb = piv;

  if (klen == DES3_KEY2_SIZE)
    des3_set2key_dec(&ctx, pkey);
  else if (klen == DES3_KEY3_SIZE)
    des3_set3key_dec(&ctx, pkey);

  des3_crypt_cbc(&ctx, 0, nlen, pivb, pdata, (pout));

  des3_free(&ctx);

  return 0;
}
// test
#if 0

short bcdToAsc(char * asc, unsigned char * bcd, const int size)
{
    int i;
    short pos = 0;

    for (i = 0; i < size; i++) {
        pos += sprintf(&asc[pos], "%02X", bcd[i]);
    }

    return pos;
}

static unsigned char atoh(char c)
{
    if (c >= '0' && c <= '9')
        return (c - '0'); // ok, 0-9

    if (c >= 'A' && c <= 'F')
        return (c - 'A' + 10); // ok, A-F

    if (c >= 'a' && c <= 'f')
        return (c - 'a' + 10); // ok, a-f

    return (0); // Fehler
}

static unsigned char ASCII2BCD(const char *szASCII, unsigned char *pbyBCD, short pnBCDLen)
{
    int nASCIILen, i, j;

    if (pnBCDLen == 0)
    {
        nASCIILen = strlen(szASCII);
    }
    else
    {
        nASCIILen = (pnBCDLen)*2;
        memset(pbyBCD, 0x00, pnBCDLen);
    }

    for (i = 0, j = 0; j < nASCIILen; i++, j += 2)
    {
        pbyBCD[i] = (atoh(szASCII[2 * i]) << 4) | atoh(szASCII[2 * i + 1]);
    }

    return (1);
}



void testKey(const unsigned char * theKey, const unsigned char * toDecrypt, const unsigned char * expectedClearKey, const unsigned char * expectedCheckValue, const char * label)
{
    //short result = 0;
    unsigned char theKeyBcd[16];
    unsigned char toDecryptBcd[16];
    unsigned char clearKeyBcd[16];
    //unsigned char checkValueBcd[16];

    char clearKeyAsc[33] = {'\0'};
    
    ASCII2BCD((const char *) theKey, theKeyBcd, sizeof(theKeyBcd));
    ASCII2BCD((const char *) toDecrypt, toDecryptBcd, sizeof(toDecryptBcd));

    des3_ecb_decrypt(clearKeyBcd, toDecryptBcd, sizeof(toDecryptBcd), theKeyBcd, sizeof(theKeyBcd));
    bcdToAsc(clearKeyAsc, clearKeyBcd, sizeof(clearKeyBcd));

    printf("Clear %s -> %s\n", label, clearKeyAsc);
    getchar();

	
    
}

void test(void)
{
    
    unsigned char sysClearKey[] = "F9F6FF09D77B6A78595541DB63D821FA";

    unsigned char encryptedTmk [] = "C4C538167E73EB970A626904F0213842";
    unsigned char expectedClearMasterKey[] = "C276E69EFE1F0807342AD39D5BD9DA37";
    unsigned char expectedMasterKeyCheckValue[] = "06F1DA";

    unsigned char expectedClearSessionKey[] = "7A91384AD04C8A85CD7919C1803D8FCD";
    unsigned char encryptedSessionKey[] = "A446B753852C99A7BD871D31C03BF833"; 
    unsigned char expectedSessionKeyCheckValue[] = "131A50";   

    testKey(sysClearKey, encryptedTmk, expectedClearMasterKey, expectedMasterKeyCheckValue, "MasterKey");
    testKey(expectedClearMasterKey, encryptedSessionKey, expectedClearSessionKey, expectedSessionKeyCheckValue, "Session Key");
}
int des_test_self()
{
	unsigned char buff[1024] = {0};
	unsigned char data[1024] = {0x3F,0x12,0xE7,0xC0,0x2D,0x66,0x5A,0xB0,0xC4,0x2E,0x58,0xF1};
	int ret,len,i;
	
//<<<<<<< HEAD
//	len = MyStrToHex("3F12E7C02D665AB0C42E58F1", data);//不满8字节
//=======
//	len = MyStrToHex("3F12E7C02D665AB0C42E58F1", data);//����8�ֽ�
//>>>>>>> add all file
	len = strlen((char*)data);
	for(i = 0;i < len;i++)
    {
        printf("%02X",data[i]);
    }
    printf("\r\n");

	unsigned char key[16] = {0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0x00,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
//<<<<<<< HEAD
	//DES ECB 加密
//=======
	//DES ECB ����
//>>>>>>> add all file
	printf("DES ECB ENC::\r\n");
	ret = des_ecb_encrypt(buff,data,len,key);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",buff[i]);
    }
    printf("\r\n");
//<<<<<<< HEAD
	//DES ECB 解密
//=======
	//DES ECB ����
//>>>>>>> add all file
	printf("DES ECB DEC::\r\n");
	memset(data,0,sizeof(data));
	des_ecb_decrypt(data,buff,ret,key);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",data[i]);
    }
    printf("\r\n");

//<<<<<<< HEAD
	//DES CBC 加密
//=======
	//DES CBC ����
//>>>>>>> add all file
	printf("DES CBC ENC::\r\n");
	memset(buff,0,sizeof(buff));
	des_cbc_encrypt(buff,data,ret,key,NULL);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",buff[i]);
    }
    printf("\r\n");

//<<<<<<< HEAD
	//DES CBC 解密
//=======
	//DES CBC ����
//>>>>>>> add all file
	printf("DES CBC DEC::\r\n");
	memset(data,0,sizeof(data));
	des_cbc_decrypt(data,buff,ret,key,NULL);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",data[i]);
    }
    printf("\r\n");
	printf("\r\n");


//<<<<<<< HEAD
	//3DES ECB 加密
//=======
	//3DES ECB ����
//>>>>>>> add all file
	printf("3DES ECB ENC::\r\n");
	ret = des3_ecb_encrypt(buff,data,len,key,16);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",buff[i]);
    }
    printf("\r\n");
//<<<<<<< HEAD
	//3DES ECB 解密
//=======
	//3DES ECB ����
//>>>>>>> add all file
	printf("3DES ECB DEC::\r\n");
	memset(data,0,sizeof(data));
	des3_ecb_decrypt(data,buff,ret,key,16);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",data[i]);
    }
    printf("\r\n");

//<<<<<<< HEAD
	//3DES CBC 加密
//=======
	//3DES CBC ����
//>>>>>>> add all file
	printf("3DES CBC ENC::\r\n");
	memset(buff,0,sizeof(buff));
	des3_cbc_encrypt(buff,data,ret,key,16,NULL);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",buff[i]);
    }
    printf("\r\n");

//<<<<<<< HEAD
	//3DES CBC 解密
//=======
	//3DES CBC ����
//>>>>>>> add all file
	printf("3DES CBC DEC::\r\n");
	memset(data,0,sizeof(data));
	des3_cbc_decrypt(data,buff,ret,key,16,NULL);
	for(i = 0;i < ret;i++)
    {
        printf("%02X",data[i]);
    }
    printf("\r\n");


	return 0;
}

int main(void)
{
    test();
    //return des_test_self();

    return 0;
}

#endif
