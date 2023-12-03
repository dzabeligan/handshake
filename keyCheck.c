#include "dbg.h"
#include "des/des.h"

static unsigned char atoh(const char c) {
  if (c >= '0' && c <= '9') return (c - '0');
  if (c >= 'A' && c <= 'F') return (c - 'A' + 10);
  if (c >= 'a' && c <= 'f') return (c - 'a' + 10);

  return 0;
}

static short ascToBcd2(unsigned char* bcd, const short bcdLen,
                       const char* asc) {
  int ascLen, i, j;

  if (bcdLen == 0) {
    ascLen = strlen(asc);
  } else {
    ascLen = (bcdLen) * 2;
    memset(bcd, 0x00, bcdLen);
  }

  for (i = 0, j = 0; j < ascLen; i++, j += 2) {
    bcd[i] = (atoh(asc[2 * i]) << 4) | atoh(asc[2 * i + 1]);
  }

  return i;
}

static short bcdToAsc2(unsigned char* asc, const int ascLen, const unsigned char* bcd,
                const int bcdLen) {
  int i = 0;
  short pos = 0;

  if (bcdLen <= 0 || bcdLen * 2 > ascLen) {
    log_err("Error Converting to ASCII");
    return -1;
  }

  for (i = 0; i < bcdLen; i++) {
    pos += sprintf((char*)&asc[pos], "%02X", bcd[i]);
  }

  asc[pos] = '\0';

  return pos;
}

static short checkKeyValue(const char* key, const char* kcv) {
  unsigned char keyBcd[16];
  unsigned char actualCheckValueBcd[16] = {'\0'};
  unsigned char data[9] = "\x00\x00\x00\x00\x00\x00\x00\x00";
  char actualCheckValueStr[33] = {'\0'};

  debug("Key: '%s'", key);
  ascToBcd2(keyBcd, sizeof(keyBcd), (const char*)key);
  des3_ecb_encrypt(actualCheckValueBcd, data, sizeof(data) - 1, keyBcd,
                   sizeof(keyBcd));
  bcdToAsc2((unsigned char*)actualCheckValueStr, sizeof(actualCheckValueStr),
            actualCheckValueBcd, sizeof(actualCheckValueBcd));
  debug("KCV: '%s'", actualCheckValueStr);

  return strncmp(kcv, actualCheckValueStr, 6) == 0;
}

int main(int argc, char** argv) {
  if (argc != 3) {
    printf("Usage: %s <key> <kcv>\n", argv[0]);
    return 1;
  }

  if (checkKeyValue(argv[1], argv[2])) {
    printf("Key is valid\n");
  } else {
    printf("Key is invalid\n");
  }

  return 0;
}
