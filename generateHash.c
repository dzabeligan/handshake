#include "dbg.h"
#include "platform/itexUtils.h"

int main(int argc, char const *argv[]) {
  if (argc != 3) {
    printf("Usage: %s <data> <key>\n", argv[0]);
    return 1;
  }

  char mac[65] = {0};
  generateMac((unsigned char *)mac, (unsigned char *)argv[2], strlen(argv[2]),
              (unsigned char *)argv[1], strlen(argv[1]));
  debug("Hash: %s", mac);
}
