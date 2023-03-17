#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "c8583/C8583.h"
#include "dbg.h"

static short parseIso(const char* iso) {
  short ret = EXIT_FAILURE;
  IsoMsg isoMsg = createIso8583();

  check(unpackData(isoMsg, (unsigned char*)iso, strlen(iso)), "%s",
        getMessage(isoMsg));

  logIsoMsg(isoMsg, stderr);

  ret = EXIT_SUCCESS;
error:
  destroyIso8583(isoMsg);
  return ret;
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    perror("Usage `parseIso [iso]`");
    exit(1);
  }
  parseIso(argv[1]);

  exit(0);
}
