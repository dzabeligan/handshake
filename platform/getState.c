#include "getState.h"

#include <stdio.h>
#include <time.h>

int getState(char* state, const size_t size) {
  time_t now = time(NULL);
  struct tm now_t = *localtime(&now);
  char dateTimeBuff[64] = {'\0'};
  char lastTrans[16] = {'\0'};

  strftime(dateTimeBuff, sizeof(dateTimeBuff), "%a %d/%m/%Y %H:%M:%S", &now_t);
  strftime(lastTrans, sizeof(lastTrans), "%Y%m%d%H%M%S", &now_t);

  return snprintf(
      state, size,
      "{\"ptad\": \"ITEX\",\"serial\": \"346228245\",\"bl\": 70,\"btemp\": "
      "30,\"ctime\": \"%s\",\"cs\": \"Charging\",\"ps\": "
      "\"PrinterAvailable\",\"tid\": \"2033GP24\",\"coms\": "
      "\"GSM/LTE\",\"sim\": \"\",\"simID\": "
      "\"621301234567890123456789\",\"imsi\": \"621301234567890\",\"ss\" : "
      "100,\"cloc\": "
      "\"{cid:\"0123\",lac:\"1234\",mcc:\"62130\",mnc:\"30\",ss:100dbm}\","
      "\"tmn\": \"LaptopPort\",\"tmanu\": \"Apple\",\"hb\": "
      "\"true\",\"lTxnAt\": \"%s\",\"sv\": \"0.0.1\",\"pads\": \"\"}",
      dateTimeBuff, lastTrans);
}
