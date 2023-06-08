/**
 * @file handshake_tams.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implements TAMS Handshake
 * @version 0.1
 * @date 2023-02-24
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "handshake_internals.h"

/**
 * @brief Build TAMS HTTP Request
 *
 * @param requestBuf
 * @param bufLen
 * @param handshake
 * @param data
 * @param path
 * @return int
 */
static int buildTamsHttpRequest(char* requestBuf, size_t bufLen,
                                Handshake_t* handshake, char* data,
                                const char* path) {
  int pos = 0;
  const char* TAMS_POST_VERSION = "8.0.6";
  char hash[0x100] = {'\0'};

  if (data) {
    check(
        getTamsHash(hash, data,
                    (char*)handshake->networkManagementResponse.session.key) ==
            EXIT_SUCCESS,
        "Error Generating TAMS Hash");
  }

  pos +=
      snprintf(&requestBuf[pos], bufLen - pos, "POST /%s HTTP/1.1\r\n", path);
  pos +=
      snprintf(&requestBuf[pos], bufLen - pos, "Host: %s:%d\r\n",
               handshake->handshakeHost.hostUrl, handshake->handshakeHost.port);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "User-Agent: lipman/%s\r\n",
                  TAMS_POST_VERSION);
  pos +=
      snprintf(&requestBuf[pos], bufLen - pos, "Accept: application/xml\r\n");
  pos += snprintf(&requestBuf[pos], bufLen - pos,
                  "Content-Type: application/x-www-form-urlencoded\r\n");
  pos += snprintf(&requestBuf[pos], bufLen - pos, "Terminal: %s\r\n",
                  handshake->tid);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "EOD: 0\r\n");
  pos += snprintf(&requestBuf[pos], bufLen - pos, "Sign: %s\r\n", hash);
  pos +=
      snprintf(&requestBuf[pos], bufLen - pos, "Content-Length: %zu\r\n\r\n%s",
               data ? strlen(data) : 0, data ? data : "");
error:
  return pos;
}

/**
 * @brief Parse Master Key Response
 *
 * @param handshake
 * @param response
 * @return short
 */
static short parseMasterkeyResponse(Handshake_t* handshake, char* response) {
  ezxml_t root = NULL;
  ezxml_t masterkey = NULL;
  int ret = EXIT_FAILURE;

  root = ezxml_parse_str(response, strlen(response));
  check_mem(root);
  check(checkTamsError(handshake->error.message,
                       sizeof(handshake->error.message) - 1, root) == 0,
        "TAMS Error");
  check((masterkey = ezxml_child(root, "masterkey")),
        "Error Getting `masterkey`");

  strncpy((char*)handshake->networkManagementResponse.master.key,
          masterkey->txt,
          sizeof(handshake->networkManagementResponse.master.key));

  ret = EXIT_SUCCESS;
error:
  ezxml_free(root);

  return ret;
}

/**
 * @brief Get the Master Key object
 *
 * @param handshake
 * @return short
 */
static short getMasterKey(Handshake_t* handshake) {
  int len = -1;
  char requestBuf[0x1000] = {'\0'};
  unsigned char responseBuf[0x1000] = {'\0'};
  int ret = EXIT_FAILURE;
  const char* NEW_KEY_PATH = "tams/tams/devinterface/newkey.php";

  debug("MASTER");
  len = buildTamsHttpRequest(requestBuf, sizeof(requestBuf) - 1, handshake,
                             NULL, NEW_KEY_PATH);
  check(len > 0, "Error Building TAMS Request");
  debug("Request: '%s (%d)'", requestBuf, len);

  len = handshake->comSendReceive(
      responseBuf, sizeof(responseBuf) - 1, (unsigned char*)requestBuf, len,
      handshake->handshakeHost.hostUrl, handshake->handshakeHost.port,
      handshake->handshakeHost.connectionType, handshake->comSentinel,
      "</newkey>");
  check(len > 0, "Error sending or receiving request");
  debug("Response: '%s (%d)'", responseBuf, len);

  check(parseMasterkeyResponse(handshake, (char*)responseBuf) == EXIT_SUCCESS,
        "Parse Error");

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Error Getting Master Key");
  }
  return ret;
}

/**
 * @brief Parse Get Keys Response
 *
 * @param handshake
 * @param response
 * @return short
 */
static short parseGetKeysResponse(Handshake_t* handshake, char* response) {
  ezxml_t root = NULL, cipher = NULL;
  int ret = EXIT_FAILURE;
  const int PIN_KEY_INDEX = 2;
  char clearKeys[3][33] = {{'\0'}, {'\0'}, {'\0'}};
  char encryptedKeys[3][33] = {{'\0'}, {'\0'}, {'\0'}};
  int i = 0;

  root = ezxml_parse_str(response, strlen(response));
  check_mem(root);
  check(checkTamsError(handshake->error.message,
                       sizeof(handshake->error.message) - 1, root) == 0,
        "TAMS Error");
  check((cipher = ezxml_child(root, "cipher")), "Error Getting `cipher`");

  for (i = 0; i <= PIN_KEY_INDEX; cipher = ezxml_next(cipher), i++) {
    ezxml_t number, key;

    check((number = ezxml_child(cipher, "no")), "Error Getting `no`");
    if (strncmp(number->txt, "0", 1) == 0) {
      check((key = ezxml_child(cipher, "key")), "Error Getting `key`");
      strncpy(encryptedKeys[0], key->txt, sizeof(encryptedKeys[0]));
    } else if (strncmp(number->txt, "1", 1) == 0) {
      check((key = ezxml_child(cipher, "key")), "Error Getting `key`");
      strncpy(encryptedKeys[1], key->txt, sizeof(encryptedKeys[1]));
    } else if (strncmp(number->txt, "2", 1) == 0) {
      check((key = ezxml_child(cipher, "key")), "Error Getting `key`");
      strncpy(encryptedKeys[2], key->txt, sizeof(encryptedKeys[2]));
    }
  }

  decryptTamsKey(clearKeys, encryptedKeys, handshake->tid,
                 (char*)handshake->networkManagementResponse.master.key,
                 PIN_KEY_INDEX + 1);
  strncpy((char*)handshake->networkManagementResponse.session.key, clearKeys[1],
          sizeof(handshake->networkManagementResponse.session.key));
  strncpy((char*)handshake->networkManagementResponse.pin.key, clearKeys[2],
          sizeof(handshake->networkManagementResponse.pin.key));
  ret = EXIT_SUCCESS;
error:
  ezxml_free(root);

  return ret;
}

/**
 * @brief Get the Session Key object
 *
 * @param handshake
 * @return short
 */
static short getSessionKey(Handshake_t* handshake) {
  int len = -1;
  char requestBuf[0x1000] = {'\0'};
  unsigned char responseBuf[0x1000] = {'\0'};
  int ret = EXIT_FAILURE;
  const char* SESSION_KEY_PATH = "tams/tams/devinterface/getkeys.php";

  debug("SESSION");
  len = buildTamsHttpRequest(requestBuf, sizeof(requestBuf) - 1, handshake,
                             NULL, SESSION_KEY_PATH);
  check(len > 0, "Error Building TAMS Request");
  debug("Request: '%s (%d)'", requestBuf, len);

  len = handshake->comSendReceive(
      responseBuf, sizeof(responseBuf) - 1, (unsigned char*)requestBuf, len,
      handshake->handshakeHost.hostUrl, handshake->handshakeHost.port,
      handshake->handshakeHost.connectionType, handshake->comSentinel,
      "</getkeys>");
  check(len > 0, "Error sending or receiving request");
  debug("Response: '%s (%d)'", responseBuf, len);

  check(parseGetKeysResponse(handshake, (char*)responseBuf) == EXIT_SUCCESS,
        "Parse Error");

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Error Getting Session Keys");
  }
  return ret;
}

/**
 * @brief Get the Pin Key object
 *
 * @param handshake
 * @return short
 */
static short getPinKey(Handshake_t* handshake) {
  (void)handshake;
  debug("PIN");
  return EXIT_SUCCESS;
}

/**
 * @brief Parse Get Parameters Response
 *
 * @param handshake
 * @param response
 * @return short
 */
static short parseGetParametersResponse(Handshake_t* handshake,
                                        char* response) {
  ezxml_t root, dateTimeTag, item;
  char year[5] = {'\0'};
  char month[3] = {'\0'};
  char day[3] = {'\0'};
  char hour[3] = {'\0'};
  char minutes[3] = {'\0'};
  char seconds[3] = {'\0'};
  int ret = EXIT_FAILURE;

  root = ezxml_parse_str(response, strlen(response));
  check_mem(root);
  check(checkTamsError(handshake->error.message,
                       sizeof(handshake->error.message) - 1, root) == 0,
        "TAMS Error");

  check((dateTimeTag = ezxml_child(root, "datetime")),
        "Error Getting `datetime`");

  check((item = ezxml_child(dateTimeTag, "year")), "Error Getting `year`");
  strncpy(year, item->txt, sizeof(year));

  check((item = ezxml_child(dateTimeTag, "mon")), "Error Getting `mon`");
  strncpy(month, item->txt, sizeof(month));

  check((item = ezxml_child(dateTimeTag, "day")), "Error Getting `day`");
  strncpy(day, item->txt, sizeof(day));

  check((item = ezxml_child(dateTimeTag, "hour")), "Error Getting `hour`");
  strncpy(hour, item->txt, sizeof(hour));

  check((item = ezxml_child(dateTimeTag, "min")), "Error Getting `min`");
  strncpy(minutes, item->txt, sizeof(minutes));

  check((item = ezxml_child(dateTimeTag, "sec")), "Error Getting `sec`");
  strncpy(seconds, item->txt, sizeof(seconds));

  sprintf(handshake->networkManagementResponse.parameters.serverDateAndTime,
          "%s%s%s%s%s%s", year, month, day, hour, minutes, seconds);

  check((item = ezxml_child(root, "merchantid")), "Error Getting `merchantid`");

  strncpy(
      handshake->networkManagementResponse.parameters.cardAcceptorID, item->txt,
      sizeof(handshake->networkManagementResponse.parameters.cardAcceptorID));

  check((item = ezxml_child(root, "currcode")), "Error Getting `currcode`");

  strncpy(handshake->networkManagementResponse.parameters.currencyCode,
          item->txt,
          sizeof(handshake->networkManagementResponse.parameters.currencyCode));

  check((item = ezxml_child(root, "countrycode")),
        "Error Getting `countrycode`");

  strncpy(handshake->networkManagementResponse.parameters.countryCode,
          item->txt,
          sizeof(handshake->networkManagementResponse.parameters.countryCode));

  check((item = ezxml_child(root, "currency")), "Error Getting `currency`");

  strncpy(
      handshake->networkManagementResponse.parameters.currencySymbol, item->txt,
      sizeof(handshake->networkManagementResponse.parameters.currencySymbol));

  check((item = ezxml_child(root, "footer")), "Error Getting `footer`");

  strncpy(handshake->networkManagementResponse.parameters.footer, item->txt,
          sizeof(handshake->networkManagementResponse.parameters.footer));

  check((item = ezxml_child(root, "header")), "Error Getting `header`");

  strncpy(handshake->networkManagementResponse.parameters.header, item->txt,
          sizeof(handshake->networkManagementResponse.parameters.header));

  check((item = ezxml_child(root, "endofday")), "Error Getting `endofday`");
  handshake->networkManagementResponse.parameters.endOfDay = atol(item->txt);

  check((item = ezxml_child(root, "pinreset")), "Error Getting `pinreset`");
  handshake->networkManagementResponse.parameters.resetPin =
      strncmp(item->txt, "Y", 1) == 0;

  ret = EXIT_SUCCESS;
error:
  ezxml_free(root);

  return ret;
}

/**
 * @brief Get the Parameters object
 *
 * @param handshake
 * @return short
 */
static short getParameters(Handshake_t* handshake) {
  int len = -1;
  char requestBuf[0x1000] = {'\0'};
  unsigned char responseBuf[0x1000] = {'\0'};
  int ret = EXIT_FAILURE;
  char data[0x100] = {'\0'};
  const char* PARAMETERS_PATH = "tams/tams/devinterface/getparams.php";

  debug("PARAMETER");
  snprintf(data, sizeof(data) - 1, "ver=%s&serial=%s",
           handshake->appInfo.version, handshake->deviceInfo.posUid);
  len = buildTamsHttpRequest(requestBuf, sizeof(requestBuf) - 1, handshake,
                             data, PARAMETERS_PATH);
  check(len > 0, "Error Building TAMS Request");
  debug("Request: '%s (%d)'", requestBuf, len);

  len = handshake->comSendReceive(
      responseBuf, sizeof(responseBuf) - 1, (unsigned char*)requestBuf, len,
      handshake->handshakeHost.hostUrl, handshake->handshakeHost.port,
      handshake->handshakeHost.connectionType, handshake->comSentinel,
      "</param>");
  check(len > 0, "Error sending or receiving request");
  debug("Response: '%s (%d)'", responseBuf, len);

  check(
      parseGetParametersResponse(handshake, (char*)responseBuf) == EXIT_SUCCESS,
      "Parse Error");

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Error Getting Session Keys");
  }
  return ret;
}

/**
 * @brief Do Call Home
 *
 * @param handshake
 * @return short
 */
static short doCallHome(Handshake_t* handshake) {
  (void)handshake;

  debug("CALL HOME");
  return EXIT_SUCCESS;
}

/**
 * @brief Parse Get EFT Total Response
 *
 * @param handshake
 * @param response
 * @return short
 */
static short parseGetEftTotalResponse(Handshake_t* handshake, char* response) {
  ezxml_t root, item;
  int ret = EXIT_FAILURE;

  root = ezxml_parse_str(response, strlen(response));
  check_mem(root);
  check(checkTamsError(handshake->error.message,
                       sizeof(handshake->error.message) - 1, root) == 0,
        "TAMS Error");

  check((item = ezxml_child(root, "result")), "Error Getting `result`");
  check(strncmp(item->txt, "0", 1) == 0 || strncmp(item->txt, "100", 3) == 0,
        "EFT Total result `%s`", item->txt);

  check((item = ezxml_child(root, "batchno")), "Error Getting `batchno`");
  handshake->networkManagementResponse.parameters.batchNumber = atoi(item->txt);
  ret = EXIT_SUCCESS;
error:
  ezxml_free(root);

  return ret;
}

/**
 * @brief Get the Eft Total object
 *
 * @param handshake
 * @return short
 */
static short getEftTotal(Handshake_t* handshake) {
  int len = -1;
  char requestBuf[0x1000] = {'\0'};
  unsigned char responseBuf[0x1000] = {'\0'};
  int ret = EXIT_FAILURE;
  char data[0x100] = {'\0'};
  const char* EFT_TOTAL_PATH = "tams/eftpos/devinterface/efttotals.php";

  debug("EFT TOTAL");
  snprintf(data, sizeof(data) - 1,
           "BATCHNO=%d&T=%d&A=%d&PC=%d&PV=%d&PRC=%d&PRV=%d&RC=%d&RV=%d&RRC=%d&"
           "RRV=%d",
           handshake->networkManagementResponse.parameters.batchNumber, 0, 0, 0,
           0, 0, 0, 0, 0, 0, 0);
  len = buildTamsHttpRequest(requestBuf, sizeof(requestBuf) - 1, handshake,
                             data, EFT_TOTAL_PATH);
  check(len > 0, "Error Building TAMS Request");
  debug("Request: '%s (%d)'", requestBuf, len);

  len = handshake->comSendReceive(
      responseBuf, sizeof(responseBuf) - 1, (unsigned char*)requestBuf, len,
      handshake->handshakeHost.hostUrl, handshake->handshakeHost.port,
      handshake->handshakeHost.connectionType, handshake->comSentinel,
      "</efttotals>");
  check(len > 0, "Error sending or receiving request");
  debug("Response: '%s (%d)'", responseBuf, len);

  check(parseGetEftTotalResponse(handshake, (char*)responseBuf) == EXIT_SUCCESS,
        "Parse Error");

  ret = EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Error Getting Session Keys");
  }
  return ret;
}

/**
 * @brief Get the Capk object
 *
 * @param handshake
 * @return short
 */
static short getCapk(Handshake_t* handshake) {
  (void)handshake;

  debug("CAPK DOWNLOAD");
  return EXIT_SUCCESS;
}

/**
 * @brief Bind TAMS
 *
 * @param handshake_internals
 */
void bindTams(Handshake_Internals* handshake_internals) {
  handshake_internals->getMasterKey = getMasterKey;
  handshake_internals->getSessionKey = getSessionKey;
  handshake_internals->getPinKey = getPinKey;
  handshake_internals->getParameters = getParameters;
  handshake_internals->doCallHome = doCallHome;
  handshake_internals->getEftTotal = getEftTotal;
  handshake_internals->getCapk = getCapk;
}
