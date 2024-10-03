/**
 * @file handshake_getDeviceConfig.c
 * @author Elijah Balogun (elijah.balogun@cyberpay.net.ng)
 * @brief Implements Handshake Get Device Config
 * @version 0.1
 * @date 2024-03-14
 *
 * @copyright Copyright (c) 2024
 *
 */
#include <ctype.h>
#include <stdio.h>

#include "handshake_internals.h"

#define TID_MATCH (1 << 0)
#define HOST_MATCH (1 << 1)
#define ALL_MATCH (TID_MATCH | HOST_MATCH)
#define ALL_MATCH_ERR_STR \
  "Handshake not needed, clear TID and Hosts to force handshake"

/**
 * @brief Build Get Config Request
 *
 * @param requestBuf request buffer
 * @param bufLen buffer length
 * @param handshake handshake object
 * @return ssize_t - length of request
 */
static ssize_t buildGetConfigRequest(char* requestBuf, size_t bufLen,
                                     const Handshake_t* handshake) {
  const char* TRANS_ADVICE_PATH = "tms/profile/download";
  ssize_t pos = 0;

  pos +=
      snprintf(requestBuf, bufLen, "GET /%s HTTP/1.1\r\n", TRANS_ADVICE_PATH);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "Host: %s:%d\r\n",
                  handshake->deviceConfigHost.url,
                  handshake->deviceConfigHost.port);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "User-Agent: %s/%s\r\n",
                  handshake->deviceInfo.brand, handshake->appInfo.version);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "brand: %s\r\n",
                  handshake->deviceInfo.brand);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "serial: %s\r\n",
                  handshake->deviceInfo.posUid);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "model: %s\r\n",
                  handshake->deviceInfo.model);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "appversion: %s\r\n",
                  handshake->appInfo.version);
  pos += snprintf(&requestBuf[pos], bufLen - pos, "%s", "\r\n");

  return pos;
}

/**
 * @brief Get the Pos Status object
 *
 * @param root
 * @return const short
 */
static short getPosStatus(Handshake_t* handshake, const cJSON* root) {
  const cJSON *status, *message;

  if ((status = cJSON_GetObjectItemCaseSensitive(root, "status")) &&
      cJSON_IsNumber(status) &&
      (message = cJSON_GetObjectItemCaseSensitive(root, "message")) &&
      cJSON_IsString(message)) {
    strncpy(handshake->error.message, message->valuestring,
            sizeof(handshake->error.message));
    return status->valueint == 200 &&
           strncmp(message->valuestring, "Success",
                   strlen(message->valuestring)) == 0;
  } else if (!cJSON_IsNumber(status)) {
    debug("no status");
    return 1;
  }

  return 0;
}

/**
 * @brief Get the Handshake Host object
 *
 * @param handshake
 * @param root
 * @param needsHandshakeCheck
 * @return short
 */
static short getHandshakeHost(Handshake_t* handshake, const cJSON* root,
                              short* needsHandshakeCheck) {
  const cJSON* item;
  short ret = EXIT_FAILURE;

  check((item = cJSON_GetObjectItemCaseSensitive(root, "hostip")) &&
            cJSON_IsString(item),
        "Unable to get hostip");
  if (*needsHandshakeCheck &&
      strncmp(handshake->handshakeHost.url, item->valuestring,
              sizeof(handshake->handshakeHost.url)) == 0) {
    (*needsHandshakeCheck) |= HOST_MATCH;
  }
  strncpy(handshake->handshakeHost.url, item->valuestring,
          sizeof(handshake->handshakeHost.url));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "hostport")) &&
            cJSON_IsNumber(item),
        "Unable to get hostport");
  handshake->handshakeHost.port = item->valueint;

  check((item = cJSON_GetObjectItemCaseSensitive(root, "hostssl")) &&
            cJSON_IsBool(item),
        "Unable to get hostssl");
  handshake->handshakeHost.connectionType =
      cJSON_IsTrue(item) ? CONNECTION_TYPE_SSL : CONNECTION_TYPE_PLAIN;

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Receipt Config object
 *
 * @param handshake
 * @param root
 * @return short
 */
static short getReceiptConfig(Handshake_t* handshake, const cJSON* root) {
  cJSON* item;
  int ret = EXIT_FAILURE;

  check((item = cJSON_GetObjectItemCaseSensitive(root, "rptfootertext")) &&
            cJSON_IsString(item),
        "Unable to get rptfootertext");
  strncpy(handshake->tmsResponse.footer, item->valuestring,
          sizeof(handshake->tmsResponse.footer));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "rptfootnotelabel")) &&
            cJSON_IsString(item),
        "Unable to get rptfootnotelabel");
  strncpy(handshake->tmsResponse.footnote, item->valuestring,
          sizeof(handshake->tmsResponse.footnote));

  check(
      (item = cJSON_GetObjectItemCaseSensitive(root, "rptcustomercopylabel")) &&
          cJSON_IsString(item),
      "Unable to get rptcustomercopylabel");
  strncpy(handshake->tmsResponse.customerCopyLabel, item->valuestring,
          sizeof(handshake->tmsResponse.customerCopyLabel));

  check(
      (item = cJSON_GetObjectItemCaseSensitive(root, "rptmerchantcopylabel")) &&
          cJSON_IsString(item),
      "Unable to get rptmerchantcopylabel");
  strncpy(handshake->tmsResponse.merchantCopyLabel, item->valuestring,
          sizeof(handshake->tmsResponse.merchantCopyLabel));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "bnkname")) &&
            cJSON_IsString(item),
        "Unable to get bnkname");
  strncpy(handshake->tmsResponse.bankName, item->valuestring,
          sizeof(handshake->tmsResponse.bankName));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "logordownload")) &&
            cJSON_IsString(item),
        "Unable to get logordownload");
  strncpy(handshake->tmsResponse.logoPath, item->valuestring,
          sizeof(handshake->tmsResponse.logoPath));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "rptshowlogo")) &&
            cJSON_IsBool(item),
        "Unable to get rptshowlogo");
  handshake->tmsResponse.shouldPrintLogo = cJSON_IsTrue(item);

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Get the Tms Response object
 *
 * @param handshake
 * @param root
 * @return short
 */
static short getTmsResponse(Handshake_t* handshake, const cJSON* root) {
  const cJSON* item;
  int ret = EXIT_FAILURE;

  check((item = cJSON_GetObjectItemCaseSensitive(root, "merchantname")) &&
            cJSON_IsString(item),
        "Unable to get merchantname");
  strncpy(handshake->tmsResponse.merchantName, item->valuestring,
          sizeof(handshake->tmsResponse.merchantName));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "merchantaddress")) &&
            cJSON_IsString(item),
        "Unable to get merchantaddress");
  strncpy(handshake->tmsResponse.merchantAddress, item->valuestring,
          sizeof(handshake->tmsResponse.merchantAddress));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "adminpin")) &&
            cJSON_IsString(item),
        "Unable to get adminpin");
  strncpy(handshake->tmsResponse.adminPin, item->valuestring,
          sizeof(handshake->tmsResponse.adminPin));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "merchantpin")) &&
            cJSON_IsString(item),
        "Unable to get merchantpin");
  strncpy(handshake->tmsResponse.merchantPin, item->valuestring,
          sizeof(handshake->tmsResponse.merchantPin));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "changepin")) &&
            cJSON_IsString(item),
        "Unable to get changepin");
  handshake->tmsResponse.changePin =
      strncmp(item->valuestring, "true", 4) == 0 ? 1 : 0;

  check((item = cJSON_GetObjectItemCaseSensitive(root, "email")) &&
            cJSON_IsString(item),
        "Unable to get email");
  strncpy(handshake->tmsResponse.email, item->valuestring,
          sizeof(handshake->tmsResponse.email));

//   check((item = cJSON_GetObjectItemCaseSensitive(root, "contactphone")) &&
//             cJSON_IsString(item),
//         "Unable to get contactphone");
  strncpy(handshake->tmsResponse.posSupportPhone, item->valuestring,
          sizeof(handshake->tmsResponse.posSupportPhone));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "contactname")) &&
            cJSON_IsString(item),
        "Unable to get contactname");
  strncpy(handshake->tmsResponse.posSupportName, item->valuestring,
          sizeof(handshake->tmsResponse.posSupportName));

  // currency information
  check((item = cJSON_GetObjectItemCaseSensitive(root, "countrycode")) &&
            cJSON_IsString(item),
        "Unable to get countrycode");
  strncpy(handshake->tmsResponse.currencyCode, item->valuestring,
          sizeof(handshake->tmsResponse.currencyCode));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "curabbreviation")) &&
            cJSON_IsString(item),
        "Unable to get curabbreviation");
  strncpy(handshake->tmsResponse.currencySymbol, item->valuestring,
          sizeof(handshake->tmsResponse.currencySymbol));

  check(getReceiptConfig(handshake, root) == EXIT_SUCCESS,
        "Unable to get receipt configuration");

  ret = EXIT_SUCCESS;
error:
  return ret;
}

/**
 * @brief Parse Get Device Config Response
 *
 * @param handshake
 * @param response
 * @return short
 */
static short parseGetDeviceConfigResponse(Handshake_t* handshake,
                                          const char* response) {
  cJSON* root = NULL;
  const cJSON* item;
  short ret = EXIT_FAILURE;
  short needsHandshakeCheck = 0;

  root = cJSON_Parse(strchr(response, '{'));
  check_mem(root);

  check(getPosStatus(handshake, root), "Get Device Config Status is not OK");

  check((item = cJSON_GetObjectItemCaseSensitive(root, "tid")) &&
            cJSON_IsString(item),
        "Unable to get tid");
  if (strncmp(handshake->tid, item->valuestring, sizeof(handshake->tid)) == 0) {
    needsHandshakeCheck |= TID_MATCH;
  }
  strncpy(handshake->tid, item->valuestring, sizeof(handshake->tid));

  check(getHandshakeHost(handshake, root, &needsHandshakeCheck) == EXIT_SUCCESS,
        "Unable to get handshake host");
  debug("Needs Handshake Check: %d", needsHandshakeCheck);

  check((item = cJSON_GetObjectItemCaseSensitive(root, "swkcomponent1")) &&
            cJSON_IsString(item),
        "Unable to get swkcomponent1");
  strncpy(handshake->tmsResponse.componentKey, item->valuestring,
          sizeof(handshake->tmsResponse.componentKey));

  check((item = cJSON_GetObjectItemCaseSensitive(root, "appname")) &&
            cJSON_IsString(item),
        "Unable to get appname");
  strncpy(handshake->appInfo.name, item->valuestring,
          sizeof(handshake->appInfo.name));

  check(getTmsResponse(handshake, root) == EXIT_SUCCESS,
        "Unable to get TMS Response");

  ret = needsHandshakeCheck == ALL_MATCH ? 2 : EXIT_SUCCESS;
error:
  if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             ret == 2 ? ALL_MATCH_ERR_STR
                      : "Unable to Parse Get Device Config Response");
    if (ret == 2) {
      handshake->error.code = ERROR_CODE_ALREADY_INITIALIZED;
    }
  }
  cJSON_Delete(root);
  return ret;
}

/**
 * @brief Handshake Map Device
 *
 * @param handshake
 */
void Handshake_GetDeviceConfig(Handshake_t* handshake) {
  NetworkBuffer request = {{'\0'}, 0};
  NetworkBuffer response = {{'\0'}, 0};

  handshake->error.code = ERROR_CODE_HANDSHAKE_MAPTID_ERROR;
  memset(request.data, 0, sizeof(request.data));
  request.len = buildGetConfigRequest((char*)request.data, sizeof(request.data),
                                      handshake);
  check(request.len > 0, "Error building request");
  debug("Request: '%s' (%ld)", request.data, request.len);

  response.len = handshake->comSendReceive(&response, &request,
                                           &handshake->deviceConfigHost,
                                           DEFAULT_TIMEOUT, NULL, NULL);
  check(response.len > 0, "Error sending or receiving request");
  debug("Response: '%s (%ld)'", response.data, response.len);

  check(parseGetDeviceConfigResponse(handshake, (char*)response.data) ==
            EXIT_SUCCESS,
        "Parse Error");
  debug("TID after getting config: %s", handshake->tid);
  debug("Handshake host: %s:%d", handshake->handshakeHost.url,
        handshake->handshakeHost.port);

  handshake->error.code = ERROR_CODE_NO_ERROR;
  memset(handshake->error.message, '\0', sizeof(handshake->error.message));
error:
  if (handshake->error.code != ERROR_CODE_NO_ERROR &&
      handshake->error.message[0] == 0) {
    snprintf(handshake->error.message, sizeof(handshake->error.message),
             "Handshake Get Device Config Error");
  }
}
