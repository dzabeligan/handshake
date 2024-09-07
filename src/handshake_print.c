/**
 * @file handshake_print.c
 * @author Elijah Balogun (elijah.balogun@cyberpay.net.ng)
 * @brief Implement interface to print Handshake objects
 * @version 0.1
 * @date 2023-02-23
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "handshake_internals.h"

/**
 * @brief Log TMS Response
 *
 * @param tmsResponse
 */
void logTMSResponse(const TMSResponse* tmsResponse) {
  debug("TMS RESPONSE");
  debug("========================================");
  debug("Admin PIN:                     %s", tmsResponse->adminPin);
  debug("Change PIN:                    %d", tmsResponse->changePin);
  debug("Component KEY:                 %s", tmsResponse->componentKey);
  debug("Currency Code:                 %s", tmsResponse->currencyCode);
  debug("Currency Symbol:               %s", tmsResponse->currencySymbol);
  debug("Customer Copy Label:           %s", tmsResponse->customerCopyLabel);
  debug("Email:                         %s", tmsResponse->email);
  debug("Footer:                        %s", tmsResponse->footer);
  debug("Footnote:                      %s", tmsResponse->footnote);
  debug("Logo Path:                     %s", tmsResponse->logoPath);
  debug("Merchant Address:              %s", tmsResponse->merchantAddress);
  debug("Merchant Copy Label:           %s", tmsResponse->merchantCopyLabel);
  debug("Merchant Name:                 %s", tmsResponse->merchantName);
  debug("Merchant PIN:                  %s", tmsResponse->merchantPin);
  debug("Support Phone:                 %s", tmsResponse->posSupportName);
  debug("Support Name:                  %s", tmsResponse->posSupportPhone);
  debug("Should Print Logo:             %d", tmsResponse->shouldPrintLogo);
}

/**
 * @brief Log Key
 *
 * @param key
 * @param title
 */
void logKey(const Key* key, const char* title) {
  debug("%s", title);
  debug("========================================");
  debug("Key:                           %s", key->key);
  debug("KCV:                           %s", key->kcv);
}

/**
 * @brief Log Parameters
 *
 * @param parameters
 */
void logParameter(Parameters* parameters) {
  debug("PARAMETERS");
  debug("========================================");
  debug("Call Home Time:                %s", parameters->callHomeTime);
  debug("Card Acceptor ID:              %s", parameters->cardAcceptorID);
  debug("Country Code:                  %s", parameters->countryCode);
  debug("Currency Code:                 %s", parameters->currencyCode);
  debug("Currency Symbol:               %s", parameters->currencySymbol);
  debug("Merchant Category Code:        %s", parameters->merchantCategoryCode);
  debug("Merchant Name and Location:    %s",
        parameters->merchantNameAndLocation);
  debug("Server Date and Time:          %s", parameters->serverDateAndTime);
  debug("Timeout:                       %s", parameters->timeout);
}

/**
 * @brief Log Network Management Response
 *
 * @param networkManagementResponse
 */
void logNetworkManagementResponse(
    NetworkManagementResponse* networkManagementResponse) {
  debug("NETWORK MANAGEMENT RESPONSE");
  debug("========================================");
  debug("Response Code:                 %s",
        networkManagementResponse->responseCode);
  logKey(&networkManagementResponse->master, "MASTER KEY");
  logKey(&networkManagementResponse->session, "SESSION KEY");
  logKey(&networkManagementResponse->pin, "PIN KEY");
  logParameter(&networkManagementResponse->parameters);
}
