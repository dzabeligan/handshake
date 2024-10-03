/**
 * @file handshake.c
 * @author Elijah Balogun (elijah.balogun@cyberpay.net.ng)
 * @brief Implements Handshake
 * @version 0.1
 * @date 2023-01-09
 *
 * @copyright Copyright (c) 2023
 *
 */
#include <stdio.h>

#include "handshake_internals.h"

/**
 * @brief Check if the device data in the handshake matches the expected format.
 *
 * @param handshake The handshake object containing the device data to be
 * checked.
 * @return A short indicating whether the device data is valid (1) or not (0).
 */
static short checkGetDeviceConfigData(Handshake_t* handshake) {
  return handshake->appInfo.version[0] && handshake->deviceInfo.brand[0] &&
         handshake->deviceInfo.model[0] && handshake->deviceInfo.posUid[0] &&
         handshake->deviceConfigHost.url[0] &&
         handshake->deviceConfigHost.port != 0;
}

/**
 * @brief Checks if all mandatory fields in the Handshake_t struct are
 * populated.
 *
 * `comSendReceive` must be set
 * atleast deviceConfigHost must be set when get device config is set to true
 * handshakeHost is optional when get device config is true, mandatory otherwise
 *
 * @param handshake Pointer to the Handshake_t struct to be checked.
 * @return Returns a short indicating whether all mandatory fields are populated
 * (1) or not (0).
 */
static short checkMandatoryFields(Handshake_t* handshake) {
  return handshake->comSendReceive &&
         ((handshake->shouldGetDeviceConfig &&
           checkGetDeviceConfigData(handshake)) ||
          (!handshake->shouldGetDeviceConfig &&
           handshake->handshakeHost.url[0] && handshake->handshakeHost.port));
}

/**
 * @brief Validates the handshake data.
 *
 * @param handshake A pointer to the Handshake_t struct containing the handshake
 * data to be validated.
 * @return A short indicating whether the validation was successful
 * (EXIT_SUCCESS) or not (EXIT_FAILURE).
 */
static short validateHandshakeData(Handshake_t* handshake) {
  if (!checkMandatoryFields(handshake)) {
    log_err(
        "`comSendReceive` or `hosts` or `data needed to get device config` not "
        "set");
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "`comSendReceive` or `hosts` or `data needed to get device "
             "config` not set");
    return EXIT_FAILURE;
  }

  // tid must be set when get device config is false
  if (!handshake->shouldGetDeviceConfig && !(handshake->tid[0])) {
    log_err("TID can't be empty when `shouldGetDeviceConfig` is false");
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "TID can't be empty when `shouldGetDeviceConfig` is false");
    return EXIT_FAILURE;
  }

  if (handshake->operations & HANDSHAKE_OPERATIONS_CALLHOME &&
      handshake->platform == PLATFORM_NIBSS && !handshake->getCallHomeData) {
    log_err("`getCallHomeData` must be set when performing callhome for NIBSS");
    snprintf(
        handshake->error.message, sizeof(handshake->error.message) - 1,
        "`getCallHomeData` must be set when performing callhome for NIBSS");
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}

/**
 * @brief Initializes a Handshake_t struct.
 *
 * @param handshake A pointer to the Handshake_t struct to be initialized.
 */
static void Handshake_Init(Handshake_t* handshake) {
  handshake->error.code = ERROR_CODE_HANDSHAKE_INIT_ERROR;

  check(validateHandshakeData(handshake) == EXIT_SUCCESS,
        "Error Validating `handshake`");

  // Handshake operations not set so perform all operations
  if (handshake->operations == HANDSHAKE_OPERATIONS_NONE) {
    handshake->operations = HANDSHAKE_OPERATIONS_ALL;
  }
  // If all operations should be performed, clear response objects
  if (handshake->operations == HANDSHAKE_OPERATIONS_ALL) {
    memset(&handshake->tmsResponse, '\0', sizeof(handshake->tmsResponse));
    memset(&handshake->networkManagementResponse, '\0',
           sizeof(handshake->networkManagementResponse));
  }

  handshake->error.code = ERROR_CODE_NO_ERROR;
  memset(handshake->error.message, '\0', sizeof(handshake->error.message));
error:
  return;
}

/**
 * Binds the platform to the Handshake internals.
 *
 * @param handshakeInternals The Handshake internals to bind the platform to.
 */
static void bindPlatform(HandshakeOperations* handshakeInternals,
                         Platform platform) {
  if (platform == PLATFORM_NIBSS) {
    bindNibss(handshakeInternals);
  }
}

/**
 * @brief Runs the handshake process.
 *
 * @param handshake A pointer to the Handshake_t struct.
 */
static void Handshake_Run(Handshake_t* handshake) {
  handshake->error.code = ERROR_CODE_HANDSHAKE_RUN_ERROR;
  HandshakeOperations handshakeInternals = {0};

  bindPlatform(&handshakeInternals, handshake->platform);

  if (handshake->operations & HANDSHAKE_OPERATIONS_MASTER_KEY) {
    check(handshakeInternals.getMasterKey(handshake) == EXIT_SUCCESS,
          "Error Getting Master Key");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_SESSION_KEY) {
    check(handshakeInternals.getSessionKey(handshake) == EXIT_SUCCESS,
          "Error Getting Session Key");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_PIN_KEY) {
    check(handshakeInternals.getPinKey(handshake) == EXIT_SUCCESS,
          "Error Getting PIN Key");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_PARAMETER) {
    check(handshakeInternals.getParameters(handshake) == EXIT_SUCCESS,
          "Error Getting Parameters");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_CALLHOME) {
    check(handshakeInternals.doCallHome(handshake) == EXIT_SUCCESS,
          "Error Doing Call Home");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_CAPK) {
    check(handshakeInternals.getCapk(handshake) == EXIT_SUCCESS,
          "Error Getting CAPK");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_CAPK) {
    check(handshakeInternals.getAid(handshake) == EXIT_SUCCESS,
          "Error Getting AID");
  }

  handshake->error.code = ERROR_CODE_NO_ERROR;
  memset(handshake->error.message, '\0', sizeof(handshake->error.message));
error:
  return;
}

/**
 * @brief Performs a handshake operation using the provided Handshake_t struct.
 *
 * @param handshake A pointer to the Handshake_t struct to use for the
 * handshake.
 */
void Handshake(Handshake_t* handshake) {
  Handshake_Init(handshake);
  check(handshake->error.code == ERROR_CODE_NO_ERROR, "Handshake Init Error");

  if (handshake->shouldGetDeviceConfig) {
    Handshake_GetDeviceConfig(handshake);
    check(handshake->error.code == ERROR_CODE_NO_ERROR, "%s",
          handshake->error.message);
  }

  Handshake_Run(handshake);
error:
  return;
}
