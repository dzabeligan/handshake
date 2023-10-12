/**
 * @file handshake.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implements Handshake with NIBSS/Middleware and TAMS
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
static short checkMapDeviceData(Handshake_t* handshake) {
  return handshake->appInfo.name[0] && handshake->appInfo.version[0] &&
         handshake->deviceInfo.model[0] && handshake->deviceInfo.posUid[0] &&
         handshake->mapDeviceHost.url[0] && handshake->mapDeviceHost.port != 0;
}

/**
 * @brief Checks if all mandatory fields in the Handshake_t struct are
 * populated.
 *
 * `comSendReceive` must be set
 * atleast mapdDeviceHost must be set when Map device is set to true
 * handshakeHost is optional when Map device is true, mandatory otherwise
 *
 * @param handshake Pointer to the Handshake_t struct to be checked.
 * @return Returns a short indicating whether all mandatory fields are populated
 * (1) or not (0).
 */
static short checkMandatoryFields(Handshake_t* handshake) {
  return handshake->comSendReceive &&
         ((handshake->mapDevice == HANDSHAKE_MAP_DEVICE_TRUE &&
           checkMapDeviceData(handshake)) ||
          (handshake->mapDevice == HANDSHAKE_MAP_DEVICE_FALSE &&
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
        "`comSendReceive` or `hosts` or `data needed to map device` not set");
    snprintf(
        handshake->error.message, sizeof(handshake->error.message) - 1,
        "`comSendReceive` or `hosts` or `data needed to map device` not set");
    return EXIT_FAILURE;
  }

  // tid must be set when map device is false
  if (handshake->mapDevice == HANDSHAKE_MAP_DEVICE_FALSE &&
      !(handshake->tid[0])) {
    log_err("TID can't be empty when `mapDevice` is false");
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "TID can't be empty when `mapDevice` is false");
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
    memset(&handshake->tamsResponse, '\0', sizeof(handshake->tamsResponse));
    memset(&handshake->networkManagementResponse, '\0',
           sizeof(handshake->networkManagementResponse));
  }

  handshake->error.code = ERROR_CODE_NO_ERROR;
  memset(handshake->error.message, '\0', sizeof(handshake->error.message));
error:
  return;
}

/**
 * @brief A helper function to get the handshake host.
 *
 * This function is used internally to retrieve the handshake host.
 *
 * @param handshake A pointer to the Handshake_t struct.
 * @param server
 */
static void getHandshakeHostHelper(Handshake_t* handshake,
                                   PrivatePublicServer* server) {
  SimType simType = handshake->simInfo.simType;

  if (simType == SIM_TYPE_PUBLIC) {
    strncpy(handshake->handshakeHost.url, server->publicServer.ip,
            sizeof(handshake->handshakeHost.url));
    handshake->handshakeHost.port = server->publicServer.port;
  } else if (simType == SIM_TYPE_PRIVATE) {
    strncpy(handshake->handshakeHost.url, server->privateServer.ip,
            sizeof(handshake->handshakeHost.url));
    handshake->handshakeHost.port = server->privateServer.port;
  }
}

/**
 * @brief Retrieves the handshake host from the given Handshake_t struct.
 *
 * @param handshake A pointer to the Handshake_t struct to retrieve the host
 * from.
 * @param middlewareServer
 */
static void getHandshakeHost(Handshake_t* handshake,
                             MiddlewareServer* middlewareServer) {
  ConnectionType connectionType =
      handshake->tamsResponse.servers.connectionType;

  if (connectionType == CONNECTION_TYPE_SSL) {
    getHandshakeHostHelper(handshake, &middlewareServer->ssl);
  } else if (connectionType == CONNECTION_TYPE_PLAIN) {
    getHandshakeHostHelper(handshake, &middlewareServer->plain);
  }
}

/**
 * @brief Retrieves the hosts for the Handshake_t object.
 *
 * @param handshake The Handshake_t object to retrieve hosts from.
 */
static void Handshake_GetHosts(Handshake_t* handshake) {
  MiddlewareServerType middlewareServerType =
      handshake->tamsResponse.servers.middlewareServerType;
  int fromTamsResponse = 0;

  if (!handshake->handshakeHost.url[0] || handshake->handshakeHost.port == 0) {
    if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_POSVAS) {
      getHandshakeHost(handshake, &handshake->tamsResponse.servers.posvas);
    } else if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_EPMS) {
      getHandshakeHost(handshake, &handshake->tamsResponse.servers.posvas);
    }

    handshake->handshakeHost.connectionType =
        handshake->tamsResponse.servers.connectionType;
    fromTamsResponse = 1;
  }

  if (!handshake->callHomeHost.url[0] || handshake->callHomeHost.port == 0) {
    if (fromTamsResponse) {
      if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_POSVAS) {
        strncpy(handshake->callHomeHost.url,
                handshake->tamsResponse.servers.callhomePosvas.ip,
                sizeof(handshake->callHomeHost.url));
        handshake->callHomeHost.port =
            handshake->tamsResponse.servers.callhomePosvas.port;
      } else if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_EPMS) {
        strncpy(handshake->callHomeHost.url,
                handshake->tamsResponse.servers.callhome.ip,
                sizeof(handshake->callHomeHost.url));
        handshake->callHomeHost.port =
            handshake->tamsResponse.servers.callhome.port;
      }
      handshake->callHomeHost.connectionType =
          handshake->tamsResponse.servers.connectionType;
    } else {
      strncpy(handshake->callHomeHost.url, handshake->handshakeHost.url,
              sizeof(handshake->callHomeHost.url));
      handshake->callHomeHost.port = handshake->handshakeHost.port;
      handshake->callHomeHost.connectionType =
          handshake->handshakeHost.connectionType;
    }
    handshake->callHomeTime = handshake->tamsResponse.servers.callhomeTime;
  }
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
  } else if (platform == PLATFORM_TAMS) {
    bindTams(handshakeInternals);
  }
}

/**
 * @brief Runs the handshake process.
 *
 * @param handshake A pointer to the Handshake_t struct.
 */
static void Handshake_Run(Handshake_t* handshake) {
  handshake->error.code = ERROR_CODE_HANDSHAKE_RUN_ERROR;
  HandshakeOperations handshakeInternals;

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
  if (handshake->operations & HANDSHAKE_OPERATIONS_EFT_TOTAL) {
    check(handshakeInternals.getEftTotal(handshake) == EXIT_SUCCESS,
          "Error Getting EFT Total");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_CAPK) {
    check(handshakeInternals.getCapk(handshake) == EXIT_SUCCESS,
          "Error Getting CAPK");
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

  if (handshake->mapDevice == HANDSHAKE_MAP_DEVICE_TRUE) {
    Handshake_MapDevice(handshake);
    check(handshake->error.code == ERROR_CODE_NO_ERROR,
          "Handshake Map Device Error");
  }

  Handshake_GetHosts(handshake);
  debug("Handshake host: %s:%d", handshake->handshakeHost.url,
        handshake->handshakeHost.port);
  debug("Callhome host: %s:%d", handshake->callHomeHost.url,
        handshake->callHomeHost.port);

  Handshake_Run(handshake);
error:
  return;
}
