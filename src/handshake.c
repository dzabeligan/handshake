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

static short checkMapDeviceData(Handshake_t* handshake) {
  return handshake->appInfo.name[0] && handshake->appInfo.version[0] &&
         handshake->deviceInfo.model[0] && handshake->deviceInfo.posUid[0] &&
         handshake->mapDeviceHost.hostUrl[0] &&
         handshake->mapDeviceHost.port != 0;
}

static short validateHandshakeData(Handshake_t* handshake) {
  if (!handshake->comSendReceive ||
      (!((handshake->mapDeviceHost.hostUrl[0] &&
          handshake->mapDevice == HANDSHAKE_MAP_DEVICE_TRUE) ||
         (handshake->handshakeHost.hostUrl[0] &&
          handshake->handshakeHost.port)))) {
    log_err("`comSendReceive` or `hosts` not set");
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "`comSendReceive` or `hosts` not set");
    return EXIT_FAILURE;
  }

  if (handshake->mapDevice == HANDSHAKE_MAP_DEVICE_FALSE &&
      !(handshake->tid[0])) {
    log_err("TID can't be empty when `mapDevice` is false");
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "TID can't be empty when `mapDevice` is false");
    return EXIT_FAILURE;
  }

  if (handshake->mapDevice == HANDSHAKE_MAP_DEVICE_TRUE &&
      !checkMapDeviceData(handshake)) {
    log_err("Map Device `data` or `host` not set");
    snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
             "Map Device `data` or `mapDeviceHost` not set");
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

static void Handshake_Init(Handshake_t* handshake,
                           Handshake_Internals* handshakeInternals) {
  handshake->error.code = ERROR_CODE_HANDSHAKE_INIT_ERROR;

  check(validateHandshakeData(handshake) == EXIT_SUCCESS,
        "Error Validating `handshake`");

  if (handshake->operations == HANDSHAKE_OPERATIONS_NONE) {
    handshake->operations = HANDSHAKE_OPERATIONS_ALL;
  }
  if (handshake->operations == HANDSHAKE_OPERATIONS_ALL) {
    memset(&handshake->tamsResponse, '\0', sizeof(TAMSResponse));
    memset(&handshake->networkManagementResponse, '\0',
           sizeof(NetworkManagementResponse));
  }

  if (handshake->platform == PLATFORM_NIBSS) {
    bindNibss(handshakeInternals);
  } else if (handshake->platform == PLATFORM_TAMS) {
    bindTams(handshakeInternals);
  }

  handshake->error.code = ERROR_CODE_NO_ERROR;
  memset(handshake->error.message, '\0', sizeof(handshake->error.message));
error:
  return;
}

static void getHandshakeHostHelper(Handshake_t* handshake,
                                   PrivatePublicServer* server) {
  SimType simType = handshake->simInfo.simType;

  if (simType == SIM_TYPE_PUBLIC) {
    strncpy(handshake->handshakeHost.hostUrl, server->publicServer.ip,
            sizeof(handshake->handshakeHost.hostUrl));
    handshake->handshakeHost.port = server->publicServer.port;
  } else if (simType == SIM_TYPE_PRIVATE) {
    strncpy(handshake->handshakeHost.hostUrl, server->privateServer.ip,
            sizeof(handshake->handshakeHost.hostUrl));
    handshake->handshakeHost.port = server->privateServer.port;
  }
}

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

static void Handshake_GetHosts(Handshake_t* handshake) {
  MiddlewareServerType middlewareServerType =
      handshake->tamsResponse.servers.middlewareServerType;
  int fromTamsResponse = 0;

  if (!handshake->handshakeHost.hostUrl[0] ||
      handshake->handshakeHost.port == 0) {
    if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_POSVAS) {
      getHandshakeHost(handshake, &handshake->tamsResponse.servers.posvas);
    } else if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_EPMS) {
      getHandshakeHost(handshake, &handshake->tamsResponse.servers.posvas);
    }

    handshake->handshakeHost.connectionType =
        handshake->tamsResponse.servers.connectionType;
    fromTamsResponse = 1;
  }

  if (!handshake->callHomeHost.hostUrl[0] ||
      handshake->callHomeHost.port == 0) {
    if (fromTamsResponse) {
      if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_POSVAS) {
        strncpy(handshake->callHomeHost.hostUrl,
                handshake->tamsResponse.servers.callhomePosvas.ip,
                sizeof(handshake->callHomeHost.hostUrl));
        handshake->callHomeHost.port =
            handshake->tamsResponse.servers.callhomePosvas.port;
      } else if (middlewareServerType == MIDDLEWARE_SERVER_TYPE_EPMS) {
        strncpy(handshake->callHomeHost.hostUrl,
                handshake->tamsResponse.servers.callhome.ip,
                sizeof(handshake->callHomeHost.hostUrl));
        handshake->callHomeHost.port =
            handshake->tamsResponse.servers.callhome.port;
      }
      handshake->callHomeHost.connectionType =
          handshake->tamsResponse.servers.connectionType;
    } else {
      strncpy(handshake->callHomeHost.hostUrl, handshake->handshakeHost.hostUrl,
              sizeof(handshake->callHomeHost.hostUrl));
      handshake->callHomeHost.port = handshake->handshakeHost.port;
      handshake->callHomeHost.connectionType =
          handshake->handshakeHost.connectionType;
    }
    handshake->callHomeHost.receiveTimeout =
        handshake->tamsResponse.servers.callhomeTime;
  }
}

static void Handshake_Run(Handshake_t* handshake,
                          Handshake_Internals* handshakeInternals) {
  handshake->error.code = ERROR_CODE_HANDSHAKE_RUN_ERROR;

  if (handshake->operations & HANDSHAKE_OPERATIONS_MASTER_KEY) {
    check(handshakeInternals->getMasterKey(handshake) == EXIT_SUCCESS,
          "Error Getting Master Key");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_SESSION_KEY) {
    check(handshakeInternals->getSessionKey(handshake) == EXIT_SUCCESS,
          "Error Getting Session Key");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_PIN_KEY) {
    check(handshakeInternals->getPinKey(handshake) == EXIT_SUCCESS,
          "Error Getting PIN Key");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_PARAMETER) {
    check(handshakeInternals->getParameters(handshake) == EXIT_SUCCESS,
          "Error Getting Parameters");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_CALLHOME) {
    check(handshakeInternals->doCallHome(handshake) == EXIT_SUCCESS,
          "Error Doing Call Home");
  }
  if (handshake->operations & HANDSHAKE_OPERATIONS_EFT_TOTAL) {
    check(handshakeInternals->getEftTotal(handshake) == EXIT_SUCCESS,
          "Error Getting EFT Total");
  }

  handshake->error.code = ERROR_CODE_NO_ERROR;
  memset(handshake->error.message, '\0', sizeof(handshake->error.message));
error:
  return;
}

void Handshake(Handshake_t* handshake) {
  Handshake_Internals handshakeInternals;

  Handshake_Init(handshake, &handshakeInternals);
  check(handshake->error.code == ERROR_CODE_NO_ERROR, "Handshake Init Error");

  if (handshake->mapDevice == HANDSHAKE_MAP_DEVICE_TRUE) {
    Handshake_MapDevice(handshake);
    check(handshake->error.code == ERROR_CODE_NO_ERROR,
          "Handshake Map Device Error");
  }

  Handshake_GetHosts(handshake);
  debug("Handshake host: %s:%d", handshake->handshakeHost.hostUrl,
        handshake->handshakeHost.port);
  debug("Callhome host: %s:%d", handshake->callHomeHost.hostUrl,
        handshake->callHomeHost.port);

  Handshake_Run(handshake, &handshakeInternals);
error:
  return;
}
