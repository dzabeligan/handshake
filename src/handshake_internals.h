/**
 * @file handshake_internals.h
 * @author Elijah Balogun (elijah.balogun@cyberpay.net.ng)
 * @brief Declares interface for Handshake
 * @version 0.1
 * @date 2023-02-23
 *
 * @copyright Copyright (c) 2023
 *
 */
#ifndef HANDSHAKE_INTERNALS_H
#define HANDSHAKE_INTERNALS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "../c8583/C8583.h"
#include "../c8583/FieldNames.h"
#include "../cJSON/cJSON.h"
#include "../dbg.h"
#include "../des/des.h"
#include "../ezxml/ezxml.h"
#include "../platform/platform.h"
#include "handshake.h"

/**
 * Function pointer type for a function that retrieves network management data
 * for a Handshake_t object. The function should take a pointer to a Handshake_t
 * object as its argument and return a short integer.
 */
typedef short (*GetNetworkManagementData)(Handshake_t* handshake);

/**
 * @brief Struct containing function pointers for retrieving various network
 * management data.
 */
typedef struct HandshakeOperations {
  /**< Function pointer for retrieving the master key. */
  GetNetworkManagementData getMasterKey;
  /**< Function pointer for retrieving the session key. */
  GetNetworkManagementData getSessionKey;
  /**< Function pointer for retrieving the PIN key. */
  GetNetworkManagementData getPinKey;
  /**< Function pointer for retrieving the network parameters. */
  GetNetworkManagementData getParameters;
  /**< Function pointer for performing a call home operation. */
  GetNetworkManagementData doCallHome;
  /**< Function pointer for retrieving the CAPK. */
  GetNetworkManagementData getCapk;
  /**< Function pointer for retrieving the Aid. */
  GetNetworkManagementData getAid;
} HandshakeOperations;

void bindNibss(HandshakeOperations* handshakeInternals);

void Handshake_GetDeviceConfig(Handshake_t* handshake);

#ifdef __cplusplus
}
#endif

#endif
