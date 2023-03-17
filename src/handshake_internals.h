/**
 * @file handshake_internals.h
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
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
#include "../dbg.h"
#include "../des/des.h"
#include "../ezxml/ezxml.h"
#include "../inc/handshake.h"
#include "../platform/utils.h"

/**
 * @brief Function pointer for Network Management operations
 *
 */
typedef short (*GetNetworkManagementData)(Handshake_t* handshake);

/**
 * @brief Data structure for internal objects
 * @getMasterKey: function pointer to get master key
 * @getSessionKey: function pointer to get session key
 * @getPinKey: function pointer to get pin key
 * @getParameters: function pointer to get parameters
 * @doCallHome: function pointer to do call home
 * @getCapk: function pointer to get capk
 * @getEftTotal: function pointer to get eft total
 *
 */
typedef struct Handshake_Internals {
  GetNetworkManagementData getMasterKey;
  GetNetworkManagementData getSessionKey;
  GetNetworkManagementData getPinKey;
  GetNetworkManagementData getParameters;
  GetNetworkManagementData doCallHome;
  GetNetworkManagementData getCapk;
  GetNetworkManagementData getEftTotal;
} Handshake_Internals;

void bindNibss(Handshake_Internals* handshakeInternals);
void bindTams(Handshake_Internals* handshakeInternals);

void Handshake_MapDevice(Handshake_t* handshake);

#ifdef __cplusplus
}
#endif

#endif
