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

#include "../inc/handshake.h"

typedef short (*GetNetworkManagementData)(Handshake_t* handshake);

typedef struct Handshake_Internals {
    GetNetworkManagementData getMasterKey;
    GetNetworkManagementData getSessionKey;
    GetNetworkManagementData getPinKey;
    GetNetworkManagementData getParameters;
    GetNetworkManagementData doCallHome;
} Handshake_Internals;

void bindNibss(Handshake_Internals* handshakeInternals);
void bindTams(Handshake_Internals* handshakeInternals);

void Handshake_MapTid(Handshake_t* handshake);

#ifdef __cplusplus
}
#endif

#endif
