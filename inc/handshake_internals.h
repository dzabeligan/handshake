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

void bindNibss(Handshake_t* handshake);

void Handshake_MapTid(Handshake_t* handshake);

#ifdef __cplusplus
}
#endif

#endif
