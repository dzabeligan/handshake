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
#include "../dbg.h"

#include "../inc/handshake_internals.h"

static short getMasterKey(void* vHandshake)
{
    (void)vHandshake;
    debug("\n\nMASTER");
    return 0;
}

static short getSessionKey(void* vHandshake)
{
    (void)vHandshake;
    debug("\n\nSESSION");
    return 0;
}

static short getPinKey(void* vHandshake)
{
    (void)vHandshake;
    debug("\n\nPIN");
    return 0;
}

static short getParameter(void *vHandshake)
{
    (void)vHandshake;
    debug("\n\nPARAMETER");
    return EXIT_SUCCESS;
}

void bindTams(Handshake_t* handshake)
{
    handshake->getMasterKey = getMasterKey;
    handshake->getSessionKey = getSessionKey;
    handshake->getPinKey = getPinKey;
    handshake->getParameter = getParameter;
}