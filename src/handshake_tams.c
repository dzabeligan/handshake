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

static short getMasterKey(Handshake_t* handshake)
{
    (void)handshake;
    debug("\n\nMASTER");
    return 0;
}

static short getSessionKey(Handshake_t* handshake)
{
    (void)handshake;
    debug("\n\nSESSION");
    return 0;
}

static short getPinKey(Handshake_t* handshake)
{
    (void)handshake;
    debug("\n\nPIN");
    return 0;
}

static short getParameter(Handshake_t *handshake)
{
    (void)handshake;
    debug("\n\nPARAMETER");
    return EXIT_SUCCESS;
}

void bindTams(Handshake_Internals* handshake_internals)
{
    handshake_internals->getMasterKey = getMasterKey;
    handshake_internals->getSessionKey = getSessionKey;
    handshake_internals->getPinKey = getPinKey;
    handshake_internals->getParameters = getParameter;
}
