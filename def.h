/**
 * @file def.h
 * @author Elijah Balogun (elijah.balogun@cyberpay.net.ng)
 * @brief
 * @version 0.1
 * @date 2024-03-15
 *
 * @copyright Copyright (c) 2024
 *
 */

#ifndef __EFT_DEF_INCLUDED__
#define __EFT_DEF_INCLUDED__

#include <stdarg.h>
#include <stdlib.h>

#include "platform/platform.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error Code
 *
 */
typedef enum {
  ERROR_CODE_NO_ERROR,
  ERROR_CODE_ALREADY_INITIALIZED,
  ERROR_CODE_HANDSHAKE_INIT_ERROR,
  ERROR_CODE_HANDSHAKE_MAPTID_ERROR,
  ERROR_CODE_HANDSHAKE_RUN_ERROR,
  ERROR_CODE_HOST_DECISION_ERROR,
  ERROR_CODE_ERROR,
} ErrorCode;

/**
 * @brief error
 * @code: error code
 * @message: error message
 *
 */
typedef struct Error {
  ErrorCode code;
  char message[0x200];
} Error;

typedef enum Platform {
  PLATFORM_NIBSS,
  PLATFORM_MAX,
} Platform;

#ifdef __cplusplus
}
#endif

#endif
