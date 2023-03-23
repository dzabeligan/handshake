/**
 * @file handshake.h
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Declares interface for Handshake
 * @version 0.1
 * @date 2023-02-07
 *
 * @copyright Copyright (c) 2023
 *
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "../EftDef.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HANDSHAKE_INIT_DATA                                                   \
  {                                                                           \
    {'\0'}, {{'\0'}, {'\0'}}, {{'\0'}, {'\0'}}, {SIM_TYPE_PUBLIC, {'\0'}},    \
        HANDSHAKE_MAP_DEVICE_FALSE, HANDSHAKE_OPERATIONS_ALL, PLATFORM_NIBSS, \
        PTAD_KEY_UNKNOWN, {{'\0'}, 0, CONNECTION_TYPE_PLAIN, 0},              \
        {{'\0'}, 0, CONNECTION_TYPE_PLAIN, 0},                                \
        {{'\0'}, 0, CONNECTION_TYPE_PLAIN, 0},                                \
        {{'\0'},                                                              \
         {{'\0'}, {'\0'}},                                                    \
         {{'\0'}, {'\0'}},                                                    \
         {{'\0'}, {'\0'}},                                                    \
         {0,                                                                  \
          {'\0'},                                                             \
          {'\0'},                                                             \
          {'\0'},                                                             \
          {'\0'},                                                             \
          {'\0'},                                                             \
          0,                                                                  \
          {'\0'},                                                             \
          {'\0'},                                                             \
          {'\0'},                                                             \
          {'\0'},                                                             \
          0,                                                                  \
          {'\0'},                                                             \
          {'\0'}}},                                                           \
        {{'\0'},                                                              \
         {'\0'},                                                              \
         0,                                                                   \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         {'\0'},                                                              \
         TERMINAL_APP_TYPE_UNKNOWN,                                           \
         {'\0'},                                                              \
         {{'\0'}, {'\0'}, {'\0'}, {'\0'}, {'\0'}, {'\0'}, {'\0'}, {'\0'}},    \
         {CONNECTION_TYPE_PLAIN,                                              \
          MIDDLEWARE_SERVER_TYPE_UNKNOWN,                                     \
          {{'\0'}, 0},                                                        \
          {{'\0'}, 0},                                                        \
          {{'\0'}, 0},                                                        \
          0,                                                                  \
          {{{'\0'}, 0}, {{'\0'}, 0}},                                         \
          {{{{'\0'}, 0}, {{'\0'}, 0}}, {{{'\0'}, 0}, {{'\0'}, 0}}},           \
          {{{{'\0'}, 0}, {{'\0'}, 0}}, {{{'\0'}, 0}, {{'\0'}, 0}}},           \
          {'\0'}}},                                                           \
        NULL, NULL, NULL, {                                                   \
      ERROR_CODE_ERROR, { '\0' }                                              \
    }                                                                         \
  }

void logTamsResponse(TAMSResponse* tamsResponse);
void logTerminals(TAMSResponse* tamsResponse);
void logServers(TAMSResponse* tamsResponse);
void logKey(Key* key, const char* title);
void logParameter(Parameters* parameters);
void logNetworkManagementResponse(
    NetworkManagementResponse* networkManagementResponse);

void Handshake(Handshake_t* handshake);

#ifdef __cplusplus
}
#endif

#endif
