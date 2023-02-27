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
#include "../platform/utils.h"

#include "../inc/handshake_internals.h"

static short getTamsHash(char* hash, const char* data, const char* key)
{
    char hashdata[500];
    char digest[65] = { '\0' };
    short ret = EXIT_FAILURE;
    char body[1000] = { '\0' };
    char* token = NULL;

    check(data && key, "`data` or `key` can't be NULL");

    memset(body, 0, sizeof(body));
    memset(hashdata, 0, sizeof(hashdata));
    strcpy(body, data);

    token = (char*)strtok(body, "&");

    while (token != NULL) {
        int i = 0;
        int len = strlen(token);

        for (i = 0; i < len; i++) {
            if (token[i] == '=') {
                strcat(hashdata, &token[i + 1]);
                break;
            }
        }

        token = strtok(NULL, "&");
    }

    memset(digest, 0, sizeof(digest));

    get256Hash(digest, sizeof(digest), hashdata, key);
    sprintf(hash, "S%s", digest);

    ret = EXIT_SUCCESS;
error:
    return ret;
}

static int buildTamsHttpRequest(char* requestBuf, size_t bufLen,
    Handshake_t* handshake, char* data, const char* path)
{
    int pos = 0;
    const char* TAMS_POST_VERSION = "8.0.6";
    char hash[0x100] = { '\0' };

    if (data) {
        char key[0x100] = { '\0' };

        // decryptTamsKey(key, handshake->networkManagementResponse.session.key,
        //     handshake->tid, handshake->networkManagementResponse.master.key);
        debug("Clear key: %s", key);
        check(getTamsHash(hash, data, key) == EXIT_SUCCESS,
            "Error Generating TAMS Hash");
    }

    pos += snprintf(
        &requestBuf[pos], bufLen - pos, "POST /%s HTTP/1.1\r\n", path);
    pos += snprintf(&requestBuf[pos], bufLen - pos, "Host: %s:%d\r\n",
        handshake->handshakeHost.hostUrl, handshake->handshakeHost.port);
    pos += snprintf(&requestBuf[pos], bufLen - pos, "User-Agent: lipman/%s\r\n",
        TAMS_POST_VERSION);
    pos += snprintf(
        &requestBuf[pos], bufLen - pos, "Accept: application/xml\r\n");
    pos += snprintf(&requestBuf[pos], bufLen - pos,
        "Content-Type: application/x-www-form-urlencoded\r\n");
    pos += snprintf(
        &requestBuf[pos], bufLen - pos, "Terminal: %s\r\n", handshake->tid);
    pos += snprintf(&requestBuf[pos], bufLen - pos, "EOD: 0\r\n");
    pos += snprintf(&requestBuf[pos], bufLen - pos, "Sign: %s\r\n", hash);
    pos += snprintf(&requestBuf[pos], bufLen - pos,
        "Content-Length: %zu\r\n\r\n%s", data ? strlen(data) : 0,
        data ? data : "");
error:
    return pos;
}

static short parseMasterkeyResponse(Handshake_t* handshake, char* response)
{
    ezxml_t root = NULL;
    ezxml_t masterkey = NULL;
    int ret = EXIT_FAILURE;

    root = ezxml_parse_str(response, strlen(response));
    check_mem(root);
    check(checkTamsError(handshake->error.message,
              sizeof(handshake->error.message) - 1, root)
            == 0,
        "TAMS Error");
    check((masterkey = ezxml_child(root, "masterkey")),
        "Error Getting `masterkey`");

    strncpy((char*)handshake->networkManagementResponse.master.key,
        masterkey->txt,
        sizeof(handshake->networkManagementResponse.master.key));

    ret = EXIT_SUCCESS;
error:
    ezxml_free(root);

    return ret;
}

static short getMasterKey(Handshake_t* handshake)
{
    int len = -1;
    char requestBuf[0x1000] = { '\0' };
    unsigned char responseBuf[0x1000] = { '\0' };
    int ret = EXIT_FAILURE;
    const char* NEW_KEY_PATH = "tams/tams/devinterface/newkey.php";

    debug("MASTER");
    len = buildTamsHttpRequest(
        requestBuf, sizeof(requestBuf) - 1, handshake, NULL, NEW_KEY_PATH);
    check(len > 0, "Error Building TAMS Request");
    debug("Request: '%s'", requestBuf);

    len = handshake->comSendReceive(responseBuf, sizeof(responseBuf) - 1,
        (unsigned char*)requestBuf, sizeof(requestBuf) - 1,
        handshake->handshakeHost.hostUrl, handshake->handshakeHost.port,
        handshake->comSentinel, "</newkey>");
    check(len > 0, "Error sending or receiving request");
    debug("Response: '%s (%d)'", responseBuf, len);

    check(parseMasterkeyResponse(handshake, (char*)responseBuf) == EXIT_SUCCESS,
        "Parse Error");

    ret = EXIT_SUCCESS;
error:
    if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error Getting Master Key");
    }
    return ret;
}

static short parseGetKeysResponse(Handshake_t* handshake, char* response)
{
    ezxml_t root = NULL, cipher = NULL;
    int ret = EXIT_FAILURE;

    root = ezxml_parse_str(response, strlen(response));
    check_mem(root);
    check(checkTamsError(handshake->error.message,
              sizeof(handshake->error.message) - 1, root)
            == 0,
        "TAMS Error");
    check((cipher = ezxml_child(root, "cipher")), "Error Getting `cipher`");

    do {
        ezxml_t number, key;

        check((number = ezxml_child(cipher, "no")), "Error Getting `no`");
        if (strncmp(number->txt, "1", 1) == 0) {
            check((key = ezxml_child(cipher, "key")), "Error Getting `key`");
            strncpy((char*)handshake->networkManagementResponse.session.key,
                key->txt,
                sizeof(handshake->networkManagementResponse.session.key));
        } else if (strncmp(number->txt, "2", 1) == 0) {
            check((key = ezxml_child(cipher, "key")), "Error Getting `key`");
            strncpy((char*)handshake->networkManagementResponse.pin.key,
                key->txt, sizeof(handshake->networkManagementResponse.pin.key));
        }
        cipher = ezxml_next(cipher);
    } while (!handshake->networkManagementResponse.session.key[0]
        || !handshake->networkManagementResponse.pin.key[0]);

    ret = EXIT_SUCCESS;
error:
    ezxml_free(root);

    return ret;
}

static short getSessionKey(Handshake_t* handshake)
{
    int len = -1;
    char requestBuf[0x1000] = { '\0' };
    unsigned char responseBuf[0x1000] = { '\0' };
    int ret = EXIT_FAILURE;
    const char* SESSION_KEY_PATH = "tams/tams/devinterface/getkeys.php";

    debug("SESSION");
    len = buildTamsHttpRequest(
        requestBuf, sizeof(requestBuf) - 1, handshake, NULL, SESSION_KEY_PATH);
    check(len > 0, "Error Building TAMS Request");
    debug("Request: '%s'", requestBuf);

    len = handshake->comSendReceive(responseBuf, sizeof(responseBuf) - 1,
        (unsigned char*)requestBuf, sizeof(requestBuf) - 1,
        handshake->handshakeHost.hostUrl, handshake->handshakeHost.port,
        handshake->comSentinel, "</getkeys>");
    check(len > 0, "Error sending or receiving request");
    debug("Response: '%s (%d)'", responseBuf, len);

    check(parseGetKeysResponse(handshake, (char*)responseBuf) == EXIT_SUCCESS,
        "Parse Error");

    ret = EXIT_SUCCESS;
error:
    if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error Getting Session Keys");
    }
    return ret;
}

static short getPinKey(Handshake_t* handshake)
{
    (void)handshake;
    debug("PIN");
    return EXIT_SUCCESS;
}

static short getParameters(Handshake_t* handshake)
{
    int len = -1;
    char requestBuf[0x1000] = { '\0' };
    unsigned char responseBuf[0x1000] = { '\0' };
    int ret = EXIT_FAILURE;
    char data[0x100] = { '\0' };
    const char* PARAMETERS_PATH = "tams/tams/devinterface/getparams.php";

    debug("PARAMETER");
    snprintf(data, sizeof(data) - 1, "ver=%s&serial=%s",
        handshake->appInfo.version, handshake->deviceInfo.posUid);
    len = buildTamsHttpRequest(
        requestBuf, sizeof(requestBuf) - 1, handshake, data, PARAMETERS_PATH);
    check(len > 0, "Error Building TAMS Request");
    debug("Request: '%s'", requestBuf);

    len = handshake->comSendReceive(responseBuf, sizeof(responseBuf) - 1,
        (unsigned char*)requestBuf, sizeof(requestBuf) - 1,
        handshake->handshakeHost.hostUrl, handshake->handshakeHost.port,
        handshake->comSentinel, "</param>");
    check(len > 0, "Error sending or receiving request");
    debug("Response: '%s (%d)'", responseBuf, len);

    // check(parseGetKeysResponse(handshake, (char*)responseBuf) ==
    // EXIT_SUCCESS,
    //     "Parse Error");

    ret = EXIT_SUCCESS;
error:
    if (ret != EXIT_SUCCESS && !handshake->error.message[0]) {
        snprintf(handshake->error.message, sizeof(handshake->error.message) - 1,
            "Error Getting Session Keys");
    }
    return ret;
}

static short doCallHome(Handshake_t* handshake)
{
    (void)handshake;

    debug("CALL HOME");
    return EXIT_SUCCESS;
}

void bindTams(Handshake_Internals* handshake_internals)
{
    handshake_internals->getMasterKey = getMasterKey;
    handshake_internals->getSessionKey = getSessionKey;
    handshake_internals->getPinKey = getPinKey;
    handshake_internals->getParameters = getParameters;
    handshake_internals->doCallHome = doCallHome;
}
