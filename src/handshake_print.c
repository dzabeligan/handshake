/**
 * @file handshake_print.c
 * @author Elijah Balogun (elijah.balogun@iisysgroup.com)
 * @brief Implement interface to print Handshake objects
 * @version 0.1
 * @date 2023-02-23
 *
 * @copyright Copyright (c) 2023
 *
 */
#include "../dbg.h"

#include "../inc/handshake.h"

/**
 * @brief Terminal App Type to string
 *
 * @param terminalAppType
 * @return const char*
 */
static const char* terminalAppTypeToString(TerminalAppType terminalAppType)
{
    switch (terminalAppType) {
    case TERMINAL_APP_TYPE_AGENT:
        return "AGENT";
    case TERMINAL_APP_TYPE_MERCHANT:
        return "MERCHANT";
    case TERMINAL_APP_TYPE_CONVERTED:
        return "CONVERTED";
    case TERMINAL_APP_TYPE_UNKNOWN:
        return "UNKOWN";
    default:
        return "";
    }
}

/**
 * @brief Middleware server type to string
 *
 * @param middlewareServerType
 * @return const char*
 */
static const char* middlewareServerTypeToString(
    MiddlewareServerType middlewareServerType)
{
    switch (middlewareServerType) {
    case MIDDLEWARE_SERVER_TYPE_POSVAS:
        return "POSVAS";
    case MIDDLEWARE_SERVER_TYPE_EPMS:
        return "EPMS";
    case MIDDLEWARE_SERVER_TYPE_UNKNOWN:
        return "UNKOWN";
    default:
        return "";
    }
}

/**
 * @brief Log TAMS Response Terminals
 *
 * @param tamsResponse
 */
void logTerminals(TAMSResponse* tamsResponse)
{
    debug("AMP:                           %s", tamsResponse->terminals.amp);
    debug("MOREFUN:                       %s", tamsResponse->terminals.moreFun);
    debug("NEWLAND:                       %s", tamsResponse->terminals.newLand);
    debug("NEWPOS:                        %s", tamsResponse->terminals.newPos);
    debug("NEXGO:                         %s", tamsResponse->terminals.nexGo);
    debug("PAX:                           %s", tamsResponse->terminals.pax);
    debug(
        "PAYSHARP:                      %s", tamsResponse->terminals.paySharp);
    debug(
        "VERIFONE:                      %s", tamsResponse->terminals.verifone);
}

/**
 * @brief Log TAMS Response Servers
 *
 * @param tamsResponse
 */
void logServers(TAMSResponse* tamsResponse)
{
    debug("Middleware server type:        %s",
        middlewareServerTypeToString(
            tamsResponse->servers.middlewareServerType));
    debug("Connection Type:               %s",
        tamsResponse->servers.connectionType == CONNECTION_TYPE_PLAIN ? "PLAIN"
                                                                      : "SSL");
    debug("TAMS Public IP:                %s", tamsResponse->servers.tams.ip);
    debug("EPMS Plain Public IP:          %s",
        tamsResponse->servers.epms.plain.publicServer.ip);
    debug("EPMS Plain Public Port:        %d",
        tamsResponse->servers.epms.plain.publicServer.port);
    debug("EPMS Plain Private IP:         %s",
        tamsResponse->servers.epms.plain.privateServer.ip);
    debug("EPMS Plain Private Port:       %d",
        tamsResponse->servers.epms.plain.privateServer.port);
    debug("EPMS SSL Public IP:            %s",
        tamsResponse->servers.epms.ssl.publicServer.ip);
    debug("EPMS SSL Public Port:          %d",
        tamsResponse->servers.epms.ssl.publicServer.port);
    debug("EPMS SSL Private IP:           %s",
        tamsResponse->servers.epms.ssl.privateServer.ip);
    debug("EPMS SSL Private Port:         %d",
        tamsResponse->servers.epms.ssl.privateServer.port);
    debug("POSVAS Plain Public IP:        %s",
        tamsResponse->servers.posvas.plain.publicServer.ip);
    debug("POSVAS Plain Public Port:      %d",
        tamsResponse->servers.posvas.plain.publicServer.port);
    debug("POSVAS Plain Private IP:       %s",
        tamsResponse->servers.posvas.plain.privateServer.ip);
    debug("POSVAS Plain Private Port:     %d",
        tamsResponse->servers.posvas.plain.privateServer.port);
    debug("POSVAS SSL Public IP:          %s",
        tamsResponse->servers.posvas.ssl.publicServer.ip);
    debug("POSVAS SSL Public Port:        %d",
        tamsResponse->servers.posvas.ssl.publicServer.port);
    debug("POSVAS SSL Private IP:         %s",
        tamsResponse->servers.posvas.ssl.privateServer.ip);
    debug("POSVAS SSL Private Port:       %d",
        tamsResponse->servers.posvas.ssl.privateServer.port);
    debug("Remote Upgrade Public IP:      %s",
        tamsResponse->servers.remoteUpgrade.publicServer.ip);
    debug("Remote Upgrade Private IP:     %s",
        tamsResponse->servers.remoteUpgrade.publicServer.ip);
    debug(
        "Call Home Public IP:           %s", tamsResponse->servers.callhome.ip);
    debug("Call Home Public Port:         %d",
        tamsResponse->servers.callhome.port);
    debug("Call Home POSVAS Public IP:    %s",
        tamsResponse->servers.callhomePosvas.ip);
    debug("Call Home POSVAS Public Port:  %d",
        tamsResponse->servers.callhomePosvas.port);
    debug("Call Home Time:                %d",
        tamsResponse->servers.callhomeTime);
    debug("VAS URL:                       %s", tamsResponse->servers.vasUrl);
}

/**
 * @brief Log TAMS Response
 *
 * @param tamsResponse
 */
void logTamsResponse(TAMSResponse* tamsResponse)
{
    debug("Account to Debit:              %s", tamsResponse->accountToDebit);
    debug("Account Number:                %s", tamsResponse->accountNumber);
    debug("Account Selection Type:        %d",
        tamsResponse->accountSelectionType);
    debug("Aggregator Name:               %s", tamsResponse->aggregatorName);
    debug("Balance:                       %s", tamsResponse->balance);
    debug("Commission:                    %s", tamsResponse->commision);
    debug("Email:                         %s", tamsResponse->email);
    debug("Merchant Address:              %s", tamsResponse->merchantAddress);
    debug("Merchant Name:                 %s", tamsResponse->merchantName);
    debug("Notification ID:               %s", tamsResponse->notificationId);
    debug("Phone:                         %s", tamsResponse->phone);
    debug("POS Support:                   %s", tamsResponse->posSupport);
    debug("Pre Connect:                   %s", tamsResponse->preConnect);
    debug("RRN:                           %s", tamsResponse->rrn);
    debug("Stamp Duty:                    %s", tamsResponse->stampDuty);
    debug(
        "Stamp Duty Threshold:          %s", tamsResponse->stampDutyThreshold);
    debug("Stamp Label:                   %s", tamsResponse->stampLabel);
    debug("Terminal App Type:             (%d) %s",
        tamsResponse->terminalAppType,
        terminalAppTypeToString(tamsResponse->terminalAppType));
    debug("User ID:                       %s", tamsResponse->userId);

    logTerminals(tamsResponse);
    logServers(tamsResponse);
}

void logKey(Key* key, const char* title)
{
    debug("%s", title);
    debug("Key:                           %s", key->key);
    debug("KCV:                           %s", key->kcv);

}

void logParameter(Parameters* parameters)
{
    debug("Call Home Time:                %s", parameters->callHomeTime);
    debug("Card Acceptor ID:              %s", parameters->cardAcceptorID);
    debug("Country Code:                  %s", parameters->countryCode);
    debug("Currency Code:                 %s", parameters->currencyCode);
    debug("Merchant Category Code:        %s", parameters->merchantCategoryCode);
    debug("Merchant Name and Location:    %s", parameters->merchantNameAndLocation);
    debug("Server Date and Time:          %s", parameters->serverDateAndTime);
    debug("Timeout:                       %s", parameters->timeout);

}

void logNetworkManagementResponse(NetworkManagementResponse* networkManagementResponse)
{
    debug("Response Code:                 %s", networkManagementResponse->responseCode);
    logKey(&networkManagementResponse->master, "MASTER KEY");
    logKey(&networkManagementResponse->session, "SESSION KEY");
    logKey(&networkManagementResponse->pin, "PIN KEY");
    logParameter(&networkManagementResponse->parameters);
}
