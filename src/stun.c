/**
 * Copyright (C) 2007 Saikat Guha <saikat@cs.cornell.edu>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <syslog.h>
#include <stdio.h>
#include "common.h"

static char *server = "sternd/1.0";
static char *realm = NULL;

//------------------------------------------------------------------------------
static char *
format_addr(char *buf, size_t len, struct sockaddr *addr)
{
    char ipbuf[64];
    struct sockaddr_in *sin = (struct sockaddr_in *) addr;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) addr;

    if (addr->sa_family == AF_INET) {
        snprintf(buf, len, "%s:%d",
                 inet_ntop(AF_INET, &sin->sin_addr, ipbuf, sizeof(ipbuf)),
                 ntohs(sin->sin_port));
    } else if (addr->sa_family == AF_INET6) {
        snprintf(buf, len, "%s/%d",
                 inet_ntop(AF_INET6, &sin6->sin6_addr, ipbuf, sizeof(ipbuf)),
                 ntohs(sin6->sin6_port));
    } else {
        snprintf(buf, sizeof(buf), "<unknown>");
    }
    buf[len - 1] = '\0';
    return buf;
}

//------------------------------------------------------------------------------
const char *
stun_error_reason(int error_code)
{
    switch (error_code) {
        case 300: return "Try Alternate";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 420: return "Unknown Attribute";
        case 430: return "Stale Credentials";
        case 431: return "Integrity Check Failure";
        case 432: return "Missing Username";
        case 433: return "Use TLS";
        case 434: return "Missing Realm";
        case 435: return "Missing Nonce";
        case 436: return "Unknown Username";
        case 437: return "Allocation Mismatch";
        case 438: return "Stale Nonce";
        case 442: return "Unsupported Transport Protocol";
        case 443: return "Invalid IP Address";
        case 444: return "Invalid Port";
        case 445: return "Operation for TCP Only";
        case 446: return "Connection Already Exists";
        case 486: return "Allocation Quota Reached";
        case 500: return "Server Error";
        case 507: return "Insufficient Capacity";
        case 600: return "Global Failure";
        default:  return "Internal error";
    }
}

//------------------------------------------------------------------------------
struct stun_message *
stun_init_response(int type, struct stun_message *req)
{
    struct stun_message *resp;
    int i, nunk = 0;

    resp = stun_new(type);

    /* Xact ID */
    memcpy(resp->xact_id, req->xact_id, STUN_XIDLEN);

    /* Server */
    resp->server = strdup(server);

    /* Unknown Attributes */
    if (req->other) {
        for (i = 0; req->other[i].type; i++) {
            if (req->other[i].is_unknown) {
                resp->unknown_attributes = (int *) s_realloc(
                        resp->unknown_attributes,
                        (++nunk + 1) * sizeof(int));
                resp->unknown_attributes[nunk-1] = req->other[i].type;
                resp->unknown_attributes[nunk] = 0;
            }
        }
    }

    /* Message integrity */
    if (req->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED) {
        resp->message_integrity = STUN_ATTR_PRESENT;
        if (req->_password) {
            resp->_password_length = req->_password_length;
            resp->_password = s_malloc(resp->_password_length);
            memcpy(resp->_password, req->_password, resp->_password_length);
        }
    }

    /* Fingerprint */
    if (req->fingerprint)
        resp->fingerprint = STUN_ATTR_PRESENT;

    return resp;
}

//------------------------------------------------------------------------------
static struct stun_message *
make_binding_response(struct stun_message *req, struct sockaddr *addr)
{
    struct stun_message *resp;
    char buf[64];

    /* Init response */
    resp = stun_init_response(req->message_type | STUN_RESPONSE, req);

    /* Mapped address */
    resp->mapped_address = s_malloc(sizeof(struct sockaddr));
    memcpy(resp->mapped_address, addr, sizeof(struct sockaddr));

    /* Xor-mapped address */
    resp->xor_mapped_address = s_malloc(sizeof(struct sockaddr));
    memcpy(resp->xor_mapped_address, addr, sizeof(struct sockaddr));

    syslog(LOG_INFO, "Binding response for %s%s%s%s%s%s",
           format_addr(buf, sizeof(buf), addr),
           req->username || req->realm ? " (" : "",
           req->username ? req->username : "",
           req->realm ? "@" : "",
           req->realm ? req->realm : "",
           req->username || req->realm ? ")" : "");

    return resp;
}

//------------------------------------------------------------------------------
static struct stun_message *
make_error_response(struct stun_message *req, struct sockaddr *addr, int error)
{
    struct stun_message *resp;
    char buf[64];

    /* Init response */
    resp = stun_init_response(req->message_type | STUN_ERROR, req);

    /* Error */
    resp->error_code = error;

    syslog(LOG_INFO, "Error response %d for %s", error,
           format_addr(buf, sizeof(buf), addr));

    return resp;
}

//------------------------------------------------------------------------------
int
stun_cannot_comprehend(struct stun_message *req)
{
    int i;

    if (req->other)
        for (i = 0; req->other[i].type; i++)
            if (req->other[i].is_unknown &&
                req->other[i].type <= STUN_COMPREHENSION_REQD)
                return 1;
    return 0;
}

//------------------------------------------------------------------------------
struct stun_message *
stun_respond_to(struct stun_message *req, struct sockaddr *addr)
{
    /* Ensure request */
    if (!IS_REQUEST(req->message_type))
        return NULL;

    /* Check figerprint when present */
    if (req->fingerprint == STUN_ATTR_PRESENT_BUT_INVALID)
        return make_error_response(req, addr, 400);

    /* Check integrity when present */
    if (req->message_integrity == STUN_ATTR_PRESENT_BUT_INVALID
        || req->message_integrity == STUN_ATTR_PRESENT)
        return make_error_response(req, addr, 431);

    /* Any comprehension-reqd attributes? */
    if (stun_cannot_comprehend(req))
        return make_error_response(req, addr, 420);

    /* Generate binding response */
    if (req->message_type == STUN_BINDING_REQUEST)
        return make_binding_response(req, addr);

    /* Catch all error */
    return make_error_response(req, addr, 500);
}

//------------------------------------------------------------------------------
void
stun_free(struct stun_message *stun)
{
    int i;

    if (stun->error_reason)
        s_free(stun->error_reason);
    if (stun->username)
        s_free(stun->username);
    if (stun->realm)
        s_free(stun->realm);
    if (stun->server)
        s_free(stun->server);
    if (stun->mapped_address)
        s_free(stun->mapped_address);
    if (stun->xor_mapped_address)
        s_free(stun->xor_mapped_address);
    if (stun->alternate_address)
        s_free(stun->alternate_address);
    if (stun->unknown_attributes)
        s_free(stun->unknown_attributes);
    if (stun->peer_address)
        s_free(stun->peer_address);
    if (stun->relay_address)
        s_free(stun->relay_address);
    if (stun->requested_ip_port)
        s_free(stun->requested_ip_port);
    if (stun->data)
        s_free(stun->data);
    if (stun->_password)
        s_free(stun->_password);
    if (stun->other) {
        for (i = 0; stun->other[i].type; i++) {
            if (stun->other[i].value)
                s_free(stun->other[i].value);
        }
        s_free(stun->other);
    }

    s_free(stun);
}

//------------------------------------------------------------------------------
struct stun_message *
stun_new(int type)
{
    struct stun_message *stun;
    int i;

    stun = s_malloc(sizeof(struct stun_message));
    memset(stun, 0, sizeof(struct stun_message));

    // Fields where 0 is a valid value
    stun->channel = -1;
    stun->requested_transport = -1;
    stun->lifetime = -1;
    stun->requested_port_align = -1;
    stun->connect_status = -1;

    stun->message_type = type;
    for (i = 0; i < STUN_XIDLEN; i++)
        stun->xact_id[i] = rand() & 0xFF;
    return stun;
}

//------------------------------------------------------------------------------
int
stun_set_sockaddr(struct stun_message *stun, int attr, struct sockaddr *addr, socklen_t len)
{
    struct sockaddr **saddr;

    switch (attr) {
        case ATTR_MAPPED_ADDRESS: saddr = &stun->mapped_address; break;
        case ATTR_XOR_MAPPED_ADDRESS: saddr = &stun->xor_mapped_address; break;
        case ATTR_RELAY_ADDRESS: saddr = &stun->relay_address; break;
        case ATTR_PEER_ADDRESS: saddr = &stun->peer_address; break;
        default: return -1;
    }

    *saddr = s_malloc(len);
    memcpy(*saddr, addr, len);
    return 0;
}

//------------------------------------------------------------------------------
int
stun_xid_matches(struct stun_message *a, struct stun_message *b)
{
    return (memcmp(a->xact_id, b->xact_id, STUN_XIDLEN) == 0);
}

//------------------------------------------------------------------------------
int
stun_is_ok_response(struct stun_message *response, struct stun_message *request)
{
    if (!response || !IS_SUCCESS_RESP(response->message_type))
        return 0;
    if (!stun_xid_matches(response, request))
        return 0;
    return 1;
}
