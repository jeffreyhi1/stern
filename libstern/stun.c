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
#include "libstern.h"

static char *server = "sternd/1.0";

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

    /* Init response */
    resp = stun_init_response(req->message_type | STUN_SUCCESS, req);

    /* Mapped address */
    resp->mapped_address = s_malloc(sizeof(struct sockaddr));
    memcpy(resp->mapped_address, addr, sizeof(struct sockaddr));

    /* Xor-mapped address */
    resp->xor_mapped_address = s_malloc(sizeof(struct sockaddr));
    memcpy(resp->xor_mapped_address, addr, sizeof(struct sockaddr));

    return resp;
}

//------------------------------------------------------------------------------
static struct stun_message *
make_error_response(struct stun_message *req, struct sockaddr *addr, int error)
{
    struct stun_message *resp;

    /* Init response */
    resp = stun_init_response(req->message_type | STUN_ERROR, req);

    /* Error */
    resp->error_code = error;

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
int
stun_xid_matches(struct stun_message *a, struct stun_message *b)
{
    return (memcmp(a->xact_id, b->xact_id, STUN_XIDLEN) == 0);
}

//------------------------------------------------------------------------------
int
stun_is_ok_response(struct stun_message *response, struct stun_message *request)
{
    if (!response)
        return 0;
    if (!stun_xid_matches(response, request))
        return 0;
    if (response->message_type != (response->message_type | STUN_SUCCESS))
        return 0;
    return 1;
}

//------------------------------------------------------------------------------
int
stun_is_err_response(struct stun_message *response, struct stun_message *request)
{
    if (!response)
        return 0;
    if (!stun_xid_matches(response, request))
        return 0;
    if (response->message_type != (response->message_type | STUN_ERROR))
        return 0;
    return 1;
}

//------------------------------------------------------------------------------
void
stun_set_data(struct stun_message *stun, char *buf, size_t len)
{
    if (stun->data)
        s_free(stun->data);
    stun->data = s_malloc(len);
    memcpy(stun->data, buf, len);
    stun->data_len = len;
}

//------------------------------------------------------------------------------
void
stun_set_mapped_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len)
{
    if (stun->mapped_address)
        s_free(stun->mapped_address);
    stun->mapped_address = s_malloc(len);
    memcpy(stun->mapped_address, addr, len);
}

//------------------------------------------------------------------------------
void
stun_set_xor_mapped_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len)
{
    if (stun->xor_mapped_address)
        s_free(stun->xor_mapped_address);
    stun->xor_mapped_address = s_malloc(len);
    memcpy(stun->xor_mapped_address, addr, len);
}

//------------------------------------------------------------------------------
void
stun_set_peer_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len)
{
    if (stun->peer_address)
        s_free(stun->peer_address);
    stun->peer_address = s_malloc(len);
    memcpy(stun->peer_address, addr, len);
}

//------------------------------------------------------------------------------
void
stun_set_relay_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len)
{
    if (stun->relay_address)
        s_free(stun->relay_address);
    stun->relay_address = s_malloc(len);
    memcpy(stun->relay_address, addr, len);
}
