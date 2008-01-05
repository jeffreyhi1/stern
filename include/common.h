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
#ifndef __COMMON_H
#define __COMMON_H

#include <assert.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "stun.h"

#define STUN_MAGIC                0x2112A442
#define STUN_FINGERPRINT_MAGIC    0x5354554e
#define STUN_HLEN                 20
#define STUN_AHLEN                4
#define STUN_XIDLEN               12
#define STUN_COMPREHENSION_REQD   0x7fff

#define ATTR_RESERVED             0x0000
#define ATTR_MAPPED_ADDRESS       0x0001
#define ATTR_USERNAME             0x0006
#define ATTR_MESSAGE_INTEGRITY    0x0008
#define ATTR_ERROR_CODE           0x0009
#define ATTR_UNKNOWN_ATTRIBUTES   0x000A
#define ATTR_REALM                0x0014
#define ATTR_NONCE                0x0015
#define ATTR_XOR_MAPPED_ADDRESS   0x0020

#define ATTR_REQUESTED_TRANSPORT  0x0019
#define ATTR_CHANNEL_NUMBER       0x000C
#define ATTR_LIFETIME             0x000D
#define ATTR_BANDWIDTH            0x0010
#define ATTR_PEER_ADDRESS         0x0012
#define ATTR_DATA                 0x0013
#define ATTR_RELAY_ADDRESS        0x0016
#define ATTR_REQUESTED_PORT_PROPS 0x0018
#define ATTR_REQUESTED_TRANSPORT  0x0019
#define ATTR_REQUESTED_IP         0x0022
#define ATTR_CONNECT_STATUS       0x0023

#define ATTR_SERVER               0x8022
#define ATTR_FINGERPRINT          0x8028

#define STUN_SUCCESS              0x0100
#define STUN_ERROR                0x0110

#define TURN_ALLOCATION_REQUEST   0x0003
#define TURN_ALLOCATION_SUCCESS   0x0103
#define TURN_ALLOCATION_ERROR     0x0113

#define TURN_REFRESH_REQUEST      0x0004
#define TURN_REFRESH_SUCCESS      0x0104
#define TURN_REFRESH_ERROR        0x0114

#define TURN_LISTEN_REQUEST       0x0008
#define TURN_LISTEN_SUCCESS       0x0108
#define TURN_LISTEN_ERROR         0x0118

#define TURN_CONNECT_REQUEST      0x0007
#define TURN_CONNECT_SUCCESS      0x0107
#define TURN_CONNECT_ERROR        0x0117

#define TURN_SEND_INDICATION      0x0016
#define TURN_DATA_INDICATION      0x0017
#define TURN_CONN_STAT_INDICATION 0x0019
#define TURN_CHAN_CONF_INDICATION 0x0019

#define TURN_CONNSTAT_LISTEN      0x0000
#define TURN_CONNSTAT_ESTABLISHED 0x0001
#define TURN_CONNSTAT_CLOSED      0x0002

#define STUN_ADDR_IP4             1
#define STUN_ADDR_IP6             2

#define TURN_TRANSPORT_UDP        0
#define TURN_TRANSPORT_TCP        1

#define PAD4(x)                    (((x) + 3) & ~0x3)

#define IS_REQUEST(msg_type)       (((msg_type) & 0x0110) == 0x0000)
#define IS_INDICATION(msg_type)    (((msg_type) & 0x0110) == 0x0010)
#define IS_SUCCESS_RESP(msg_type)  (((msg_type) & 0x0110) == 0x0100)
#define IS_ERR_RESP(msg_type)      (((msg_type) & 0x0110) == 0x0110)

#define BUFFER_MIN     256
#define BUFFER_MAX     8192

struct buffer {
    size_t len, pos;
    void *bytes;
};

static inline void *s_malloc(size_t len)
{
    void *ptr = malloc(len);
    assert(ptr);
    return ptr;
}

static inline void *s_realloc(void *ptr, size_t len)
{
    ptr = realloc(ptr, len);
    assert(ptr);
    return ptr;
}

static inline void s_free(void *ptr)
{
    free(ptr);
}

typedef struct stun_message *(stun_responder)(struct stun_message *, struct sockaddr *, void *);


void *stun_tcp_init();
void *stun_tcp_adopt(int sock, stun_responder *fn, void *arg);
void stun_tcp_stop(void *arg);
void *stun_udp_init();
const char *stun_error_reason(int error_code);
int stun_cannot_comprehend(struct stun_message *req);

#endif
