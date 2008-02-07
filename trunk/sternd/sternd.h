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
#ifndef __STERND_H
#define __STERND_H

#include <netinet/in.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <unistd.h>
#include <event.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <time.h>
#include <stdlib.h>

#include <stern/stun.h>
#include <stern/turn.h>

#include "config.h"
#include "const.h"
#include "internal.h"

#define CLIENT_TIMEOUT 120

struct stun_clientstate_tcp {
    int sock;
    struct event ev_read, ev_write;
    struct buffer request, response;
};

struct stun_clientstate_udp {
};

struct stun_client {
    struct sockaddr addr;
    union {
        struct stun_clientstate_tcp tcp;
        struct stun_clientstate_udp udp;
    } s;
    LIST_ENTRY(stun_client) entries;
};

struct stun_serverstate_tcp {
    struct event ev_accept;
};

struct stun_serverstate_udp {
    struct event ev_recv;
};

struct stun_server {
    int sock;
    struct sockaddr addr;
    union {
        struct stun_serverstate_tcp tcp;
        struct stun_serverstate_udp udp;
    } s;
    LIST_HEAD(stun_clients, stun_client) clients;
};

struct sternd {
    struct stun_server stuntcp, stunudp;
};

extern struct sternd sternd;

void sternd_init();
int sternd_set_stun_socket(int transport, int socket, int port);

#endif
