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
#include <fcntl.h>

#include <stern/stun.h>
#include <stern/turn.h>

#include "config.h"
#include "const.h"
#include "internal.h"

#define CLIENT_TIMEOUT 120

struct stun_client;
struct stun_server;
struct turn_client;
struct turn_server;
struct sternd;

struct stun_clientstate_tcp {
    int sock;
    struct event ev_read, ev_write;
    struct buffer wbuf, rbuf;
};

struct stun_clientstate_udp {
};

struct stun_client {
    struct stun_server *server;
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
    struct sternd *sternd;
    int sock;
    int protocol;
    struct sockaddr addr;
    union {
        struct stun_serverstate_tcp tcp;
        struct stun_serverstate_udp udp;
    } s;
    LIST_HEAD(stun_clients, stun_client) clients;
};

struct turn_clientstate_tcp {
    int sock;
    struct buffer wbuf, rbuf;
    struct event ev_read, ev_write;
};

struct turn_channelstate_tcp {
    int sock;
    int shut_rd, shut_rd_pending, shut_wr, shut_wr_pending;
    struct buffer wbuf, rbuf;
    struct event ev_read, ev_write;
};

struct turn_permission {
    struct turn_client *client;
    struct sockaddr addr;
    LIST_ENTRY(turn_permission) entries;
};

struct turn_channel {
    struct turn_client *client;
    int protocol;
    struct sockaddr addr;
    socklen_t slen;
    int num_client, num_self;
    int confirmed_by_self, confirmed_by_client;
    struct turn_permission *permission;
    union {
        struct turn_channelstate_tcp tcp;
    } s;
    LIST_ENTRY(turn_channel) entries;
};

struct turn_client {
    struct turn_server *server;
    struct sockaddr addr;
    int bandwidth;
    int peer;
    int protocol;
    int num_channels;
    int allocated;
    struct event ev_peer;
    time_t expires;
    union {
        struct turn_clientstate_tcp tcp;
    } s;
    LIST_ENTRY(turn_client) entries;
    LIST_HEAD(turn_channels, turn_channel) channels;
    LIST_HEAD(turn_permissions, turn_permission) permissions;
};

struct turn_serverstate_tcp {
    struct event ev_accept;
};

struct turn_server {
    struct sternd *sternd;
    int protocol;
    int sock;
    union {
        struct turn_serverstate_tcp tcp;
    } s;
    LIST_HEAD(turn_clients, turn_client) clients;
};

struct sternd {
    struct event_base *base;
    struct stun_server stuntcp, stunudp;
    struct turn_server turntcp;
};

extern struct sternd sternd;

int stun_cannot_comprehend(struct stun_message *req);

void sternd_init();
int sternd_set_stun_socket(int transport, int socket, int port);
int sternd_set_turn_socket(int transport, int socket, int port);
void sternd_set_stun_timeout(int s, int us);
void sternd_dispatch();
void sternd_loop();
void sternd_turn_quit();
void sternd_stun_quit();
void sternd_quit();

#endif
