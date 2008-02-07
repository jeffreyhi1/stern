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
#include <sys/queue.h>

#include "sternd.h"

struct server;

struct serverstate_tcp {
    struct event ev_accept;
    struct timeval *client_timeout;
};

struct serverstate_udp {
    struct event ev_recv;
};

struct clientstate_tcp {
    int clisock;
    struct event ev_read, ev_write;
    struct buffer request, response;
};

struct clientstate_udp {
};

struct client {
    struct server *server;
    struct sockaddr addr;
    union {
        struct clientstate_tcp tcp;
        struct clientstate_udp udp;
    } s;
    LIST_ENTRY(client) entries;
};

struct server {
    int protocol;
    int srvsock;
    int closing;
    struct sockaddr_in addr;
    union {
        struct serverstate_tcp tcp;
        struct serverstate_udp udp;
    } s;
    LIST_HEAD(clients, client) clients;
};

static struct timeval timeout = { CLIENT_TIMEOUT, 0 };

//------------------------------------------------------------------------------
static void
server_free(struct server *server)
{
    assert(LIST_EMPTY(&server->clients));

    if (server->srvsock != -1) {
        close(server->srvsock);
        if (server->protocol == IPPROTO_TCP)
            event_del(&server->s.tcp.ev_accept);
        else if (server->protocol == IPPROTO_UDP)
            event_del(&server->s.udp.ev_recv);
    }
    s_free(server);
}

//------------------------------------------------------------------------------
static void
client_free(struct client *client)
{
    if (client->server->protocol == IPPROTO_TCP) {
        if (client->s.tcp.clisock != -1)
            close(client->s.tcp.clisock);
        event_del(&client->s.tcp.ev_read);
        event_del(&client->s.tcp.ev_write);
        b_reset(&client->s.tcp.request);
        b_reset(&client->s.tcp.response);
    } else if (client->server->protocol == IPPROTO_UDP) {
    }

    LIST_REMOVE(client, entries);
    if (LIST_EMPTY(&client->server->clients) && client->server->closing)
        server_free(client->server);

    s_free(client);
}

//------------------------------------------------------------------------------
static void
client_set_events(struct client *client)
{
    assert(client->server->protocol == IPPROTO_TCP);

    if (!b_is_empty(&client->s.tcp.response))
        event_add(&client->s.tcp.ev_write, client->server->s.tcp.client_timeout);
    else
        event_add(&client->s.tcp.ev_read, client->server->s.tcp.client_timeout);
}

//------------------------------------------------------------------------------
static void
client_expand_write_buffer(struct client *client)
{
    b_grow(&client->s.tcp.response);
}

//------------------------------------------------------------------------------
static struct stun_message *
stun_default_responser(struct stun_message *request, struct sockaddr *addr)
{
    return stun_respond_to(request, addr);
}

//------------------------------------------------------------------------------
static void
client_queue_response(struct client *client, struct stun_message *request)
{
    int ret;
    void *wbuf;
    size_t wlen;
    struct stun_message *response;
    struct clientstate_tcp *state = &client->s.tcp;

    if (client->server->closing)
        return;
    response = stun_default_responser(request, &client->addr);
    if (response) {
        ret = -1;
        do {
            if (state->response.len == 0
                || state->response.len - state->response.pos < BUFFER_MIN)
                client_expand_write_buffer(client);
            wbuf = state->response.bytes + state->response.pos;
            wlen = state->response.len - state->response.pos;
            ret = stun_to_bytes(wbuf, wlen, response);
        } while (ret == -1);
        if (ret != -1)
            state->response.pos += ret;
        stun_free(response);
    }
}

//------------------------------------------------------------------------------
static void
client_process_requests(struct client *client)
{
    int processed;
    size_t rlen;
    void *rbuf;
    struct stun_message *request;
    struct clientstate_tcp *state = &client->s.tcp;

    /* Process requests */
    rbuf = state->request.bytes;
    do {
        processed = 0;
        rlen = state->request.pos - (rbuf - state->request.bytes);
        request = stun_from_bytes(rbuf, &rlen);
        if (request) {
            rbuf += rlen;
            processed = 1;
            client_queue_response(client, request);
            stun_free(request);
        }
    } while (processed);

    /* Shrink buffers */
    b_shrink(&state->request);
}

//------------------------------------------------------------------------------
static int
client_read(struct client *client)
{
    int ret;
    struct clientstate_tcp *state = &client->s.tcp;
    void *buf = state->request.bytes + state->request.pos;
    size_t len = state->request.len - state->request.pos;

    ret = read(client->s.tcp.clisock, buf, len);
    if (ret <= 0) {
        client_free(client);
        return -1;
    }
    state->request.pos += ret;
    return 0;
}

//------------------------------------------------------------------------------
static void
client_expand_read_buffer(struct client *client)
{
    b_grow(&client->s.tcp.request);
}

//------------------------------------------------------------------------------
static void
on_client_read(int fd, short ev, void *arg)
{
    struct client *client = (struct client *) arg;

    if (ev == EV_TIMEOUT || client->server->closing) {
        client_free(client);
        return;
    }

    if (client->s.tcp.request.len == 0
        || client->s.tcp.request.len - client->s.tcp.request.pos < BUFFER_MIN)
        client_expand_read_buffer(client);

    if (client_read(client) == -1)
        return;

    client_process_requests(client);

    client_set_events(client);
}

//------------------------------------------------------------------------------
static int
client_write(struct client *client)
{
    int ret;

    ret = write(client->s.tcp.clisock, client->s.tcp.response.bytes, client->s.tcp.response.pos);
    if (ret <= 0) {
        client_free(client);
        return -1;
    }
    b_shrink(&client->s.tcp.response);
    return 0;
}

//------------------------------------------------------------------------------
static void
on_client_write(int fd, short ev, void *arg)
{
    struct client *client = (struct client *) arg;

    if (ev == EV_TIMEOUT || client->server->closing) {
        client_free(client);
        return;
    }

    if (client_write(client) == -1)
        return;

    client_set_events(client);
}

//------------------------------------------------------------------------------
static struct client *
client_new(int fd, struct sockaddr *addr, struct server *server)
{
    struct client *client;
    client = s_malloc(sizeof(struct client));
    memset(client, 0, sizeof(struct client));
    client->server = server;
    LIST_INSERT_HEAD(&server->clients, client, entries);
    client->s.tcp.clisock = fd;
    if (addr)
        client->addr = *addr;
    event_set(&client->s.tcp.ev_read, fd, EV_READ, on_client_read, client);
    event_set(&client->s.tcp.ev_write, fd, EV_WRITE, on_client_write, client);
    client_set_events(client);
    return client;
}

//------------------------------------------------------------------------------
static void
on_srv_accept(int fd, short ev, void *arg)
{
    struct server *server = (struct server *) arg;
    struct client *client;
    struct sockaddr addr;
    int cli;
    socklen_t len = sizeof(addr);

    cli = accept(fd, &addr, &len);
    if (cli == -1)
        return;
    client = client_new(cli, &addr, server);
    if (!client)
        close(cli);
}

//------------------------------------------------------------------------------
static void
on_recv(int fd, short ev, void *arg)
{
    struct server *server = (struct server *) arg;
    struct stun_message *request, *response;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);
    char buf[BUFFER_MAX];
    int ret;

    /* Receive message */
    ret = recvfrom(fd, buf, sizeof(buf), 0, &addr, &len);
    if (ret <= 0) return;

    /* Process request */
    len = ret;
    request = stun_from_bytes(buf, &len);
    if (request) {
        response = stun_respond_to(request, &addr);
        if (response) {
            ret = stun_to_bytes(buf, sizeof(buf), response);
            if (ret > 0)
                sendto(fd, buf, ret, 0, &addr, len);
            stun_free(response);
        }
        stun_free(request);
    }
}

//------------------------------------------------------------------------------
void
stun_tcp_stop(void *arg)
{
    struct server *server = (struct server *) arg;

    server->closing = 1;
    if (LIST_EMPTY(&server->clients))
        server_free(server);
}

//------------------------------------------------------------------------------
static struct server *
server_new(int  fd)
{
    struct server *server;

    server = (struct server *) s_malloc(sizeof(struct server));
    server->srvsock = fd;
    server->closing = 0;
    server->s.tcp.client_timeout = &timeout;
    if (fd != -1) {
        event_set(&server->s.tcp.ev_accept, fd, EV_READ | EV_PERSIST, on_srv_accept, server);
        event_add(&server->s.tcp.ev_accept, NULL);
    }
    return server;
}

//------------------------------------------------------------------------------
void *
stun_tcp_init()
{
    int fd;
    struct sockaddr_in sin;
    static int one = 1;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(PORT_STUN);

    fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *) &sin, sizeof(sin))
        || listen(fd, 5)) {
        close(fd);
        return NULL;
    }

    return server_new(fd);
}

//------------------------------------------------------------------------------
void *
stun_udp_init()
{
    struct server *server;
    static int one = 1;

    server = (struct server *) s_malloc(sizeof(struct server));

    server->addr.sin_family = AF_INET;
    server->addr.sin_addr.s_addr = INADDR_ANY;
    server->addr.sin_port = htons(PORT_STUN);

    server->srvsock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(server->srvsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(server->srvsock, (struct sockaddr *)&server->addr, sizeof(server->addr))) {
        close(server->srvsock);
        s_free(server);
        return NULL;
    }

    event_set(&server->s.udp.ev_recv, server->srvsock, EV_READ|EV_PERSIST, on_recv, server);
    event_add(&server->s.udp.ev_recv, NULL);

    return server;
}
