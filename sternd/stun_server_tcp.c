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
#include <netinet/in.h>
#include <sys/time.h>
#include <unistd.h>
#include <event.h>

#include "common.h"

#define PORT_STUN      3478
#define CLIENT_TIMEOUT 120

struct server {
    int sock;
    int shut;
    void *cb_arg;
    int nclients;
    struct event ev_accept;
    stun_responder *stun_cb;
    struct timeval *client_timeout;
};

struct client {
    struct server *server;
    int sock;
    struct sockaddr addr;
    struct event ev_read, ev_write;
    struct buffer request, response;
};

static struct timeval timeout = { CLIENT_TIMEOUT, 0 };

//------------------------------------------------------------------------------
int
buffer_expand(struct buffer *buf)
{
    if (buf->len * 2 > BUFFER_MAX) {
        return -1;
    }
    buf->len *= 2;
    if (buf->len == 0)
        buf->len = BUFFER_MIN;
    buf->bytes = s_realloc(buf->bytes, buf->len);
    return 0;
}

//------------------------------------------------------------------------------
void
buffer_collapse(struct buffer *buf, size_t len)
{
    buf->pos -= len;
    if (buf->pos == 0) {
        buf->len = 0;
        s_free(buf->bytes);
        buf->bytes = NULL;
    } else {
        memmove(buf->bytes, buf->bytes + len, buf->pos);
    }
}

//------------------------------------------------------------------------------
static void
on_server_error(struct server *server)
{
    if (server->sock != -1) {
        close(server->sock);
        event_del(&server->ev_accept);
    }
    s_free(server);
}

//------------------------------------------------------------------------------
static void
on_client_error(struct client *client)
{
    close(client->sock);
    event_del(&client->ev_read);
    event_del(&client->ev_write);
    if (client->request.bytes)
        s_free(client->request.bytes);
    if (client->response.bytes)
        s_free(client->response.bytes);
    client->server->nclients--;
    if (client->server->nclients == 0 && client->server->shut)
        on_server_error(client->server);
    s_free(client);
}

//------------------------------------------------------------------------------
static void
client_set_events(struct client *client)
{
    if (client->response.pos > 0)
        event_add(&client->ev_write, client->server->client_timeout);
    else
        event_add(&client->ev_read, client->server->client_timeout);
}

//------------------------------------------------------------------------------
static int
client_expand_write_buffer(struct client *client)
{
    return buffer_expand(&client->response);
}

//------------------------------------------------------------------------------
static void
client_queue_response(struct client *client, struct stun_message *request)
{
    int ret;
    void *wbuf;
    size_t wlen;
    struct stun_message *response;

    if (client->server->shut)
        return;
    response = client->server->stun_cb(request, &client->addr, client->server->cb_arg);
    if (response) {
        ret = -1;
        do {
            if (client->response.len == 0
                || client->response.len - client->response.pos < BUFFER_MIN)
                if (client_expand_write_buffer(client) == -1)
                    break;
            wbuf = client->response.bytes + client->response.pos;
            wlen = client->response.len - client->response.pos;
            ret = stun_to_bytes(wbuf, wlen, response);
        } while (ret == -1);
        if (ret != -1)
            client->response.pos += ret;
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

    /* Process requests */
    rbuf = client->request.bytes;
    do {
        processed = 0;
        rlen = client->request.pos - (rbuf - client->request.bytes);
        request = stun_from_bytes(rbuf, &rlen);
        if (request) {
            rbuf += rlen;
            processed = 1;
            client_queue_response(client, request);
            stun_free(request);
        }
    } while (processed);

    /* Shrink buffers */
    buffer_collapse(&client->request, rbuf - client->request.bytes);
}

//------------------------------------------------------------------------------
static int
client_read(struct client *client)
{
    int ret;
    void *buf = client->request.bytes + client->request.pos;
    size_t len = client->request.len - client->request.pos;

    ret = read(client->sock, buf, len);
    if (ret <= 0) {
        on_client_error(client);
        return -1;
    }
    client->request.pos += ret;
    return 0;
}

//------------------------------------------------------------------------------
static int
client_expand_read_buffer(struct client *client)
{
    if (buffer_expand(&client->request) == -1) {
        on_client_error(client);
        return -1;
    }
    return 0;
}

//------------------------------------------------------------------------------
static void
on_client_read(int fd, short ev, void *arg)
{
    struct client *client = (struct client *) arg;

    if (ev == EV_TIMEOUT || client->server->shut) {
        on_client_error(client);
        return;
    }

    if (client->request.len == 0
        || client->request.len - client->request.pos < BUFFER_MIN)
        if (client_expand_read_buffer(client) == -1)
            return;

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

    ret = write(client->sock, client->response.bytes, client->response.pos);
    if (ret <= 0) {
        on_client_error(client);
        return -1;
    }
    buffer_collapse(&client->response, ret);
    return 0;
}

//------------------------------------------------------------------------------
static void
on_client_write(int fd, short ev, void *arg)
{
    struct client *client = (struct client *) arg;

    if (ev == EV_TIMEOUT || client->server->shut) {
        on_client_error(client);
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
    server->nclients++;
    client->sock = fd;
    if (addr)
        client->addr = *addr;
    event_set(&client->ev_read, fd, EV_READ, on_client_read, client);
    event_set(&client->ev_write, fd, EV_WRITE, on_client_write, client);
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
static struct stun_message *
stun_default_responser(struct stun_message *request, struct sockaddr *addr, void *arg)
{
    return stun_respond_to(request, addr);
}

//------------------------------------------------------------------------------
void
stun_tcp_stop(void *arg)
{
    struct server *server = (struct server *) arg;

    server->shut = 1;
    if (server->nclients == 0)
        on_server_error(server);
}

//------------------------------------------------------------------------------
static struct server *
server_new(int  fd, stun_responder *fn, void *arg)
{
    struct server *server;

    server = (struct server *) s_malloc(sizeof(struct server));
    server->sock = fd;
    server->stun_cb = fn;
    server->cb_arg = arg;
    server->shut = 0;
    server->client_timeout = &timeout;
    if (fd != -1) {
        event_set(&server->ev_accept, fd, EV_READ | EV_PERSIST, on_srv_accept, server);
        event_add(&server->ev_accept, NULL);
    }
    return server;
}

//------------------------------------------------------------------------------
void *
stun_tcp_adopt(int sock, stun_responder *fn, void *arg)
{
    struct server *server;
    struct client *client;

    server = server_new(-1, fn, arg);
    server->client_timeout = NULL;
    client = client_new(sock, NULL, server);

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

    return server_new(fd, stun_default_responser, NULL);
}

