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
#include "sternd.h"

static struct timeval timeout = { CLIENT_TIMEOUT, 0 };

//------------------------------------------------------------------------------
static void
tcpcli_free(struct stun_client *client)
{
    if (client->s.tcp.sock != -1)
        close(client->s.tcp.sock);
    event_del(&client->s.tcp.ev_read);
    event_del(&client->s.tcp.ev_write);
    b_reset(&client->s.tcp.wbuf);
    b_reset(&client->s.tcp.rbuf);

    LIST_REMOVE(client, entries);
    s_free(client);
}

//------------------------------------------------------------------------------
static void
tcpcli_set_events(struct stun_client *client)
{
    if (!b_is_empty(&client->s.tcp.wbuf))
        event_add(&client->s.tcp.ev_write, &timeout);
    else
        event_add(&client->s.tcp.ev_read, &timeout);
}

//------------------------------------------------------------------------------
static struct stun_message *
stun_default_responder(struct stun_message *request, struct sockaddr *addr)
{
    return stun_respond_to(request, addr);
}

//------------------------------------------------------------------------------
static void
tcpcli_queueresponse(struct stun_client *client, struct stun_message *response)
{
    int ret = 0;
    struct buffer *wbuf = &client->s.tcp.wbuf;

    do {
        if (ret == -1)
            b_grow(wbuf);
        ret = stun_to_bytes(b_pos_free(wbuf), b_num_free(wbuf), response);
    } while (ret == -1);
    b_used_free(wbuf, ret);
}

//------------------------------------------------------------------------------
static void
tcpcli_process_requests(struct stun_client *client)
{
    int processed;
    size_t rlen;
    struct stun_message *request, *response;
    struct buffer *rbuf = &client->s.tcp.rbuf;

    do {
        processed = 0;
        rlen = b_num_avail(rbuf);
        request = stun_from_bytes(b_pos_avail(rbuf), &rlen);
        if (request) {
            processed = 1;
            b_used_avail(rbuf, rlen);
            response = stun_default_responder(request, &client->addr);
            if (response) {
                tcpcli_queueresponse(client, response);
                stun_free(response);
            }
            stun_free(request);
        }
    } while (processed);
}

//------------------------------------------------------------------------------
static int
tcpcli_recv(struct stun_client *client)
{
    int ret;

    ret = b_recv(&client->s.tcp.rbuf, client->s.tcp.sock, 0, MSG_DONTWAIT);
    return (ret <= 0) ? -1 : 0;
}

//------------------------------------------------------------------------------
static void
stuntcpcli_read(int fd, short ev, void *arg)
{
    struct stun_client *client = (struct stun_client *) arg;

    if (ev == EV_TIMEOUT || tcpcli_recv(client) == -1) {
        tcpcli_free(client);
        return;
    }

    tcpcli_process_requests(client);
    tcpcli_set_events(client);
}

//------------------------------------------------------------------------------
static int
tcpcli_send(struct stun_client *client)
{
    int ret;

    ret = b_send(&client->s.tcp.wbuf, client->s.tcp.sock, MSG_DONTWAIT | MSG_NOSIGNAL);
    return (ret <= 0) ? -1 : 0;
}

//------------------------------------------------------------------------------
static void
stuntcpcli_send(int fd, short ev, void *arg)
{
    struct stun_client *client = (struct stun_client *) arg;

    if (ev == EV_TIMEOUT || tcpcli_send(client) == -1) {
        tcpcli_free(client);
        return;
    }

    tcpcli_set_events(client);
}

//------------------------------------------------------------------------------
static struct stun_client *
stuntcp_newclient(int fd, struct sockaddr *addr, struct stun_server *server)
{
    struct stun_client *client;

    client = s_malloc(sizeof(struct stun_client));
    memset(client, 0, sizeof(struct stun_client));
    LIST_INSERT_HEAD(&server->clients, client, entries);
    client->s.tcp.sock = fd;
    if (addr)
        client->addr = *addr;
    event_set(&client->s.tcp.ev_read, fd, EV_READ, stuntcpcli_read, client);
    event_set(&client->s.tcp.ev_write, fd, EV_WRITE, stuntcpcli_send, client);
    event_base_set(server->sternd->base, &client->s.tcp.ev_read);
    event_base_set(server->sternd->base, &client->s.tcp.ev_write);
    tcpcli_set_events(client);
    return client;
}

//------------------------------------------------------------------------------
static void
stuntcp_accept(int fd, short ev, void *arg)
{
    struct stun_server *server = (struct stun_server *) arg;
    struct stun_client *client;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);
    int cli;

    cli = accept(fd, &addr, &len);
    if (cli == -1)
        return;
    client = stuntcp_newclient(cli, &addr, server);
    if (!client)
        close(cli);
}

//------------------------------------------------------------------------------
static void
stunudp_recv(int fd, short ev, void *arg)
{
    // struct stun_server *server = (struct stun_server *) arg;
    struct stun_message *request, *response;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);
    char buf[BUFFER_MAX];
    size_t slen;
    int ret;

    /* Receive message */
    ret = recvfrom(fd, buf, sizeof(buf), 0, &addr, &len);
    if (ret <= 0) return;

    /* Process request */
    slen = ret;
    request = stun_from_bytes(buf, &slen);
    if (request) {
        response = stun_default_responder(request, &addr);
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
int
sternd_set_stun_socket(int transport, int socket, int port)
{
    struct sockaddr_in sin;
    static int one = 1;

    if (port != -1) {
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = INADDR_ANY;
        sin.sin_port = htons(port);
        setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        if (bind(socket, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)))
            return -1;
    }

    if (transport == IPPROTO_TCP) {
        if (sternd.stuntcp.sock != -1) {
            close(sternd.stuntcp.sock);
            event_del(&sternd.stuntcp.s.tcp.ev_accept);
        }
        sternd.stuntcp.sock = socket;
        listen(socket, 5);
        event_set(&sternd.stuntcp.s.tcp.ev_accept, socket, EV_READ | EV_PERSIST, stuntcp_accept, &sternd.stuntcp);
        event_base_set(sternd.base, &sternd.stuntcp.s.tcp.ev_accept);
        event_add(&sternd.stuntcp.s.tcp.ev_accept, NULL);
        return 0;
    } else if (transport == IPPROTO_UDP) {
        if (sternd.stunudp.sock != -1) {
            close(sternd.stunudp.sock);
            event_del(&sternd.stuntcp.s.udp.ev_recv);
        }
        sternd.stunudp.sock = socket;
        event_set(&sternd.stunudp.s.udp.ev_recv, socket, EV_READ|EV_PERSIST, stunudp_recv, &sternd.stunudp);
        event_base_set(sternd.base, &sternd.stunudp.s.udp.ev_recv);
        event_add(&sternd.stunudp.s.udp.ev_recv, NULL);
        return 0;
    } else {
        return -1;
    }
}

//------------------------------------------------------------------------------
void
sternd_stun_quit()
{
    while (LIST_FIRST(&sternd.stuntcp.clients) != NULL) {
        tcpcli_free(LIST_FIRST(&sternd.stuntcp.clients));
    }

    if (sternd.stuntcp.sock != -1) {
        event_del(&sternd.stuntcp.s.tcp.ev_accept);
        close(sternd.stuntcp.sock);
        sternd.stuntcp.sock = -1;
    }

    if (sternd.stunudp.sock != -1) {
        event_del(&sternd.stunudp.s.udp.ev_recv);
        close(sternd.stunudp.sock);
        sternd.stunudp.sock = -1;
    }
}

//------------------------------------------------------------------------------
void
sternd_set_stun_timeout(int s, int us)
{
    timeout.tv_sec = s;
    timeout.tv_usec = us;
}
