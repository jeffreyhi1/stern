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

#define DEFAULT_LIFETIME  300
#define DEFAULT_BANDWIDTH 32

#pragma pack(push)
struct tag {
    uint16_t channel;
    uint16_t length;
};
#pragma pack(pop)

static void turntcp_acceptpeer(int fd, short ev, void *arg);
static void turnudp_recvpeer(int fd, short ev, void *arg);
static void turntcpchan_read(int fd, short ev, void *arg);
static void turntcpchan_send(int fd, short ev, void *arg);
static void tcpchan_set_events(struct turn_channel *channel);

#if 0
//------------------------------------------------------------------------------
static void
on_peer_shutrd(struct channel *channel)
{
    struct sockaddr addr;
    socklen_t len = sizeof(addr);

    event_del(channel->ev_peerread);
    s_free(channel->ev_peerread);
    channel->ev_peerread = NULL;
    getsockname(channel->peer, &addr, &len);
    channel_queue_connstat(channel, &addr, len, TURN_CONNSTAT_CLOSED);
}
#endif

//------------------------------------------------------------------------------
static int
turnchan_getid(struct turn_client *client)
{
    int chan, i, tries = 10;
    struct turn_channel *channel;

    do {
        chan = rand() & 0xFFFF;
        chan |= ((rand() + 1) & 0x3) << 14;
        if (--tries == 0)
            return -1;
        for (channel = LIST_FIRST(&client->channels); channel;
             channel = LIST_NEXT(channel, entries)) {
            if (channel->num_self == chan)
                break;
        }
    } while (channel != NULL);

    return chan;
}

//------------------------------------------------------------------------------
static void
turnresp_add_lifetime(struct stun_message * response, struct turn_client *client)
{
    response->lifetime = client->expires - time(NULL);
}

//------------------------------------------------------------------------------
void turnresp_add_relay_address(struct stun_message *response, struct turn_client *client)
{
    struct sockaddr addr;
    socklen_t len;

    len = sizeof(addr);
    getsockname(client->peer, &addr, &len);
    stun_set_relay_address(response, &addr, sizeof(addr));
}

//------------------------------------------------------------------------------
static void
turnresp_add_bandwidth(struct stun_message * response, struct turn_client *client)
{
    response->bandwidth = client->bandwidth;
}

//------------------------------------------------------------------------------
static void
turnresp_add_xor_mapped_address(struct stun_message * response, struct turn_client *client)
{
    stun_set_xor_mapped_address(response, &client->addr, sizeof(client->addr));
}

//------------------------------------------------------------------------------
static struct stun_message *
turnreq_allocate_respond(struct stun_message *request, struct turn_client *client)
{
    struct stun_message *response;

    response = stun_init_response(TURN_ALLOCATION_SUCCESS, request);
    turnresp_add_relay_address(response, client);
    turnresp_add_xor_mapped_address(response, client);
    turnresp_add_bandwidth(response, client);
    turnresp_add_lifetime(response, client);
    return response;
}

//------------------------------------------------------------------------------
static int
turnreq_allocate_req_ip_port(struct turn_client *client, struct stun_message *request, struct sockaddr *addr)
{
    struct sockaddr_in *sin = (struct sockaddr_in *) addr;
    // struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) addr;

    if (request->requested_ip_port == NULL) {
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = INADDR_ANY;
        sin->sin_port = 0;
        return 0;
    }
    return -1;
}

//------------------------------------------------------------------------------
static int
turnreq_allocate_bind(struct turn_client *client, struct stun_message *request, struct sockaddr *addr, socklen_t len)
{
    int fd;

    if (request->requested_transport == TURN_TRANSPORT_UDP) {
        fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
    } else if (request->requested_transport == TURN_TRANSPORT_TCP) {
        fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
    } else {
        return -1;
    }

    if (bind(fd, addr, len) == -1) {
        close(fd);
        return -1;
    }

    client->peer = fd;
    if (request->requested_transport == TURN_TRANSPORT_UDP) {
        client->protocol = IPPROTO_UDP;
        event_set(&client->ev_peer, fd, EV_READ | EV_PERSIST, turnudp_recvpeer, client);
    } else if (request->requested_transport == TURN_TRANSPORT_TCP) {
        client->protocol = IPPROTO_TCP;
        event_set(&client->ev_peer, fd, EV_READ | EV_PERSIST, turntcp_acceptpeer, client);
    }
    event_base_set(client->server->sternd->base, &client->ev_peer);

    return 0;
}

//------------------------------------------------------------------------------
static struct stun_message *
turnreq_allocate(struct stun_message *request, struct turn_client *client)
{
    struct sockaddr addr;

    if (client->peer != -1)
        return NULL;

    if (turnreq_allocate_req_ip_port(client, request, &addr) == -1
        || turnreq_allocate_bind(client, request, &addr, sizeof(addr)) == -1)
        return NULL;

    client->bandwidth = DEFAULT_BANDWIDTH;
    client->expires = time(NULL) + DEFAULT_LIFETIME;

    return turnreq_allocate_respond(request, client);
}

//------------------------------------------------------------------------------
static struct stun_message *
turnreq_listen(struct stun_message *request, struct turn_client *client)
{
    struct stun_message *response;
    int ret;

    if (client->peer == -1 || client->protocol != IPPROTO_TCP)
        return NULL;

    ret = listen(client->peer, 5);
    if (ret == -1) {
        response = stun_init_response(TURN_LISTEN_ERROR, request);
        response->error_code = 445;
        return response;
    }
    event_add(&client->ev_peer, NULL);

    response = stun_init_response(TURN_LISTEN_SUCCESS, request);
    turnresp_add_lifetime(response, client);
    return response;
}

//------------------------------------------------------------------------------
static struct turn_channel *
tcpchan_find(struct turn_client *client, int chan, struct sockaddr *addr)
{
    struct turn_channel *channel;
    struct sockaddr saddr;
    socklen_t slen;

    if (chan != -1) {
        for (channel = LIST_FIRST(&client->channels); channel;
             channel = LIST_NEXT(channel, entries)) {
            if (channel->num_client == chan)
                return channel;
        }
    }

    if (addr != NULL) {
        for (channel = LIST_FIRST(&client->channels); channel;
             channel = LIST_NEXT(channel, entries)) {
            slen = sizeof(saddr);
            getpeername(channel->s.tcp.sock, &saddr, &slen);
            if (sockaddr_matches(addr, &saddr))
                return channel;
        }
    }
    return NULL;
}

//------------------------------------------------------------------------------
static void
turnind_connstat(struct stun_message *request, struct turn_client *client)
{
    struct turn_channel *channel;

    if (!request->peer_address)
        return;

    channel = tcpchan_find(client, -1, request->peer_address);
    if (channel == NULL) return;

    if (request->connect_status == TURN_CONNSTAT_CLOSED) {
        channel->s.tcp.shut_wr_pending = 1;
        if (!channel->s.tcp.shut_wr)
            event_add(&channel->s.tcp.ev_write, NULL);
    }
}

//------------------------------------------------------------------------------
static void
turnind_send_queue_data(struct turn_client *client, struct turn_channel *channel,
                        struct stun_message *request)
{
    if (channel->s.tcp.shut_wr || channel->s.tcp.shut_wr_pending)
        return;

    if (channel->protocol == IPPROTO_TCP) {
        while (b_num_free(&channel->s.tcp.wbuf) < request->data_len)
            b_grow(&channel->s.tcp.wbuf);
        memcpy(b_pos_free(&channel->s.tcp.wbuf), request->data, request->data_len);
        b_used_free(&channel->s.tcp.wbuf, request->data_len);
        tcpchan_set_events(channel);
    } else {
        assert(0);
    }
}

//------------------------------------------------------------------------------
static struct turn_permission *
tcpperm_new(struct turn_client *client, struct sockaddr *addr, socklen_t len)
{
    struct turn_permission *perm = NULL;

    perm = (struct turn_permission *) s_malloc(sizeof(struct turn_permission));
    LIST_INSERT_HEAD(&client->permissions, perm, entries);

    perm->client = client;
    memcpy(&perm->addr, addr, len);
    return perm;
}

//------------------------------------------------------------------------------
static struct turn_permission *
turnperm_find(struct turn_client *client, struct sockaddr *addr, socklen_t len)
{
    struct turn_permission *perm;

    for (perm = LIST_FIRST(&client->permissions); perm; perm = LIST_NEXT(perm, entries)) {
        if (sockaddr_matches_addr(addr, &perm->addr))
            return perm;
    }
    return NULL;
}

//------------------------------------------------------------------------------
static int
set_nonblocking(int fd)
{
    int flags;

    if ((flags = fcntl(fd, F_GETFL, 0)) == -1
        || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;
    return 0;
}

//------------------------------------------------------------------------------
static struct turn_channel *
turntcp_newchannel(int fd, struct sockaddr *addr, socklen_t len, struct turn_client *client)
{
    int chan;
    struct turn_channel *channel;

    chan = turnchan_getid(client);
    if (chan == -1)
        return NULL;

    channel = s_malloc(sizeof(struct turn_channel));
    memset(channel, 0, sizeof(struct turn_channel));
    LIST_INSERT_HEAD(&client->channels, channel, entries);
    channel->s.tcp.sock = fd;
    channel->num_self = chan;
    channel->client = client;
    channel->protocol = IPPROTO_TCP;
    if (addr) {
        channel->addr = *addr;
        channel->slen = len;
    }
    event_set(&channel->s.tcp.ev_read, fd, EV_READ, turntcpchan_read, channel);
    event_set(&channel->s.tcp.ev_write, fd, EV_WRITE, turntcpchan_send, channel);
    event_base_set(client->server->sternd->base, &channel->s.tcp.ev_read);
    event_base_set(client->server->sternd->base, &channel->s.tcp.ev_write);
    tcpchan_set_events(channel);
    return channel;
}

//------------------------------------------------------------------------------
static struct turn_channel *
turntcp_connect(struct stun_message *request, struct turn_client *client, struct turn_permission *perm)
{
    int fd, ret;
    struct turn_channel *channel;

    fd = socket(request->peer_address->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (fd == -1)
        return NULL;
    set_nonblocking(fd);
    ret = connect(fd, request->peer_address, request->peer_address_len);
    if (ret == -1 && errno != EINPROGRESS) {
        close(fd);
        return NULL;
    }
    channel = turntcp_newchannel(fd, request->peer_address, request->peer_address_len, client);
    if (channel == NULL) {
        close(fd);
        return NULL;
    }
    channel->permission = perm;
    channel->num_client = request->channel;
    return channel;
}

//------------------------------------------------------------------------------
static void
tcpcli_set_events(struct turn_client *client)
{
    if (b_num_avail(&client->s.tcp.wbuf))
        event_add(&client->s.tcp.ev_write, NULL);
    event_add(&client->s.tcp.ev_read, NULL);
}

//------------------------------------------------------------------------------
static void
tcpcli_queueresponse(struct turn_client *client, struct stun_message *response)
{
    int ret = 0;
    struct buffer *wbuf = &client->s.tcp.wbuf;

    do {
        if (ret == -1)
            b_grow(wbuf);
        ret = stun_to_bytes(b_pos_free(wbuf), b_num_free(wbuf), response);
    } while (ret == -1);
    b_used_free(wbuf, ret);
    tcpcli_set_events(client);
}

//------------------------------------------------------------------------------
static void
tcpchan_process_requests(struct turn_channel *channel)
{
    struct turn_client *client = channel->client;
    struct stun_message *stun;
    struct buffer *rbuf = &channel->s.tcp.rbuf;
    struct tag *tag;
    size_t rlen, dlen;

    rlen = b_num_avail(rbuf);
    if (rlen == 0) return;
    if (channel->confirmed_by_client) {
        dlen = rlen + TURN_TAGLEN;
        while (b_num_free(&client->s.tcp.wbuf) < dlen)
            b_grow(&client->s.tcp.wbuf);
        tag = (struct tag *) b_pos_free(&client->s.tcp.wbuf);
        tag->channel = htons(channel->num_self);
        tag->length = htons(rlen);
        memcpy(b_pos_free(&client->s.tcp.wbuf) + TURN_TAGLEN, b_pos_avail(&channel->s.tcp.rbuf), rlen);
        b_used_free(&client->s.tcp.wbuf, dlen);
        tcpcli_set_events(client);
    } else {
        stun = stun_new(TURN_SEND_INDICATION);
        stun_set_peer_address(stun, &channel->addr, channel->slen);
        stun_set_data(stun, b_pos_avail(&channel->s.tcp.rbuf), rlen);
        stun->channel = channel->num_self;
        tcpcli_queueresponse(client, stun);
        stun_free(stun);
    }
    b_used_avail(&channel->s.tcp.rbuf, rlen);
}

//------------------------------------------------------------------------------
static void
turnind_send_connstat(struct turn_channel *channel, struct sockaddr *addr, socklen_t len, int status)
{
    struct turn_client *client = channel->client;
    struct stun_message *stun;

    stun = stun_new(TURN_CHAN_CONF_INDICATION);
    stun_set_peer_address(stun, addr, len);
    stun->channel = channel->num_self;
    if (status != -1)
        stun->connect_status = status;
    channel->confirmed_by_self = 1;
    if (client->server->protocol == IPPROTO_TCP)
        channel->confirmed_by_client = 1;
    tcpcli_queueresponse(client, stun);
    stun_free(stun);
}

//------------------------------------------------------------------------------
static void
turnind_send(struct stun_message *request, struct turn_client *client)
{
    struct turn_permission *perm;
    struct turn_channel *channel;
    struct sockaddr *addr;
    socklen_t len;

    if (!request->peer_address)
        return;
    addr = request->peer_address;
    len = request->peer_address_len;

    perm = turnperm_find(client, addr, len);
    if (perm == NULL)
        perm = tcpperm_new(client, addr, len);
    if (perm == NULL)
        return;

    if (request->data) {
        channel = tcpchan_find(client, -1, addr);
        if (channel == NULL) {
            if (client->protocol == TURN_TRANSPORT_TCP)
                channel = turntcp_connect(request, client, perm);
            else
                assert(0);
        }
        if (channel == NULL) return;
        channel->num_client = request->channel;
        turnind_send_connstat(channel, addr, len, TURN_CONNSTAT_ESTABLISHED);
        turnind_send_queue_data(client, channel, request);
    } else {
        channel = tcpchan_find(client, -1, addr);
        if (channel == NULL) return;
        channel->num_client = request->channel;
        turnind_send_connstat(channel, addr, len, -1);
    }
}

//------------------------------------------------------------------------------
static struct stun_message *
turn_default_responder(struct stun_message *request, struct turn_client *client)
{
    struct stun_message *response = NULL;

    if (stun_cannot_comprehend(request))
        response = NULL;
    else if (request->message_type == TURN_ALLOCATION_REQUEST)
        response = turnreq_allocate(request, client);
    else if (request->message_type == TURN_LISTEN_REQUEST)
        response = turnreq_listen(request, client);
    else if (request->message_type == TURN_CONN_STAT_INDICATION)
        turnind_connstat(request, client);
    else if (request->message_type == TURN_SEND_INDICATION)
        turnind_send(request, client);
    else if (IS_INDICATION(request->message_type))
        response = NULL;

    if (response == NULL && IS_REQUEST(request->message_type)) {
        response = stun_init_response(request->message_type | STUN_ERROR, request);
        response->error_code = stun_cannot_comprehend(request) ? 420 : 400;
    }

    return response;
}

//------------------------------------------------------------------------------
static int
tcpcli_process_stun_request(struct turn_client *client)
{
    struct stun_message *request, *response;
    struct buffer *rbuf = &client->s.tcp.rbuf;
    size_t rlen;

    rlen = b_num_avail(rbuf);
    request = stun_from_bytes(b_pos_avail(rbuf), &rlen);
    if (request) {
        response = turn_default_responder(request, client);
        if (response) {
            tcpcli_queueresponse(client, response);
            stun_free(response);
        }
        stun_free(request);
        b_used_avail(rbuf, rlen);
        return 1;
    }
    return 0;
}

//------------------------------------------------------------------------------
static int
tcpcli_process_raw_frame(struct turn_client *client)
{
    struct buffer *rbuf = &client->s.tcp.rbuf;
    struct turn_channel *channel;
    size_t dlen;
    struct tag *tag;

    tag = (struct tag *) b_pos_avail(rbuf);
    dlen = ntohs(tag->length);
    if (b_num_avail(rbuf) < TURN_TAGLEN + dlen)
        return 0;
    channel = tcpchan_find(client, ntohs(tag->channel), NULL);
    if (channel && !channel->s.tcp.shut_wr && !channel->s.tcp.shut_wr_pending) {
        while (b_num_free(&channel->s.tcp.wbuf) < dlen)
            b_grow(&channel->s.tcp.wbuf);
        memcpy(b_pos_free(&channel->s.tcp.wbuf), b_pos_avail(rbuf) + TURN_TAGLEN, dlen);
        b_used_free(&channel->s.tcp.wbuf, dlen);
        tcpchan_set_events(channel);
    }
    b_used_avail(rbuf, TURN_TAGLEN + dlen);
    return 1;
}

//------------------------------------------------------------------------------
static void
tcpcli_process_requests(struct turn_client *client)
{
    int processed;
    struct tag *tag;
    struct buffer *rbuf = &client->s.tcp.rbuf;

    do {
        if (b_num_avail(rbuf) < TURN_TAGLEN) break;
        tag = (struct tag *) b_pos_avail(rbuf);
        if (IS_STUN_CHANNEL(ntohs(tag->channel))) {
            processed = tcpcli_process_stun_request(client);
        } else {
            processed = tcpcli_process_raw_frame(client);
        }
    } while (processed);
}

//------------------------------------------------------------------------------
static void
tcpchan_shutwr(struct turn_channel *channel)
{
    if (!channel->s.tcp.shut_wr) {
        event_del(&channel->s.tcp.ev_write);
        b_reset(&channel->s.tcp.wbuf);
        shutdown(channel->s.tcp.sock, SHUT_WR);
        channel->s.tcp.shut_wr = 1;
    }
}

//------------------------------------------------------------------------------
static void
tcpchan_shutrd(struct turn_channel *channel)
{
    if (!channel->s.tcp.shut_rd) {
        turnind_send_connstat(channel, &channel->addr, channel->slen, TURN_CONNSTAT_CLOSED);
        event_del(&channel->s.tcp.ev_read);
        b_reset(&channel->s.tcp.rbuf);
        shutdown(channel->s.tcp.sock, SHUT_RD);
        channel->s.tcp.shut_rd = 1;
    }
}

//------------------------------------------------------------------------------
static void
tcpchan_close(struct turn_channel *channel)
{
    if (channel->s.tcp.sock != -1) {
        tcpchan_shutwr(channel);
        tcpchan_shutrd(channel);
        close(channel->s.tcp.sock);
        channel->s.tcp.sock = -1;
    }
}

//------------------------------------------------------------------------------
static void
tcpchan_free(struct turn_channel *channel)
{
    tcpchan_close(channel);
    LIST_REMOVE(channel, entries);
    s_free(channel);
}

//------------------------------------------------------------------------------
static void
tcpchan_set_events(struct turn_channel *channel)
{
    if (!channel->s.tcp.shut_wr && !b_is_empty(&channel->s.tcp.wbuf))
        event_add(&channel->s.tcp.ev_write, NULL);
    if (!channel->s.tcp.shut_rd)
        event_add(&channel->s.tcp.ev_read, NULL);
}

//------------------------------------------------------------------------------
static int
tcpchan_recv(struct turn_channel *channel)
{
    int ret;

    ret = b_recv(&channel->s.tcp.rbuf, channel->s.tcp.sock, 0, MSG_DONTWAIT);
    return (ret <= 0) ? -1 : 0;
}

//------------------------------------------------------------------------------
static void
turntcpchan_read(int fd, short ev, void *arg)
{
    struct turn_channel *channel = (struct turn_channel *) arg;

    if (ev == EV_TIMEOUT || tcpchan_recv(channel) == -1) {
        channel->s.tcp.shut_rd_pending = 1;
    }

    tcpchan_process_requests(channel);

    if (channel->s.tcp.shut_rd_pending && b_num_avail(&channel->s.tcp.rbuf) == 0) {
        tcpchan_shutrd(channel);
    }

    tcpchan_set_events(channel);
}

//------------------------------------------------------------------------------
static int
tcpchan_send(struct turn_channel *channel)
{
    int ret;

    ret = b_send(&channel->s.tcp.wbuf, channel->s.tcp.sock, MSG_DONTWAIT | MSG_NOSIGNAL);
    return (ret < 0) ? -1 : 0;
}

//------------------------------------------------------------------------------
static void
turntcpchan_send(int fd, short ev, void *arg)
{
    struct turn_channel *channel = (struct turn_channel *) arg;

    if (ev == EV_TIMEOUT || tcpchan_send(channel) == -1) {
        tcpchan_shutwr(channel);
    }

    if (channel->s.tcp.shut_wr_pending && b_is_empty(&channel->s.tcp.wbuf)) {
        tcpchan_shutwr(channel);
    }

    tcpchan_set_events(channel);
}

//------------------------------------------------------------------------------
static void
tcpperm_free(struct turn_permission *permission)
{
    LIST_REMOVE(permission, entries);
    s_free(permission);
}

//------------------------------------------------------------------------------
static void
tcpcli_free(struct turn_client *client)
{
    while (LIST_FIRST(&client->permissions) != NULL)
        tcpperm_free(LIST_FIRST(&client->permissions));

    while (LIST_FIRST(&client->channels) != NULL)
        tcpchan_free(LIST_FIRST(&client->channels));

    b_reset(&client->s.tcp.wbuf);
    b_reset(&client->s.tcp.rbuf);
    event_del(&client->s.tcp.ev_read);
    event_del(&client->s.tcp.ev_write);
    event_del(&client->ev_peer);

    close(client->s.tcp.sock);
    if (client->peer != -1)
        close(client->peer);

    LIST_REMOVE(client, entries);
    s_free(client);
}

//------------------------------------------------------------------------------
static int
tcpcli_recv(struct turn_client *client)
{
    int ret;

    ret = b_recv(&client->s.tcp.rbuf, client->s.tcp.sock, 0, MSG_DONTWAIT);
    return (ret <= 0) ? -1 : 0;
}

//------------------------------------------------------------------------------
static void
turntcpcli_read(int fd, short ev, void *arg)
{
    struct turn_client *client = (struct turn_client *) arg;

    if (ev == EV_TIMEOUT || tcpcli_recv(client) == -1) {
        tcpcli_free(client);
        return;
    }

    tcpcli_process_requests(client);
    tcpcli_set_events(client);
}

//------------------------------------------------------------------------------
static int
tcpcli_send(struct turn_client *client)
{
    int ret;

    ret = b_send(&client->s.tcp.wbuf, client->s.tcp.sock, MSG_DONTWAIT | MSG_NOSIGNAL);
    return (ret <= 0) ? -1 : 0;
}

//------------------------------------------------------------------------------
static void
turntcpcli_send(int fd, short ev, void *arg)
{
    struct turn_client *client = (struct turn_client *) arg;

    if (ev == EV_TIMEOUT || tcpcli_send(client) == -1) {
        tcpcli_free(client);
        return;
    }

    tcpcli_set_events(client);
}


//------------------------------------------------------------------------------
static void
turnudp_recvpeer(int fd, short ev, void *arg)
{
    assert(0);
}

//------------------------------------------------------------------------------
static void
turntcp_acceptpeer(int fd, short ev, void *arg)
{
    struct turn_client *client = (struct turn_client *) arg;
    struct turn_channel *channel;
    struct turn_permission *perm;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);
    int cli;

    cli = accept(fd, &addr, &len);
    if (cli == -1)
        return;
    perm = turnperm_find(client, &addr, len);
    if (perm == NULL) {
        close(cli);
        return;
    }

    channel = turntcp_newchannel(cli, &addr, len, client);
    if (channel == NULL) {
        close(cli);
        return;
    }

    channel->permission = perm;
    turnind_send_connstat(channel, &addr, len, TURN_CONNSTAT_ESTABLISHED);
}

//------------------------------------------------------------------------------
static struct turn_client *
turntcp_newclient(int fd, struct sockaddr *addr, struct turn_server *server)
{
    struct turn_client *client;

    client = s_malloc(sizeof(struct turn_client));
    memset(client, 0, sizeof(struct turn_client));
    LIST_INSERT_HEAD(&server->clients, client, entries);
    LIST_INIT(&client->permissions);
    LIST_INIT(&client->channels);
    client->s.tcp.sock = fd;
    client->peer = -1;
    client->server = server;
    if (addr)
        client->addr = *addr;
    event_set(&client->s.tcp.ev_read, fd, EV_READ, turntcpcli_read, client);
    event_set(&client->s.tcp.ev_write, fd, EV_WRITE, turntcpcli_send, client);
    event_base_set(server->sternd->base, &client->s.tcp.ev_read);
    event_base_set(server->sternd->base, &client->s.tcp.ev_write);
    tcpcli_set_events(client);
    return client;
}

//------------------------------------------------------------------------------
static void
turntcp_acceptclient(int fd, short ev, void *arg)
{
    struct turn_server *server = (struct turn_server *) arg;
    struct turn_client *client;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);
    int cli;

    cli = accept(fd, &addr, &len);
    if (cli == -1)
        return;
    client = turntcp_newclient(cli, &addr, server);
    if (!client)
        close(cli);
}

//------------------------------------------------------------------------------
int
sternd_set_turn_socket(int transport, int socket, int port)
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
        if (sternd.turntcp.sock != -1) {
            close(sternd.turntcp.sock);
            event_del(&sternd.turntcp.s.tcp.ev_accept);
        }
        sternd.turntcp.sock = socket;
        listen(socket, 5);
        event_set(&sternd.turntcp.s.tcp.ev_accept, socket, EV_READ | EV_PERSIST, turntcp_acceptclient, &sternd.turntcp);
        event_base_set(sternd.base, &sternd.turntcp.s.tcp.ev_accept);
        event_add(&sternd.turntcp.s.tcp.ev_accept, NULL);
        return 0;
    } else {
        return -1;
    }
}

//------------------------------------------------------------------------------
void
sternd_turn_quit()
{
    while (LIST_FIRST(&sternd.turntcp.clients) != NULL) {
        tcpcli_free(LIST_FIRST(&sternd.turntcp.clients));
    }

    if (sternd.turntcp.sock != -1) {
        event_del(&sternd.turntcp.s.tcp.ev_accept);
        close(sternd.turntcp.sock);
        sternd.turntcp.sock = -1;
    }
}

