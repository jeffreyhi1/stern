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

enum state {
    MUX_WAITING_FOR_DATA,
    MUX_SPLICING_TO_CLIENT_READING,
    MUX_SPLICING_TO_CLIENT_WRITING_TAG,
    MUX_SPLICING_TO_CLIENT_WRITING_DATA,
    MUX_SPLICING_FROM_CLIENT_READING_TAG,
    MUX_SPLICING_FROM_CLIENT_READING_DATA,
    MUX_SPLICING_FROM_CLIENT_WRITING
};

struct server {
    int sock;
    struct event ev_accept;
};

struct client;

struct permission {
    struct sockaddr  addr;           /* Peer address                                */
};

struct channel {
    int                clnt_confirm;   /* Whether client has confirmed our number   */
    int                num_clnt;       /* Number as per client                      */
    int                num_self;       /* Number of this permission                 */
    int                peer;           /* Peer socket (TCP only)                    */
    int                self_confirm;   /* Whether we have confirmed client's number */
    struct client     *client;         /* Client allocation this channel is for     */
    struct event      *ev_peerread;    /* Peer sent data (TCP only)                 */
    struct event      *ev_peerwrite;   /* Can write to peer (TCP only)              */
    struct permission *perm;           /* Permission this channel was created under */
};

struct client {
    enum state          state;           /* Current forwarding state                    */
    int                 bandwidth;       /* Bandwidth for allocation                    */
    int                 clnt;            /* Client socket                               */
    int                 nchannels;       /* Number of channels/permissions              */
    int                 nperms;          /* Number of channels/permissions              */
    int                 need_maintain;   /* Need to perform periodic maintainance       */
    int                 peer;            /* Peer socket for UDP, Listen socket for TCP  */
    int                 protocol;        /* IP protocol to client UDP or TCP            */
    size_t              len;             /* Number of bytes to write/read               */
    size_t              pos;             /* Number of bytes written/read so far         */
    struct channel    **channels;        /* Channels                                    */
    struct event       *ev_cliread;      /* Client sent data                            */
    struct event       *ev_cliwrite;     /* Can write to client (TCP only)              */
    struct event       *ev_peerread;     /* Peer sent data (UDP), Can accept peer (TCP) */
    struct event       *ev_peerwrite;    /* Can write to peer (TCP only)                */
    struct permission **perms;           /* Permissions                                 */
    struct server      *server;          /* Server that accepted client socket          */
    struct sockaddr     addr;            /* Client reflexive address                    */
    struct tag          tag;             /* Tag for current read/write to client        */
    time_t              expires;         /* Time this allocation expires                */
    void               *buf;             /* Buffer with data for current read/write     */
};

static void on_peer_accept(int fd, short ev, void *arg);
static void on_peer_read(int fd, short ev, void *arg);
static void on_peer_recvfrom(int fd, short ev, void *arg);
static void on_peer_error(struct channel *channel);
static void on_peer_write(int fd, short ev, void *arg);
static void on_client_write(int fd, short ev, void *arg);

//------------------------------------------------------------------------------
static int
turnreq_allocate_bind(struct client *client, struct stun_message *request, struct sockaddr *addr, socklen_t len)
{
    int fd;

    if (request->requested_transport == TURN_TRANSPORT_UDP) {
        fd = socket(addr->sa_family, SOCK_DGRAM, IPPROTO_UDP);
        if (bind(fd, addr, len) == -1) {
            close(fd);
            return -1;
        }
        client->protocol = IPPROTO_UDP;
        client->ev_peerread = (struct event *) s_malloc(sizeof(struct event));
        event_set(client->ev_peerread, client->peer, EV_READ, on_peer_recvfrom, client);
    } else if (request->requested_transport == TURN_TRANSPORT_TCP) {
        fd = socket(addr->sa_family, SOCK_STREAM, IPPROTO_TCP);
        if (bind(fd, addr, len) == -1) {
            close(fd);
            return -1;
        }
        client->protocol = IPPROTO_TCP;
    } else {
        return -1;
    }
    client->peer = fd;
    return 0;
}

//------------------------------------------------------------------------------
static void
turnresp_add_lifetime(struct stun_message * response, struct client *client)
{
    response->lifetime = client->expires - time(NULL);
}

//------------------------------------------------------------------------------
void turnresp_add_relay_address(struct stun_message *response, struct client *client)
{
    struct sockaddr addr;
    socklen_t len;

    len = sizeof(addr);
    getsockname(client->peer, &addr, &len);
    stun_set_sockaddr(response, ATTR_RELAY_ADDRESS, &addr, sizeof(addr));
}

//------------------------------------------------------------------------------
static void
turnresp_add_bandwidth(struct stun_message * response, struct client *client)
{
    response->bandwidth = client->bandwidth;
}

//------------------------------------------------------------------------------
static void
turnresp_add_xor_mapped_address(struct stun_message * response, struct client *client)
{
    stun_set_sockaddr(response, ATTR_XOR_MAPPED_ADDRESS, &client->addr, sizeof(client->addr));
}

//------------------------------------------------------------------------------
static struct stun_message *
turnreq_allocate_respond(struct stun_message *request, struct client *client)
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
turnreq_allocate_req_ip_port(struct client *client, struct stun_message *request, struct sockaddr *addr)
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
static struct stun_message *
turnreq_allocate(struct stun_message *request, struct client *client)
{
    struct sockaddr addr;

    if (turnreq_allocate_req_ip_port(client, request, &addr) == -1
        || turnreq_allocate_bind(client, request, &addr, sizeof(addr)) == -1)
        return NULL;

    client->bandwidth = DEFAULT_BANDWIDTH;
    client->expires = time(NULL) + DEFAULT_LIFETIME;

    return turnreq_allocate_respond(request, client);
}

//------------------------------------------------------------------------------
static struct stun_message *
turnreq_listen(struct stun_message *request, struct client *client)
{
    struct stun_message *response;
    int ret;

    if (client->peer == -1 || client->protocol != IPPROTO_TCP)
        return NULL;

    ret = listen(client->peer, 2);
    if (ret == -1) {
        response = stun_init_response(TURN_LISTEN_ERROR, request);
        response->error_code = 445;
        return response;
    }
    client->ev_peerread = (struct event *) s_malloc(sizeof(struct event));
    event_set(client->ev_peerread, client->peer, EV_READ, on_peer_accept, client);

    response = stun_init_response(TURN_LISTEN_SUCCESS, request);
    turnresp_add_lifetime(response, client);
    return response;
}


//------------------------------------------------------------------------------
static int
channel_find_unused(struct client *client)
{
    int chan, i, tries = 10;

    do {
        do {
            chan = rand() & 0xFFFF;
        } while (chan == 0);
        if (--tries == 0)
            return -1;
        for (i = 0; i < client->nchannels; i++)
            if (client->channels[i]->num_self == chan)
                break;
    } while (i < client->nchannels);

    return chan;
}

//------------------------------------------------------------------------------
static struct permission *
perm_new(struct client *client, struct sockaddr *addr)
{
    struct permission *perm = NULL;

    client->perms = (struct permission **) s_realloc(
            client->perms,
            (++client->nperms) * sizeof(struct permission *));
    perm = (struct permission *) s_malloc(sizeof(struct permission));
    client->perms[client->nperms - 1] = perm;

    memcpy(&perm->addr, addr,
           addr->sa_family == AF_INET ? sizeof(struct sockaddr_in)
           : addr->sa_family == AF_INET6 ? sizeof(struct sockaddr_in6)
           : sizeof(struct sockaddr));
    return perm;
}

//------------------------------------------------------------------------------
static struct channel *
channel_new(struct client *client, struct permission *perm)
{
    struct channel *channel = NULL;
    int chan;

    chan = channel_find_unused(client);
    if (chan == -1) return NULL;

    client->channels = (struct channel **) s_realloc(
            client->channels,
            (++client->nchannels) * sizeof(struct channel *));
    channel = (struct channel *) s_malloc(sizeof(struct channel));
    client->channels[client->nchannels - 1] = channel;

    memset(channel, 0, sizeof(struct channel));
    channel->num_self = chan;
    channel->client = client;
    channel->peer = -1;
    channel->perm = perm;
    return channel;
}

//------------------------------------------------------------------------------
static int
sockaddr_matches_addr(struct sockaddr *addr1, struct sockaddr *addr2)
{
    struct sockaddr_in *sina = (struct sockaddr_in *) addr1;
    struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in *sinb = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *sin6b = (struct sockaddr_in6 *) addr2;

    return (addr1->sa_family == addr2->sa_family
            && ((addr1->sa_family == AF_INET
                 && sina->sin_addr.s_addr == sinb->sin_addr.s_addr)
                || (addr1->sa_family == AF_INET6
                    && memcmp(sin6a->sin6_addr.s6_addr,
                              sin6b->sin6_addr.s6_addr,
                              16) == 0)));
}

//------------------------------------------------------------------------------
static int
sockaddr_matches(struct sockaddr *addr1, struct sockaddr *addr2)
{
    struct sockaddr_in *sina = (struct sockaddr_in *) addr1;
    struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in *sinb = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *sin6b = (struct sockaddr_in6 *) addr2;

    return (addr1->sa_family == addr2->sa_family
            && ((addr1->sa_family == AF_INET
                 && sina->sin_addr.s_addr == sinb->sin_addr.s_addr
                 && sina->sin_port == sinb->sin_port)
                || (addr1->sa_family == AF_INET6
                    && memcmp(sin6a->sin6_addr.s6_addr,
                              sin6b->sin6_addr.s6_addr,
                              16) == 0
                    && sin6a->sin6_port == sin6b->sin6_port)));
}

//------------------------------------------------------------------------------
static struct channel *
channel_get(struct client *client, struct permission *perm, struct sockaddr *addr)
{
    struct channel *channel;
    struct sockaddr saddr;
    socklen_t slen;
    int i;

    if (client->protocol == IPPROTO_TCP) {
        for (i = 0; i < client->nchannels; i++) {
            channel = client->channels[i];
            slen = sizeof(saddr);
            getpeername(channel->peer, &saddr, &slen);
            if (sockaddr_matches(addr, &saddr))
                return channel;
        }
    }
    for (i = 0; i < client->nchannels; i++) {
        channel = client->channels[i];
        if (channel->perm == perm)
            return channel;
    }
    return channel_new(client, perm);
}

//------------------------------------------------------------------------------
static struct permission *
perm_get(struct client *client, struct sockaddr *addr)
{
    struct permission *perm;
    int i;

    for (i = 0; i < client->nperms; i++) {
        perm = client->perms[i];
        if (sockaddr_matches_addr(addr, &perm->addr))
            return perm;
    }
    return perm_new(client, addr);
}

//------------------------------------------------------------------------------
static void
turnind_send_queue_data(struct client *client, struct channel *channel,
                        struct stun_message *request)
{
    if (client->buf)
        s_free(client->buf);
    client->buf = request->data;
    client->len = request->data_len;
    client->pos = 0;
    request->data = NULL;
    request->data_len = 0;

    client->state = MUX_SPLICING_FROM_CLIENT_WRITING;
    client->ev_peerwrite = channel->ev_peerwrite;
}

//------------------------------------------------------------------------------
static void
turnind_send(struct stun_message *request, struct client *client)
{
    struct permission *perm;
    struct channel *channel;

    if (!request->peer_address)
        return;

    perm = perm_get(client, request->peer_address);
    if (perm == NULL) return;

    if (request->data) {
        channel = channel_get(client, perm, request->peer_address);
        if (channel == NULL) return;
        channel->num_clnt = request->channel;
        channel->perm = perm;
        turnind_send_queue_data(client, channel, request);
        return;
    }
}

//------------------------------------------------------------------------------
static void
turnind_connstat(struct stun_message *request, struct client *client)
{
    struct channel *channel;

    if (!request->peer_address)
        return;

    channel = channel_get(client, NULL, request->peer_address);
    if (channel == NULL) return;

    if (request->connect_status == TURN_CONNSTAT_CLOSED) {
        on_peer_error(channel);
        return;
    }
}

//------------------------------------------------------------------------------
static struct stun_message *
turn_stun_responder(struct stun_message *request, struct client *client)
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
        return response;
    }

    return response;
}

//------------------------------------------------------------------------------
static void
client_clear_read_events(struct client *client)
{
    int i;

    event_del(client->ev_cliread);
    if (client->ev_peerread)
        event_del(client->ev_peerread);
    for(i = 0; i < client->nchannels; i++)
        if (client->channels[i]->ev_peerread)
            event_del(client->channels[i]->ev_peerread);
}

//------------------------------------------------------------------------------
static void
client_set_events(struct client *client)
{
    int i;

    switch (client->state) {
        case  MUX_WAITING_FOR_DATA:
            event_add(client->ev_cliread, NULL);
            if (client->ev_peerread)
                event_add(client->ev_peerread, NULL);
            for(i = 0; i < client->nchannels; i++)
                if (client->channels[i]->ev_peerread)
                    event_add(client->channels[i]->ev_peerread, NULL);
            break;

        case MUX_SPLICING_FROM_CLIENT_READING_TAG:
        case MUX_SPLICING_FROM_CLIENT_READING_DATA:
            client_clear_read_events(client);
            event_add(client->ev_cliread, NULL);
            break;

        case MUX_SPLICING_FROM_CLIENT_WRITING:
            client_clear_read_events(client);
            event_add(client->ev_peerwrite, NULL);
            break;

        case MUX_SPLICING_TO_CLIENT_READING:
            // Data should have been queued for write. If no data, should
            // wait for any
            assert(0);
            break;

        case MUX_SPLICING_TO_CLIENT_WRITING_TAG:
        case MUX_SPLICING_TO_CLIENT_WRITING_DATA:
            client_clear_read_events(client);
            event_add(client->ev_cliwrite, NULL);
            break;

        default:
            assert(0);
    }
}

//------------------------------------------------------------------------------
static void
on_client_error(struct client *client)
{
    int i;

    event_del(client->ev_cliread);
    event_del(client->ev_cliwrite);

    if (client->ev_peerread)
        event_del(client->ev_peerread);

    for(i = 0; i < client->nchannels; i++) {
        if (client->channels[i]->ev_peerread) {
            event_del(client->channels[i]->ev_peerread);
            s_free(client->channels[i]->ev_peerread);
        }
        if (client->channels[i]->ev_peerwrite) {
            event_del(client->channels[i]->ev_peerwrite);
            s_free(client->channels[i]->ev_peerwrite);
        }
        if (client->channels[i]->peer != -1)
            close(client->channels[i]->peer);
        s_free(client->channels[i]);
    }
    for(i = 0; i < client->nperms; i++)
        s_free(client->perms[i]);

    close(client->clnt);
    if (client->peer != -1)
        close(client->peer);

    if (client->buf)
        s_free(client->buf);
    s_free(client->channels);
    s_free(client->perms);
    s_free(client->ev_peerread);
    s_free(client->ev_cliwrite);
    s_free(client->ev_cliread);
    s_free(client);
}

//------------------------------------------------------------------------------
static void
client_queue_stun_frame(struct stun_message *stun, struct client *client)
{
    int ret;

    client->len = 1024;
    do {
        client->buf = s_realloc(client->buf, client->len);
        ret = stun_to_bytes(client->buf, client->len, stun);
        if (ret == -1)
            client->len *= 2;
    } while (ret == -1);
    client->len = ret;
    client->tag.channel = htons(TURN_CHANNEL_CTRL);
    client->tag.length = htons(client->len);
    client->pos = 0;
    client->state = MUX_SPLICING_TO_CLIENT_WRITING_TAG;
    stun_free(stun);
}

//------------------------------------------------------------------------------
static void
channel_queue_connstat(struct channel *channel, struct sockaddr *addr, socklen_t len, int status)
{
    struct client *client = channel->client;
    struct stun_message *stun;

    stun = stun_new(TURN_CHAN_CONF_INDICATION);
    stun_set_sockaddr(stun, ATTR_PEER_ADDRESS, addr, len);
    stun->channel = channel->num_self;
    stun->connect_status = status;
    channel->clnt_confirm = 1;
    client_queue_stun_frame(stun, client);
}

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

//------------------------------------------------------------------------------
static void
on_peer_error(struct channel *channel)
{
    if (channel->ev_peerread)
        on_peer_shutrd(channel);
    if (channel->ev_peerwrite) {
        event_del(channel->ev_peerwrite);
        s_free(channel->ev_peerwrite);
        channel->ev_peerwrite = NULL;
    }

    if (channel->peer != -1)
        close(channel->peer);
    channel->peer = -1;
    channel->num_clnt = 0;
}


//------------------------------------------------------------------------------
static int
is_fatal(int ret, int err)
{
    return (ret == 0 || (ret == -1 && err != EAGAIN));
}

//------------------------------------------------------------------------------
static int
client_read_at_wait(struct client *client)
{
    client->state = MUX_SPLICING_FROM_CLIENT_READING_TAG;
    client->pos = 0;
    client->len = TURN_TAGLEN;
    return 0;
}

//------------------------------------------------------------------------------
static int
client_read_at_tag(struct client *client)
{
    int ret;

    ret = recv(client->clnt,
               client->pos + (uint8_t *)&client->tag,
               client->len - client->pos,
               MSG_DONTWAIT);
    if (is_fatal(ret, errno)) {
        on_client_error(client);
        return -1;
    } else if (ret < 0) {
        return 0;
    }
    client->pos += ret;
    if (client->pos == client->len) {
        client->state = MUX_SPLICING_FROM_CLIENT_READING_DATA;
        client->len = ntohs(client->tag.length);
        client->buf = s_realloc(client->buf, client->len);
        client->pos = 0;
    }
    return 0;
}

//------------------------------------------------------------------------------
static int
client_frame_process(struct client *client)
{
    struct stun_message *request, *response;

    /* Process control message */
    request = stun_from_bytes(client->buf, &client->len);
    if (!request) {
        on_client_error(client);
        return -1;
    }

    client->state = MUX_WAITING_FOR_DATA;
    response = turn_stun_responder(request, client);
    if (response)
        client_queue_stun_frame(response, client);
    stun_free(request);
    return 0;
}

//------------------------------------------------------------------------------
static void
client_frame_forward(struct client *client)
{
    int i;

    /* Queue delivery to peer */
    for (i = 0; i < client->nchannels; i++)
        if (client->channels[i]->num_clnt == ntohs(client->tag.channel)) {
            client->ev_peerwrite = client->channels[i]->ev_peerwrite;
            client->state = MUX_SPLICING_FROM_CLIENT_WRITING;
            client->pos = 0;
            return;
        }

    /* Unable to find peer */
    s_free(client->buf);
    client->len = 0;
    client->buf = NULL;
    client->state = MUX_WAITING_FOR_DATA;
}

//------------------------------------------------------------------------------
static int
client_read_at_data(struct client *client)
{
    int ret;

    ret = recv(client->clnt,
               client->pos + client->buf,
               client->len - client->pos,
               MSG_DONTWAIT);
    if (is_fatal(ret, errno)) {
        on_client_error(client);
        return -1;
    } else if (ret < 0) {
        return 0;
    }
    client->pos += ret;
    if (client->pos == client->len) {
        if (ntohs(client->tag.channel) != TURN_CHANNEL_CTRL)
            client_frame_forward(client);
        else
            if (client_frame_process(client) == -1)
                return -1;
    }
    return 0;
}

//------------------------------------------------------------------------------
static int
peer_write_at_data(struct channel *channel)
{
    struct client *client = channel->client;
    int ret;

    ret = send(channel->peer,
               client->buf + client->pos,
               client->len - client->pos,
               MSG_DONTWAIT | MSG_NOSIGNAL);
    if (is_fatal(ret, errno)) {
        s_free(client->buf);
        client->buf = NULL;
        client->len = 0;
        client->state = MUX_WAITING_FOR_DATA;
        on_peer_error(channel);
        return 0;
    } else if (ret < 0) {
        return 0;
    }
    client->pos += ret;
    if (client->pos == client->len) {
        s_free(client->buf);
        client->buf = NULL;
        client->len = 0;
        client->state = MUX_WAITING_FOR_DATA;
    }
    return 0;
}

//------------------------------------------------------------------------------
static int
peer_read_at_wait(struct channel *channel)
{
    struct client *client = channel->client;
    client->state = MUX_SPLICING_TO_CLIENT_READING;
    client->buf = s_realloc(client->buf, BUFFER_MAX);
    client->len = BUFFER_MAX;
    return 0;
}

//------------------------------------------------------------------------------
static int
peer_read_at_data(struct channel *channel)
{
    struct client *client = channel->client;
    int ret;

    ret = recv(channel->peer, client->buf, client->len, MSG_DONTWAIT);
    if (ret == 0) {
        on_peer_shutrd(channel);
        return 0;
    } else if (is_fatal(ret, errno)) {
        s_free(client->buf);
        client->buf = NULL;
        client->len = 0;
        client->state = MUX_WAITING_FOR_DATA;
        on_peer_error(channel);
        return 0;
    } else if (ret < 0) {
        return 0;
    }
    client->len = ret;
    client->pos = 0;
    client->state = MUX_SPLICING_TO_CLIENT_WRITING_TAG;
    client->tag.length = htons(client->len);
    client->tag.channel = htons(channel->num_self);
    return 0;
}

//------------------------------------------------------------------------------
static int
client_write_at_tag(struct client *client)
{
    int ret;

    ret = send(client->clnt,
               client->pos + (uint8_t *)&client->tag,
               TURN_TAGLEN - client->pos,
               MSG_MORE | MSG_DONTWAIT);
    if (is_fatal(ret, errno)) {
        on_client_error(client);
        return -1;
    } else if (ret < 0) {
        return 0;
    }
    client->pos += ret;
    if (client->pos == TURN_TAGLEN) {
        client->pos = 0;
        client->state =  MUX_SPLICING_TO_CLIENT_WRITING_DATA;
    }
    return 0;
}

//------------------------------------------------------------------------------
static int
client_write_at_data(struct client *client)
{
    int ret;

    ret = send(client->clnt,
               client->buf + client->pos,
               client->len - client->pos,
               MSG_DONTWAIT);
    if (is_fatal(ret, errno)) {
        on_client_error(client);
        return -1;
    } else if (ret < 0) {
        return 0;
    }
    client->pos += ret;
    if (client->pos == client->len) {
        s_free(client->buf);
        client->buf = NULL;
        client->len = 0;
        client->state = MUX_WAITING_FOR_DATA;
    }
    return 0;
}

//------------------------------------------------------------------------------
static int
client_do_maintainance(struct client *client)
{
    struct stun_message *stun;
    struct channel *channel;
    int i;

    if (!client->need_maintain)
        return 0;

    /* Confirm the first client channel that hasn't been confirmed */
    for (i = 0; i < client->nchannels; i++) {
        channel = client->channels[i];
        if (channel->num_clnt && !channel->self_confirm) {
            channel->self_confirm = 1;
            if (client->protocol == IPPROTO_UDP) {
                assert(0);
            }
        }
    }

    return 0;
}

//------------------------------------------------------------------------------
static void
on_client_read(int fd, short ev, void *arg)
{
    struct client *client = (struct client *) arg;

    if (client->state == MUX_WAITING_FOR_DATA)
        if (client_read_at_wait(client) == -1)
            return;

    if (client->state == MUX_SPLICING_FROM_CLIENT_READING_TAG)
        if (client_read_at_tag(client) == -1)
            return;

    if (client->state == MUX_SPLICING_FROM_CLIENT_READING_DATA)
        if (client_read_at_data(client) == -1)
            return;

    if (client->state == MUX_WAITING_FOR_DATA)
        if (client_do_maintainance(client) == -1)
            return;

    client_set_events(client);
}

//------------------------------------------------------------------------------
static void
on_peer_write(int fd, short ev, void *arg)
{
    struct channel *channel = (struct channel *) arg;
    struct client *client = channel->client;

    if (client->state == MUX_SPLICING_FROM_CLIENT_WRITING)
        if (peer_write_at_data(channel) == -1)
            return;

    if (client->state == MUX_WAITING_FOR_DATA)
        if (client_do_maintainance(client) == -1)
            return;

    client_set_events(client);
}

//------------------------------------------------------------------------------
static void
channel_set_peer(struct channel *channel, int peer)
{
    channel->peer = peer;
    channel->ev_peerread = (struct event *) s_malloc(sizeof(struct event));
    channel->ev_peerwrite = (struct event *) s_malloc(sizeof(struct event));
    event_set(channel->ev_peerread, peer, EV_READ, on_peer_read, channel);
    event_set(channel->ev_peerwrite, peer, EV_WRITE, on_peer_write, channel);
}

//------------------------------------------------------------------------------
static void
on_peer_accept(int fd, short ev, void *arg)
{
    struct client *client = (struct client *) arg;
    struct channel *channel;
    struct permission *perm;
    int peer;
    struct sockaddr addr;
    socklen_t len;
    int i;

    assert(client->state == MUX_WAITING_FOR_DATA);

    len = sizeof(addr);
    if ((peer = accept(fd, &addr, &len)) == -1) {
        client_set_events(client);
        return;
    }

    for (i = 0; i < client->nperms; i++) {
        perm = client->perms[i];
        if (sockaddr_matches_addr(&addr, &perm->addr)) {
            channel = channel_new(client, perm);
            if (!channel) break;
            channel_set_peer(channel, peer);
            channel_queue_connstat(channel, &addr, len, TURN_CONNSTAT_ESTABLISHED);
            client_set_events(client);
            return;
        }
    }
    close(peer);
    client_set_events(client);
}

//------------------------------------------------------------------------------
static void
on_peer_recvfrom(int fd, short ev, void *arg)
{
    assert(0);
}

//------------------------------------------------------------------------------
static void
on_peer_read(int fd, short ev, void *arg)
{
    struct channel *channel = (struct channel *) arg;
    struct client *client = channel->client;

    if (client->state == MUX_WAITING_FOR_DATA)
        if (peer_read_at_wait(channel) == -1)
            return;

    if (client->state == MUX_SPLICING_TO_CLIENT_READING)
        if (peer_read_at_data(channel) == -1)
            return;

    if (client->state == MUX_WAITING_FOR_DATA)
        if (client_do_maintainance(client) == -1)
            return;

    client_set_events(client);
}

//------------------------------------------------------------------------------
static void
on_client_write(int fd, short ev, void *arg)
{
    struct client *client = (struct client *) arg;

    if (client->state == MUX_SPLICING_TO_CLIENT_WRITING_TAG)
        if (client_write_at_tag(client) == -1)
            return;

    if (client->state == MUX_SPLICING_TO_CLIENT_WRITING_DATA)
        if (client_write_at_data(client) == -1)
            return;

    if (client->state == MUX_WAITING_FOR_DATA)
        if (client_do_maintainance(client) == -1)
            return;

    client_set_events(client);
}

//------------------------------------------------------------------------------
static struct client *
client_new()
{
    struct client *client;
    client = s_malloc(sizeof(struct client));
    memset(client, 0, sizeof(struct client));
    client->peer = -1;
    return client;
}

//------------------------------------------------------------------------------
static void
on_srv_accept(int fd, short ev, void *arg)
{
    struct server *server = (struct server *) arg;
    struct client *client;
    int cli;
    socklen_t len;

    client = client_new();
    if (!client) {
        if ((cli = accept(fd, NULL, 0)) != -1)
            close(cli);
        return;
    }
    len = sizeof(client->addr);
    client->server = server;
    client->clnt = accept(fd, &client->addr, &len);
    client->state = MUX_WAITING_FOR_DATA;
    client->ev_cliread = (struct event *) s_malloc(sizeof(struct event));
    client->ev_cliwrite = (struct event *) s_malloc(sizeof(struct event));
    event_set(client->ev_cliread, client->clnt, EV_READ, on_client_read, client);
    event_set(client->ev_cliwrite, client->clnt, EV_WRITE, on_client_write, client);
    client_set_events(client);
}

//------------------------------------------------------------------------------
void *
turn_tcp_init()
{
    int fd;
    struct sockaddr_in sin;
    static int one = 1;
    struct server *server;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(PORT_TURN);

    fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(fd, (struct sockaddr *) &sin, sizeof(sin))
        || listen(fd, 5)) {
        close(fd);
        return NULL;
    }

    server = (struct server *) s_malloc(sizeof(struct server));
    server->sock = fd;
    event_set(&server->ev_accept, fd, EV_READ | EV_PERSIST,
              on_srv_accept, server);
    event_add(&server->ev_accept, NULL);
    return server;
}
