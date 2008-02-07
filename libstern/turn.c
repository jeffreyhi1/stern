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

#define STUN_HLEN                 20

#define TO_TS(x)            ((turn_socket_t) (x))
#define FROM_TS(x)          ((struct turn_socket *) (x))
#define RETURN_ERROR(x,y)   do { errno = (x); return (y); } while(0)
#define ABORT_SOCKET(t,x,y) do {(t)->state = TS_CLOSED; RETURN_ERROR((x),(y)); } while(0)

#pragma pack(push)
struct tag {
    uint16_t channel;
    uint16_t length;
};
#pragma pack(pop)

enum turn_socket_state {
    TS_NEW,
    TS_INIT_CONNECTING,
    TS_INIT_DONE,
    TS_BIND_REQUEST_QUEUED,
    TS_BIND_REQUEST_SENT,
    TS_BIND_DONE,
    TS_LISTEN_REQUEST_QUEUED,
    TS_LISTEN_REQUEST_SENT,
    TS_LISTEN_DONE,
    TS_PERMIT_INDICATION_QUEUED,
    TS_SHUTDOWN_QUEUED,
    TS_CONNECT_REQUEST_QUEUED,
    TS_CONNECT_REQUEST_SENT,
    TS_CONNECT_DONE,
    TS_CLOSED
};

enum turn_socket_operation {
    TS_NONE,
    TS_INIT,
    TS_BIND,
    TS_LISTEN,
    TS_CONNECT,
    TS_RECV
};

struct channel {
    int num_self, num_peer;
    int peer_confirm;   /* Whether server has confirmed our number   */
    int self_confirm;   /* Whether we have confirmed server's number */
    struct sockaddr addr;
    socklen_t addrlen;
};

struct turn_socket {
    enum turn_socket_operation  op;                    /* Active operation                       */
    enum turn_socket_state      state;                 /* Socket state                           */
    int                         family     , protocol; /* Application / peer socket type         */
    int                         nchannels;             /* Number of channels                     */
    int                         sock;                  /* Socket to turn server. TCP only.       */
    int                         last_channel;          /* Channel of last frame read             */
    size_t                      last_framelen;         /* Length of last frame read (incl. hdrs) */
    size_t                      last_rawlen;           /* Length of last raw frame payload       */
    struct channel             *channels;              /* Channels                               */
    struct sockaddr             addr_self;             /* Relay address                          */
    struct stun_message        *request;               /* Last request                           */
    struct buffer               rbuf;                  /* Buffer for incoming network data       */
    struct buffer               wbuf;                  /* Buffer for outgoing network data       */
    size_t                      pos;                   /* Bytes copied to user                   */
};

//------------------------------------------------------------------------------
static int
channel_find_unused(struct turn_socket *turn)
{
    int chan, i, tries = 10;

    do {
        chan = rand() & 0xFFFF;
        chan |= ((rand() + 1) & 0x3) << 14;
        if (--tries == 0)
            return -1;
        for (i = 0; i < turn->nchannels; i++)
            if (turn->channels[i].num_self == chan)
                break;
    } while (i < turn->nchannels);

    return chan;
}

//------------------------------------------------------------------------------
static void
copy_sockaddr(struct sockaddr *addra, socklen_t *alen, struct sockaddr *addrb, socklen_t blen)
{
    if (alen && addra) {
        *alen = (*alen < blen ? *alen : blen);
        memcpy(addra, addrb, *alen);
    }
}

//------------------------------------------------------------------------------
static struct channel *
channel_new(struct turn_socket *turn, struct sockaddr *addr, socklen_t len)
{
    struct channel *channel;
    int chan;

    chan = channel_find_unused(turn);
    if (chan == -1)
        return NULL;
    turn->channels = (struct channel *) s_realloc(
            turn->channels,
            (++turn->nchannels) * sizeof(struct channel));
    channel = &turn->channels[turn->nchannels - 1];
    memset(channel, 0, sizeof(struct channel));
    channel->num_self = chan;
    channel->addrlen = sizeof(channel->addr);
    copy_sockaddr(&channel->addr, &channel->addrlen, addr, len);
    return channel;
}

//------------------------------------------------------------------------------
static struct channel *
channel_by_addr(struct turn_socket *turn, struct sockaddr *addr, socklen_t len)
{
    int i;

    for (i = 0; i < turn->nchannels; i++)
        if (sockaddr_matches(&turn->channels[i].addr, addr))
            return &turn->channels[i];
    return NULL;
}


//------------------------------------------------------------------------------
static struct channel *
channel_by_num(struct turn_socket *turn, int num_peer)
{
    int i;

    for (i = 0; i < turn->nchannels; i++)
        if (turn->channels[i].num_peer == num_peer)
            return &turn->channels[i];
    return NULL;
}

//------------------------------------------------------------------------------
static int
is_sockerr(struct turn_socket *turn, int ret, int err, int op_success, int op_progress)
{
    if (ret >= 0) {
        turn->op = op_success;
        return 0;
    } else if (ret == -1 && (err == EINPROGRESS || err == EAGAIN)) {
        turn->op = op_progress;
        return -1;
    } else {
        turn->op = TS_NONE;
        turn->state = TS_CLOSED;
        return -1;
    }
}

//------------------------------------------------------------------------------
static struct turn_socket *
socket_new(int family, int type, int protocol)
{
    struct turn_socket *turn;

    turn = (struct turn_socket *) s_malloc(sizeof(struct turn_socket));
    memset(turn, 0, sizeof(struct turn_socket));
    turn->family = family;
    turn->protocol = protocol;
    if (protocol == 0)
        turn->protocol = type == SOCK_STREAM ? IPPROTO_TCP : IPPROTO_UDP;
    turn->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    turn->state = TS_NEW;
    return turn;
}

//------------------------------------------------------------------------------
static void
queue_raw_frame(struct turn_socket *turn, char *buf, size_t len, int chan)
{
    struct tag *tag;
    struct buffer *wbuf = &turn->wbuf;

    while (b_num_free(wbuf) < TURN_TAGLEN + len)
        b_grow(wbuf);
    tag = (struct tag *) b_pos_free(wbuf);
    tag->length = htons(len);
    tag->channel = htons(chan);
    memcpy(b_pos_free(wbuf) + TURN_TAGLEN, buf, len);
    b_used_free(wbuf, len + TURN_TAGLEN);
}

//------------------------------------------------------------------------------
static void
queue_stun_frame(struct turn_socket *turn, struct stun_message *stun)
{
    int ret = 0;
    struct buffer *wbuf = &turn->wbuf;

    while (1) {
        ret = stun_to_bytes(b_pos_free(wbuf), b_num_free(wbuf), stun);
        if (ret > 0) {
            b_used_free(wbuf, ret);
            break;
        }
        b_grow(wbuf);
    }
}

//------------------------------------------------------------------------------
static int
send_frame(struct turn_socket *turn)
{
    return b_send(&turn->wbuf, turn->sock, MSG_NOSIGNAL);
}

//------------------------------------------------------------------------------
static int
recv_frame(struct turn_socket *turn)
{
    struct tag *tag;
    int len, ret;
    struct buffer *rbuf = &turn->rbuf;

    do {
        len = b_num_avail(rbuf);
        if (len < TURN_TAGLEN)
            ret = b_recv(rbuf, turn->sock, TURN_TAGLEN - len, 0);
        else if (b_num_avail(rbuf) < turn->last_framelen)
            ret = b_recv(rbuf, turn->sock, turn->last_framelen - len, 0);
        else
            break;

        if (ret == 0) RETURN_ERROR(ECONNABORTED, -1);
        else if (ret < 0) return ret;
        if (b_num_avail(rbuf) == TURN_TAGLEN) {
            tag = (struct tag *) b_pos_avail(rbuf);
            if (IS_STUN_CHANNEL(ntohs(tag->channel))) {
                turn->last_channel = TURN_CHANNEL_CTRL;
                turn->last_framelen = ntohs(tag->length) + STUN_HLEN;
            } else {
                turn->last_channel = ntohs(tag->channel);
                turn->last_framelen = ntohs(tag->length) + TURN_TAGLEN;
                turn->last_rawlen = ntohs(tag->length);
            }
        }
    } while (1);
    return turn->last_framelen;
}


//------------------------------------------------------------------------------
static void
discard_last_frame(struct turn_socket * turn)
{
    b_used_avail(&turn->rbuf, turn->last_framelen);
    b_shrink(&turn->rbuf);
}

//------------------------------------------------------------------------------
static struct stun_message *
stun_from_frame(struct turn_socket * turn)
{
    struct stun_message *stun;
    struct buffer *rbuf = &turn->rbuf;
    size_t slen = turn->last_framelen;

    stun = stun_from_bytes(b_pos_avail(rbuf), &slen);
    discard_last_frame(turn);
    return stun;
}

//------------------------------------------------------------------------------
turn_socket_t
turn_socket(int family, int type, int protocol)
{
    struct turn_socket *turn;

    /* Only IPv4 supported for now */
    if (family != AF_INET)
        RETURN_ERROR(EINVAL, NULL);

    /* Only TCP supported for now */
    if (!(type == SOCK_STREAM && (protocol == 0 || protocol == IPPROTO_TCP)))
        RETURN_ERROR(EINVAL, NULL);

    turn = socket_new(family, type, protocol);

    return TO_TS(turn);
}

//------------------------------------------------------------------------------
int
turn_init(turn_socket_t socket, struct sockaddr *addr, socklen_t len)
{
    struct turn_socket *turn = FROM_TS(socket);
    int ret;

    /* Check no operation is pending (except another init) */
    if (turn->op != TS_NONE && turn->op != TS_INIT)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        /* New socket. Connect to turn server */
        case TS_NEW:
            turn->state = TS_INIT_CONNECTING;
            // Fallthrough

        case TS_INIT_CONNECTING:
            ret = connect(turn->sock, addr, len);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_INIT))
                return -1;
            turn->state = TS_INIT_DONE;
            return ret;

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
static void
turnreq_set_requested_transport(struct stun_message * stun, struct turn_socket *turn)
{
    if (turn->protocol == IPPROTO_TCP)
        stun->requested_transport = TURN_TRANSPORT_TCP;
    else if (turn->protocol == IPPROTO_UDP)
        stun->requested_transport = TURN_TRANSPORT_UDP;
}

//------------------------------------------------------------------------------
int
turn_bind(turn_socket_t socket, struct sockaddr *addr, socklen_t len)
{
    struct turn_socket *turn = FROM_TS(socket);
    struct stun_message *response;
    int ret;

    /* Check no operation is pending (except another init) */
    if (turn->op != TS_NONE && turn->op != TS_BIND)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_INIT_DONE:
            turn->state = TS_BIND_REQUEST_QUEUED;
            turn->request = stun_new(TURN_ALLOCATION_REQUEST);
            turnreq_set_requested_transport(turn->request, turn);
            queue_stun_frame(turn, turn->request);

        case TS_BIND_REQUEST_QUEUED:
            ret = send_frame(turn);
            if (is_sockerr(turn, ret, errno, TS_BIND, TS_BIND))
                return -1;
            if (!b_is_empty(&turn->wbuf))
                RETURN_ERROR(EAGAIN, -1);
            turn->state = TS_BIND_REQUEST_SENT;

        case TS_BIND_REQUEST_SENT:
            ret = recv_frame(turn);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_BIND))
                return -1;
            if (turn->last_channel != TURN_CHANNEL_CTRL) {
                discard_last_frame(turn);
                RETURN_ERROR(EAGAIN, -1);
            }
            response  = stun_from_frame(turn);
            if (!response)
                RETURN_ERROR(EAGAIN, -1);
            if (!stun_xid_matches(response, turn->request)) {
                stun_free(response);
                RETURN_ERROR(EAGAIN, -1);
            }
            if (!stun_is_ok_response(response, turn->request)) {
                stun_free(response);
                ABORT_SOCKET(turn, ECONNABORTED, -1);
            }
            if (!response->relay_address || !response->xor_mapped_address) {
                stun_free(response);
                ABORT_SOCKET(turn, ECONNABORTED, -1);
            }
            memcpy(&turn->addr_self, response->relay_address, response->relay_address_len);
            turn->state = TS_BIND_DONE;
            stun_free(response);
            stun_free(turn->request);
            turn->request = NULL;
            return 0;

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
int
turn_getsockname(turn_socket_t socket, struct sockaddr *addr, socklen_t *len)
{
    struct turn_socket *turn = FROM_TS(socket);

    if (turn->state < TS_BIND_DONE || turn->state >= TS_CLOSED)
        RETURN_ERROR(EINVAL, -1);

    memcpy(addr, &turn->addr_self, *len);
    return 0;
}

//------------------------------------------------------------------------------
int
turn_listen(turn_socket_t socket, int limit)
{
    struct turn_socket *turn = FROM_TS(socket);
    struct stun_message *response;
    int ret;

    /* Check no operation is pending (except another listen) */
    if (turn->op != TS_NONE && turn->op != TS_BIND && turn->op != TS_LISTEN)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_INIT_DONE:
        case TS_BIND_REQUEST_QUEUED:
        case TS_BIND_REQUEST_SENT:
            ret = turn_bind(socket, NULL, 0);
            if (ret == -1) return -1;
            // Fallthrough

        case TS_BIND_DONE:
            turn->state = TS_LISTEN_REQUEST_QUEUED;
            turn->request = stun_new(TURN_LISTEN_REQUEST);
            queue_stun_frame(turn, turn->request);

        case TS_LISTEN_REQUEST_QUEUED:
            ret = send_frame(turn);
            if (is_sockerr(turn, ret, errno, TS_LISTEN, TS_LISTEN))
                return -1;
            if (!b_is_empty(&turn->wbuf))
                RETURN_ERROR(EAGAIN, -1);
            turn->state = TS_LISTEN_REQUEST_SENT;

        case TS_LISTEN_REQUEST_SENT:
            ret = recv_frame(turn);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_LISTEN))
                return -1;
            if (turn->last_channel != TURN_CHANNEL_CTRL) {
                discard_last_frame(turn);
                RETURN_ERROR(EAGAIN, -1);
            }
            response = stun_from_frame(turn);
            if (!stun_xid_matches(response, turn->request)) {
                stun_free(response);
                RETURN_ERROR(EAGAIN, -1);
            }
            if (!stun_is_ok_response(response, turn->request)) {
                stun_free(response);
                ABORT_SOCKET(turn, ECONNABORTED, -1);
            }
            turn->state = TS_LISTEN_DONE;
            stun_free(response);
            stun_free(turn->request);
            turn->request = NULL;
            return 0;

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
int
turn_permit(turn_socket_t socket, struct sockaddr *addr, socklen_t len)
{
    struct turn_socket *turn = FROM_TS(socket);
    struct stun_message *indication;
    int ret;
    struct channel *channel;

    /* Check no operation is pending */
    if (turn->op != TS_NONE && turn->op != TS_LISTEN)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_LISTEN_REQUEST_QUEUED:
        case TS_LISTEN_REQUEST_SENT:
            ret = turn_listen(socket, 0);
            if (ret == -1) return -1;
            // Fallthrough

        case TS_LISTEN_DONE:
            if ((channel = channel_new(turn, addr, len)) == NULL)
                RETURN_ERROR(ENOMEM, -1);
            indication = stun_new(TURN_SEND_INDICATION);
            stun_set_peer_address(indication, addr, len);
            indication->channel = channel->num_self;
            queue_stun_frame(turn, indication);
            stun_free(indication);
            turn->state = TS_PERMIT_INDICATION_QUEUED;

        case TS_PERMIT_INDICATION_QUEUED:
            ret = send_frame(turn);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
                return -1;
            if (!b_is_empty(&turn->wbuf))
                RETURN_ERROR(EAGAIN, -1);
            turn->state = TS_LISTEN_DONE;
            channel->peer_confirm = 1;
            return 0;

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
static ssize_t
turn_recvfrom_raw(struct turn_socket *turn, char *buf, size_t len,
                   struct sockaddr *addr, socklen_t *alen)
{
    struct channel *channel;

    channel = channel_by_num(turn, turn->last_channel);
    if (!channel) {
        discard_last_frame(turn);
        RETURN_ERROR(EAGAIN, -1);
    }

    copy_sockaddr(addr, alen, &channel->addr, channel->addrlen);

    len = (turn->last_rawlen < len) ? turn->last_rawlen : len;
    memcpy(buf, b_pos_avail(&turn->rbuf) + TURN_TAGLEN, len);
    if (len < turn->last_rawlen) {
        turn->pos = len;
        turn->op = TS_RECV;
        return len;
    } else {
        discard_last_frame(turn);
    }

    return turn->last_rawlen;
}

//------------------------------------------------------------------------------
static ssize_t
turn_recvfrom_cont(struct turn_socket *turn, char *buf, size_t len,
                   struct sockaddr *addr, socklen_t *alen)
{
    struct channel *channel;
    int ret;

    channel = channel_by_num(turn, turn->last_channel);
    if (!channel) {
        discard_last_frame(turn);
        RETURN_ERROR(EINVAL, -1);
    }

    copy_sockaddr(addr, alen, &channel->addr, channel->addrlen);

    ret = turn->last_rawlen - turn->pos;
    ret = ret > len ? len : ret;
    memcpy(buf, b_pos_avail(&turn->rbuf) + TURN_TAGLEN + turn->pos, ret);
    turn->pos += ret;
    if (turn->pos == turn->last_rawlen) {
        turn->op = TS_NONE;
        discard_last_frame(turn);
    }

    return ret;
}

//------------------------------------------------------------------------------
static ssize_t
turn_recvfrom_connstat(struct turn_socket *turn, struct stun_message *stun,
                            struct sockaddr * addr, socklen_t * alen)
{
    struct channel *channel;

    if (!stun->peer_address || stun->channel == -1 || stun->connect_status == -1)
        RETURN_ERROR(EAGAIN, -1);

    if ((channel = channel_by_num(turn, stun->channel)) == NULL) {
        channel = channel_new(turn, stun->peer_address,
                              stun->peer_address_len);
        if (!channel)
            RETURN_ERROR(EAGAIN, -1);
        channel->num_peer = stun->channel;
        channel->self_confirm = 1;
    }
    copy_sockaddr(addr, alen, &channel->addr, channel->addrlen);
    switch (stun->connect_status) {
        case TURN_CONNSTAT_CLOSED:
            return 0;
        case TURN_CONNSTAT_ESTABLISHED:
            RETURN_ERROR(EAGAIN, -2);
        default:
            RETURN_ERROR(EAGAIN, -1);
    }
}

//------------------------------------------------------------------------------
static ssize_t
turn_recvfrom_stun(struct turn_socket *turn, char *buf, size_t len,
                   struct sockaddr *addr, socklen_t *alen)
{
    struct stun_message *stun;
    ssize_t ret;

    stun  = stun_from_frame(turn);
    if (!stun)
        RETURN_ERROR(EAGAIN, -1);

    if (stun->message_type == TURN_CONN_STAT_INDICATION) {
        ret = turn_recvfrom_connstat(turn, stun, addr, alen);
        stun_free(stun);
        return ret;
    }

    stun_free(stun);
    RETURN_ERROR(EAGAIN, -1);
}

//------------------------------------------------------------------------------
ssize_t
turn_recvfrom(turn_socket_t socket, char *buf, size_t len,
              struct sockaddr *addr, socklen_t *alen)
{
    struct turn_socket *turn = FROM_TS(socket);
    int ret;

    switch (turn->op) {
        case TS_RECV: // Read pending data
            return turn_recvfrom_cont(turn, buf, len, addr, alen);
        case TS_NONE:
            break;
        default:
            RETURN_ERROR(EINVAL, -1);
    }

    switch (turn->state) {
        case TS_LISTEN_DONE:
            ret = recv_frame(turn);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
                return -1;
            if (turn->last_channel == TURN_CHANNEL_CTRL)
                return turn_recvfrom_stun(turn, buf, len, addr, alen);
            else
                return turn_recvfrom_raw(turn, buf, len, addr, alen);

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
static ssize_t
turn_sendto_raw(struct turn_socket *turn, char *buf, size_t len, struct channel *channel)
{
    int ret;

    queue_raw_frame(turn, buf, len, channel->num_self);
    ret = send_frame(turn);
    if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
        return -1;

    return len;
}

//------------------------------------------------------------------------------
static ssize_t
turn_sendto_stun(struct turn_socket *turn, char *buf, size_t len, struct channel *channel)
{
    struct stun_message *indication;
    int ret;

    indication = stun_new(TURN_SEND_INDICATION);
    stun_set_peer_address(indication, &channel->addr, channel->addrlen);
    indication->channel = channel->num_self;
    stun_set_data(indication, buf, len);
    queue_stun_frame(turn, indication);
    stun_free(indication);
    ret = send_frame(turn);
    if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
        return -1;
    channel->peer_confirm = 1;
    return len;
}

//------------------------------------------------------------------------------
ssize_t
turn_sendto(turn_socket_t socket, char *buf, size_t len,
            struct sockaddr *addr, socklen_t alen)
{
    struct turn_socket *turn = FROM_TS(socket);
    struct channel *channel;

    /* Check no operation is pending */
    if (turn->op != TS_NONE && turn->op != TS_RECV)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_LISTEN_DONE:
            if ((channel = channel_by_addr(turn, addr, alen)) == NULL) {
                if (turn->protocol == IPPROTO_TCP)
                    RETURN_ERROR(EINVAL, -1);
                else
                    if ((channel = channel_new(turn, addr, alen)) == NULL)
                        RETURN_ERROR(ENOMEM, -1);
            }
            if (!channel->peer_confirm)
                return turn_sendto_stun(turn, buf, len, channel);
            else
                return turn_sendto_raw(turn, buf, len, channel);

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
int
turn_shutdown(turn_socket_t socket, struct sockaddr *addr, socklen_t alen)
{
    struct turn_socket *turn = FROM_TS(socket);
    struct stun_message *indication;
    struct channel *channel;
    int ret;

    /* Check no operation is pending */
    if (turn->op != TS_NONE && turn->op != TS_RECV)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_LISTEN_DONE:
            if ((channel = channel_by_addr(turn, addr, alen)) == NULL)
                RETURN_ERROR(EINVAL, -1);
            indication = stun_new(TURN_CONN_STAT_INDICATION);
            stun_set_peer_address(indication, &channel->addr, channel->addrlen);
            indication->channel = channel->num_self;
            indication->connect_status = TURN_CONNSTAT_CLOSED;
            queue_stun_frame(turn, indication);
            stun_free(indication);
            turn->state = TS_SHUTDOWN_QUEUED;

        case TS_SHUTDOWN_QUEUED:
            ret = send_frame(turn);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
                return -1;
            if (!b_is_empty(&turn->wbuf))
                RETURN_ERROR(EAGAIN, -1);
            turn->state = TS_LISTEN_DONE;
            return 0;

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
void
turn_close(turn_socket_t socket)
{
    struct turn_socket *turn = FROM_TS(socket);

    if (turn->sock != -1)
        close(turn->sock);
    if (turn->request)
        stun_free(turn->request);
    b_reset(&turn->rbuf);
    b_reset(&turn->wbuf);
    s_free(turn->channels);
    s_free(turn);
}

//------------------------------------------------------------------------------
int
turn_set_nonblocking(turn_socket_t socket)
{
    struct turn_socket *turn = FROM_TS(socket);
    int flags;

    if ((flags = fcntl(turn->sock, F_GETFL, 0)) == -1
        || fcntl(turn->sock, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;
    return 0;
}

//------------------------------------------------------------------------------
int
turn_get_selectable_fd(turn_socket_t socket)
{
    struct turn_socket *turn = FROM_TS(socket);

    if (turn->state >= TS_CLOSED)
        RETURN_ERROR(EINVAL, -1);
    return turn->sock;
}
