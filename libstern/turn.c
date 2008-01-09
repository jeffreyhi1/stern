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
    TS_BIND_REQUESTED,
    TS_BIND_DONE,
    TS_LISTEN_REQUESTED,
    TS_LISTEN_DONE,
    TS_CONNECT_REQUESTED,
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
    int confirmed;
    struct sockaddr addr;
    size_t addrlen;
};

struct turn_socket {
    enum turn_socket_operation  op;                    /* Active operation                 */
    enum turn_socket_state      state;                 /* Socket state                     */
    int                         family     , protocol; /* Application / peer socket type   */
    int                         nchannels;             /* Number of channels               */
    int                         sock;                  /* Socket to turn server. TCP only. */
    int                         last_channel;          /* Channel of last frame read       */
    size_t                      last_len;              /* Length of last frame read        */
    struct channel             *channels;              /* Channels                         */
    struct sockaddr             addr_self;             /* Relay address                    */
    struct stun_message        *request;               /* Last request                     */
    void                       *buf;                   /* Buffer                           */
    size_t                      pos;                   /* Bytes copied to user             */
};

//------------------------------------------------------------------------------
static int
channel_find_unused(struct turn_socket *turn)
{
    int chan, i, tries = 10;

    do {
        do {
            chan = rand() & 0xFFFF;
        } while (chan == 0);
        if (--tries == 0)
            assert(0);
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
static int
sockaddr_matches(struct sockaddr *addr1, struct sockaddr *addr2)
{
    struct sockaddr_in *sina = (struct sockaddr_in *) addr1;
    struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in *sinb = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *sin6b = (struct sockaddr_in6 *) addr2;

    if ((!addr1 && addr2) || (addr1 && !addr2))
        return 0;

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
    } else if (ret == -1 && (err == EINPROGRESS
                             || err == EAGAIN)) {
        turn->op = op_progress;
        return -1;
    } else if (ret == -1) {
        turn->op = TS_NONE;
        turn->state = TS_CLOSED;
        return -1;
    }
    /* unreachable */
    assert(0);
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
static int
send_to_server(struct turn_socket *turn, char *buf, size_t len, int channel)
{
    struct tag tag;
    struct iovec bufs[2];
    struct msghdr msg;
    int ret;

    tag.length = htons(len);
    tag.channel = htons(channel);

    bufs[0].iov_len = TURN_TAGLEN;
    bufs[0].iov_base = &tag;
    bufs[1].iov_len = len;
    bufs[1].iov_base = buf;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = bufs;
    msg.msg_iovlen = 2;

    /* Send full frames only */
    ret = sendmsg(turn->sock, &msg, MSG_NOSIGNAL);
    if (ret == -1 && errno != EAGAIN)
        return -1;
    else if (ret != len + TURN_TAGLEN)
        RETURN_ERROR(EMSGSIZE, -1);
    return 0;
}

//------------------------------------------------------------------------------
static int
recv_from_server(struct turn_socket *turn, char *buf, size_t blen, int *channel)
{
    struct tag tag;
    size_t pos, len;
    char *tbuf;
    int ret;

    /* Read tag */
    pos = 0;
    while (pos < 4) {
        ret = recv(turn->sock, pos + (char *)&tag, TURN_TAGLEN - pos, 0);
        if (ret == -1 && errno == EAGAIN) {
            if (pos == 0)
                return -1;
            else
                RETURN_ERROR(EMSGSIZE, -1);
        } else if (ret <= 0) {
            RETURN_ERROR(ECONNABORTED, -1);
        }
        pos += ret;
    }

    /* Read into provided buffer if data fits; else into alloc'ed buffer */
    len = ntohs(tag.length);
    *channel = ntohs(tag.channel);
    tbuf = buf;
    turn->last_len = len;
    turn->last_channel = *channel;
    if (turn->buf) {
        s_free(turn->buf);
        turn->buf = NULL;
    }
    if (len > blen) {
        turn->buf = s_malloc(len);
        tbuf = turn->buf;
    }
    pos = 0;

    /* Read data */
    while (pos < len) {
        ret = recv(turn->sock, pos + tbuf, len - pos, MSG_WAITALL);
        if (ret == -1) {
            RETURN_ERROR(EMSGSIZE, -1);
        } else if (ret == 0) {
            RETURN_ERROR(ECONNABORTED, -1);
        }
        pos += ret;
    }

    if (len > blen) {
        memcpy(buf, tbuf, blen);
        turn->pos = 0;
        return blen;
    } else {
        return len;
    }
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
    char buf[1024];
    size_t slen;
    int ret;
    int channel;

    /* Check no operation is pending (except another init) */
    if (turn->op != TS_NONE && turn->op != TS_BIND)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_INIT_DONE:
            turn->state = TS_BIND_REQUESTED;
            turn->request = stun_new(TURN_ALLOCATION_REQUEST);
            turnreq_set_requested_transport(turn->request, turn);
            slen = stun_to_bytes(buf, sizeof(buf), turn->request);
            ret = send_to_server(turn, buf, slen, TURN_CHANNEL_CTRL);
            if (is_sockerr(turn, ret, errno, TS_BIND, TS_BIND))
                return -1;

        case TS_BIND_REQUESTED:
            ret = recv_from_server(turn, buf, sizeof(buf), &channel);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_BIND))
                return -1;
            if (channel != TURN_CHANNEL_CTRL)
                RETURN_ERROR(EAGAIN, -1);
            slen = ret;
            response = stun_from_bytes(buf, &slen);
            if (!stun_xid_matches(response, turn->request))
                RETURN_ERROR(EAGAIN, -1);
            if (!stun_is_ok_response(response, turn->request))
                ABORT_SOCKET(turn, ECONNABORTED, -1);
            if (!response->relay_address || !response->xor_mapped_address)
                ABORT_SOCKET(turn, ECONNABORTED, -1);
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
    char buf[1024];
    size_t slen;
    int ret;
    int channel;

    /* Check no operation is pending (except another listen) */
    if (turn->op != TS_NONE && turn->op != TS_BIND && turn->op != TS_LISTEN)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_INIT_DONE:
        case TS_BIND_REQUESTED:
            ret = turn_bind(socket, NULL, 0);
            if (ret == -1) return -1;
            // Fallthrough

        case TS_BIND_DONE:
            turn->state = TS_LISTEN_REQUESTED;
            turn->request = stun_new(TURN_LISTEN_REQUEST);
            slen = stun_to_bytes(buf, sizeof(buf), turn->request);
            ret = send_to_server(turn, buf, slen, TURN_CHANNEL_CTRL);
            if (is_sockerr(turn, ret, errno, TS_LISTEN, TS_LISTEN))
                return -1;

        case TS_LISTEN_REQUESTED:
            ret = recv_from_server(turn, buf, sizeof(buf), &channel);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_LISTEN))
                return -1;
            if (channel != TURN_CHANNEL_CTRL)
                RETURN_ERROR(EAGAIN, -1);
            slen = ret;
            response = stun_from_bytes(buf, &slen);
            if (!stun_xid_matches(response, turn->request))
                RETURN_ERROR(EAGAIN, -1);
            if (!stun_is_ok_response(response, turn->request))
                ABORT_SOCKET(turn, ECONNABORTED, -1);
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
    char buf[1024];
    size_t slen;
    int ret;
    struct channel *channel;

    /* Check no operation is pending */
    if (turn->op != TS_NONE && turn->op != TS_LISTEN)
        RETURN_ERROR(EINVAL, -1);

    switch (turn->state) {
        case TS_LISTEN_REQUESTED:
            ret = turn_listen(socket, 0);
            if (ret == -1) return -1;
            // Fallthrough

        case TS_LISTEN_DONE:
            indication = stun_new(TURN_SEND_INDICATION);
            stun_set_peer_address(indication, addr, len);
            channel = channel_new(turn, addr, len);
            indication->channel = channel->num_self;
            slen = stun_to_bytes(buf, sizeof(buf), indication);
            ret = send_to_server(turn, buf, slen, TURN_CHANNEL_CTRL);
            stun_free(indication);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
                return -1;
            channel->confirmed = 1;
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
    if (!channel)
        RETURN_ERROR(EAGAIN, -1);

    copy_sockaddr(addr, alen, &channel->addr, channel->addrlen);

    /* Last frame was bigger than buf */
    if (len < turn->last_len) {
        turn->pos = len;
        turn->op = TS_RECV;
        return len;
    }

    return turn->last_len;
}

//------------------------------------------------------------------------------
static ssize_t
turn_recvfrom_cont(struct turn_socket *turn, char *buf, size_t len,
                   struct sockaddr *addr, socklen_t *alen)
{
    struct channel *channel;
    int ret;

    channel = channel_by_num(turn, turn->last_channel);
    if (!channel)
        RETURN_ERROR(EAGAIN, -1);

    copy_sockaddr(addr, alen, &channel->addr, channel->addrlen);

    ret = turn->last_len - turn->pos;
    ret = ret > len ? len : ret;
    memcpy(buf, turn->buf + turn->pos, ret);
    turn->pos += ret;
    if (turn->pos == turn->last_len) {
        turn->op = TS_NONE;
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
        channel->num_peer = stun->channel;
    }
    copy_sockaddr(addr, alen, &channel->addr, channel->addrlen);
    if (stun->connect_status == TURN_CONNSTAT_CLOSED)
        return 0;
    RETURN_ERROR(EAGAIN, -1);
}

//------------------------------------------------------------------------------
static ssize_t
turn_recvfrom_stun(struct turn_socket *turn, char *buf, size_t len,
                   struct sockaddr *addr, socklen_t *alen)
{
    struct stun_message *stun;
    size_t slen;
    char *sbuf;
    ssize_t ret;

    slen = turn->last_len;
    sbuf = turn->buf ? turn->buf : buf;

    stun = stun_from_bytes(buf, &slen);
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
    int channel;

    switch (turn->op) {
        /* Pending read from buffer */
        case TS_RECV:
            return turn_recvfrom_cont(turn, buf, len, addr, alen);

        /* Read more from socket */
        case TS_NONE:
            break;

        /* Some other op in progress */
        default:
            RETURN_ERROR(EINVAL, -1);
    }

    switch (turn->state) {
        case TS_LISTEN_DONE:
            ret = recv_from_server(turn, buf, len, &channel);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
                return -1;
            if (channel == TURN_CHANNEL_CTRL)
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

    ret = send_to_server(turn, buf, len, channel->num_self);
    if (ret == -1) return -1;

    return len;
}

//------------------------------------------------------------------------------
static ssize_t
turn_sendto_stun(struct turn_socket *turn, char *buf, size_t len, struct channel *channel)
{
    struct stun_message *indication;
    char sbuf[65536];
    size_t slen;
    int ret;

    indication = stun_new(TURN_SEND_INDICATION);
    stun_set_peer_address(indication, &channel->addr, channel->addrlen);
    indication->channel = channel->num_self;
    stun_set_data(indication, buf, len);
    slen = stun_to_bytes(sbuf, sizeof(sbuf), indication);
    ret = send_to_server(turn, sbuf, slen, TURN_CHANNEL_CTRL);
    stun_free(indication);
    if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
        return -1;
    channel->confirmed = 1;
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
            if ((channel = channel_by_addr(turn, addr, alen)) == NULL)
                channel = channel_new(turn, addr, alen);
            if (!channel->confirmed)
                return turn_sendto_stun(turn, buf, len, channel);
            else
                return turn_sendto_raw(turn, buf, len, channel);

        default:
            RETURN_ERROR(EINVAL, -1);
    }
}

//------------------------------------------------------------------------------
ssize_t
turn_shutdown(turn_socket_t socket, struct sockaddr *addr, socklen_t alen)
{
    struct turn_socket *turn = FROM_TS(socket);
    struct stun_message *indication;
    struct channel *channel;
    char sbuf[1024];
    size_t slen;
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
            slen = stun_to_bytes(sbuf, sizeof(sbuf), indication);
            ret = send_to_server(turn, sbuf, slen, TURN_CHANNEL_CTRL);
            stun_free(indication);
            if (is_sockerr(turn, ret, errno, TS_NONE, TS_NONE))
                return -1;
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
    if (turn->buf)
        s_free(turn->buf);
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
