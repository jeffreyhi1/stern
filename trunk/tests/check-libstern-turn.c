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
#include "check-libstern.h"

#include <netinet/tcp.h>

#define CHAN_1    0x4001
#define CHAN_2    0x4002
#define CHAN_42   0x4042

turn_socket_t tsock;
int srv, cli;
struct sockaddr caddr, raddr;
socklen_t caddrlen = sizeof(caddr);
unsigned int channel, length;
char buf[8192];

enum fuzz {
    F_SUCCESS               = 0,
    F_ERROR                 = 1 << 0,
    F_READERR_SHUT          = 1 << 1,
    F_READERR_INTERRUPTED   = 1 << 2,
    F_READERR_CORRUPTED     = 1 << 3,
    F_WRITEERR              = 1 << 4,
    F_XACT_ID               = 1 << 5,
    F_CHANNEL               = 1 << 6,
    F_NO_PEER_ADDRESS       = 1 << 7,
    F_NO_XOR_MAPPED_ADDRESS = 1 << 8,
    F_NO_BANDWIDTH          = 1 << 9,
    F_NO_LIFETIME           = 1 << 10,
    F_NO_RELAY_ADDRESS      = 1 << 11,
    F_NO_CHANNEL            = 1 << 12,
    F_NO_CONNECT_STATUS     = 1 << 13,
};

enum op {
    T_INIT        = 1 << 0,
    T_BIND        = 1 << 1,
    T_GETSOCKNAME = 1 << 2,
    T_LISTEN      = 1 << 3,
    T_PERMIT      = 1 << 4,
    T_CONNECT     = 1 << 5,
    T_RECVFROM    = 1 << 6,
    T_SENDTO      = 1 << 7,
    T_SHUTDOWN    = 1 << 8,
};

//------------------------------------------------------------------------------
static void
check_sockaddr(struct sockaddr *addr1, socklen_t alen1, struct sockaddr *addr2, socklen_t alen2)
{
    struct sockaddr_in *sina = (struct sockaddr_in *) addr1;
    struct sockaddr_in *sinb = (struct sockaddr_in *) addr2;
    struct sockaddr_in6 *sin6a = (struct sockaddr_in6 *) addr1;
    struct sockaddr_in6 *sin6b = (struct sockaddr_in6 *) addr2;

    fail_unless(alen1 == alen2, "Bad length");
    fail_unless(addr1->sa_family == addr2->sa_family, "Bad family");
    if (addr1->sa_family == AF_INET) {
        fail_unless(sina->sin_addr.s_addr == sinb->sin_addr.s_addr, "Bad address");
        fail_unless(sina->sin_port == sinb->sin_port, "Bad port");
    } else if (addr1->sa_family == AF_INET6) {
        fail_unless(memcmp(sin6a->sin6_addr.s6_addr, sin6b->sin6_addr.s6_addr, 16) == 0, "Bad address");
        fail_unless(sin6a->sin6_port == sin6b->sin6_port, "Bad port");
    }
}

//------------------------------------------------------------------------------
static void
tcpsock_opmutex(enum op op)
{
    int ret;

    if (op & T_INIT) {
        ret = turn_init(tsock, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Init should not be allowed");
    }

    if (op & T_BIND) {
        ret = turn_bind(tsock, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Bind should not be allowed");
    }

    if (op & T_LISTEN) {
        ret = turn_listen(tsock, 5);
        fail_unless(ret == -1 && errno == EINVAL, "Listen should not be allowed");
    }

    if (op & T_PERMIT) {
        ret = turn_permit(tsock, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Permit should not be allowed");
    }

#if 0
    if (op & T_CONNECT) {
        ret = turn_connect(tsock, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Connect should not be allowed");
    }
#endif

    if (op & T_RECVFROM) {
        ret = turn_recvfrom(tsock, NULL, 0, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Recv should not be allowed");
    }

    if (op & T_SENDTO) {
        ret = turn_sendto(tsock, NULL, 0, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Send should not be allowed");
    }

    if (op & T_SHUTDOWN) {
        ret = turn_shutdown(tsock, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Shutdown should not be allowed");
    }

    if (op & T_GETSOCKNAME) {
        ret = turn_getsockname(tsock, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Getsockname should not be allowed");
    }

}

//------------------------------------------------------------------------------
static void
tcpsock_setup()
{
    struct sockaddr addr;
    socklen_t addrlen = sizeof(addr);
    static int one = 1;
    int ret;

    srv = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    listen(srv, 1);
    getsockname(srv, &addr, &addrlen);

    tsock = turn_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    fail_if(tsock == NULL, "Socket error");

    ret = turn_init(tsock, &addr, addrlen);
    fail_if(ret == -1, "Initialization failed");

    cli = accept(srv, &caddr, &caddrlen);
    fail_if(cli == -1, "No connection received");

    setsockopt(cli, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    ret = turn_set_nonblocking(tsock);
    fail_if(ret == -1, "Failed nonblocking IO");

    // fcntl(cli, F_SETFL, O_NONBLOCK);

    tcpsock_opmutex(~(T_BIND|T_LISTEN));
}

//------------------------------------------------------------------------------
static struct stun_message *
mocktcpsrv_read()
{
    int ret;
    size_t slen;
    uint16_t val;
    struct stun_message *turn;

    ret = read(cli, &val, sizeof(val));
    fail_unless(ret == 2, "Invalid read");
    channel = ntohs(val);

    ret = read(cli, &val, sizeof(val));
    fail_unless(ret == 2, "Invalid read");
    length = ntohs(val);

    if (IS_STUN_CHANNEL(channel)) {
        ret = read(cli, buf + TURN_TAGLEN, length + STUN_HLEN - TURN_TAGLEN);
        fail_unless(ret == length + STUN_HLEN - TURN_TAGLEN, "Invalid read");
        *((uint16_t *) &buf[0]) = htons(channel);
        *((uint16_t *) &buf[2]) = htons(length);
        length = length + STUN_HLEN;
        slen = length;
        turn = stun_from_bytes(buf, &slen);
        fail_if(turn == NULL, "Invalid message");
        return turn;
    } else {
        ret = read(cli, buf, length);
        fail_unless(ret == length, "Invalid read");
    }

    return NULL;
}

//------------------------------------------------------------------------------
static void
mocktcpsrv_write(char *buf, int channel, int len, enum fuzz fuzz)
{
    uint16_t val1, val2;

    if (channel != TURN_CHANNEL_CTRL) {
        val1 = htons(channel);
        val2 = htons(len);
        fail_if(send(cli, &val1, sizeof(val1), MSG_MORE) != 2, "Invalid write");
        fail_if(send(cli, &val2, sizeof(val2), MSG_MORE) != 2, "Invalid write");
    }
    if (!(fuzz & F_READERR_INTERRUPTED))
        fail_if(send(cli, buf, len, 0) != len, "Invalid write");
    else
        close(cli);
}

//------------------------------------------------------------------------------
static void
mocksrv_do_bind(enum fuzz fuzz)
{
    struct sockaddr_in *sin;
    struct stun_message *request, *response;
    int channel, len;

    sin = (struct sockaddr_in *) &raddr;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = rand();
    sin->sin_port = rand();

    request = mocktcpsrv_read();
    fail_unless(request->message_type == TURN_ALLOCATION_REQUEST, "Bad request");
    fail_unless(request->requested_transport == TURN_TRANSPORT_TCP, "Bad transport");

    if (!(fuzz & F_ERROR))
        response = stun_init_response(TURN_ALLOCATION_SUCCESS, request);
    else
        response = stun_init_response(TURN_ALLOCATION_ERROR, request);

    if (fuzz & F_XACT_ID)
        response->xact_id[5] ^= 0xff;
    if (!(fuzz & F_NO_RELAY_ADDRESS))
        stun_set_relay_address(response, &raddr, sizeof(struct sockaddr_in));
    if (!(fuzz & F_NO_XOR_MAPPED_ADDRESS))
        stun_set_xor_mapped_address(response, &caddr, caddrlen);
    if (!(fuzz & F_NO_BANDWIDTH))
        response->bandwidth = 10;
    if (!(fuzz & F_NO_LIFETIME))
        response->lifetime = 600;

    if (!(fuzz & F_CHANNEL))
        channel = TURN_CHANNEL_CTRL;
    else
        channel = CHAN_42;

    if (!(fuzz & F_READERR_SHUT)) {
        len = stun_to_bytes(buf, sizeof(buf), response);
        if (fuzz & F_READERR_CORRUPTED)
            buf[4] = 0x00;
        mocktcpsrv_write(buf, channel, len, fuzz);
    } else {
        close(cli);
    }
    stun_free(request);
    stun_free(response);
}

//------------------------------------------------------------------------------
static void
mocksrv_do_permit()
{
    struct stun_message *request;

    request = mocktcpsrv_read();
    fail_unless(request->message_type == TURN_SEND_INDICATION, "Bad request");
    fail_if(request->channel == -1, "Bad channel");
    fail_if(request->peer_address == NULL, "Bad peer address");

    stun_free(request);
}

//------------------------------------------------------------------------------
static void
mocksrv_do_listen(enum fuzz fuzz)
{
    struct sockaddr_in sin;
    struct stun_message *request, *response;
    int channel, len;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = rand();
    sin.sin_port = rand();

    request = mocktcpsrv_read();
    fail_unless(request->message_type == TURN_LISTEN_REQUEST, "Bad request");

    if (!(fuzz & F_ERROR))
        response = stun_init_response(TURN_LISTEN_SUCCESS, request);
    else
        response = stun_init_response(TURN_LISTEN_ERROR, request);

    if (fuzz & F_XACT_ID)
        response->xact_id[5] ^= 0xff;
    if (!(fuzz & F_NO_LIFETIME))
        response->lifetime = 600;

    if (!(fuzz & F_CHANNEL))
        channel = TURN_CHANNEL_CTRL;
    else
        channel = CHAN_42;

    if (!(fuzz & F_READERR_SHUT)) {
        len = stun_to_bytes(buf, sizeof(buf), response);
        if (fuzz & F_READERR_CORRUPTED)
            buf[4] = 0x00;
        mocktcpsrv_write(buf, channel, len, fuzz);
    } else {
        close(cli);
    }
    stun_free(request);
    stun_free(response);
}

//------------------------------------------------------------------------------
static void
mocksrv_do_accept(struct sockaddr *sin, socklen_t len, int chan, enum fuzz fuzz)
{
    struct stun_message *response;

    if (!(fuzz & F_ERROR))
        response = stun_new(TURN_CONN_STAT_INDICATION);
    else
        response = stun_new(TURN_ALLOCATION_ERROR);

    if (!(fuzz & F_NO_PEER_ADDRESS))
        stun_set_peer_address(response, sin, len);
    if (!(fuzz & F_NO_CHANNEL))
        response->channel = chan;
    if (!(fuzz & F_NO_CONNECT_STATUS))
        response->connect_status = TURN_CONNSTAT_ESTABLISHED;

    if (!(fuzz & F_CHANNEL))
        channel = TURN_CHANNEL_CTRL;
    else
        channel = CHAN_42;

    if (!(fuzz & F_READERR_SHUT)) {
        len = stun_to_bytes(buf, sizeof(buf), response);
        if (fuzz & F_READERR_CORRUPTED)
            buf[4] = 0x00;
        mocktcpsrv_write(buf, channel, len, fuzz);
    } else {
        close(cli);
    }
    stun_free(response);
}

//------------------------------------------------------------------------------
static void
mocksrv_do_recv(size_t len, int chan, enum fuzz fuzz)
{
    int i, channel;

    for (i = 0; i < len; i++)
        buf[i] = rand();

    if (!(fuzz & F_CHANNEL))
        channel = chan;
    else
        channel = CHAN_42;

    if (!(fuzz & F_READERR_SHUT)) {
        mocktcpsrv_write(buf, channel, len, fuzz);
    } else {
        close(cli);
    }
}

//------------------------------------------------------------------------------
static void
mocksrv_do_shut(struct sockaddr *sin, socklen_t len, int chan, enum fuzz fuzz)
{
    struct stun_message *response;

    if (!(fuzz & F_ERROR))
        response = stun_new(TURN_CONN_STAT_INDICATION);
    else
        response = stun_new(TURN_ALLOCATION_ERROR);

    if (!(fuzz & F_NO_PEER_ADDRESS))
        stun_set_peer_address(response, sin, len);
    if (!(fuzz & F_NO_CHANNEL))
        response->channel = chan;
    if (!(fuzz & F_NO_CONNECT_STATUS))
        response->connect_status = TURN_CONNSTAT_CLOSED;

    if (!(fuzz & F_CHANNEL))
        channel = TURN_CHANNEL_CTRL;
    else
        channel = CHAN_42;

    if (!(fuzz & F_READERR_SHUT)) {
        len = stun_to_bytes(buf, sizeof(buf), response);
        if (fuzz & F_READERR_CORRUPTED)
            buf[4] = 0x00;
        mocktcpsrv_write(buf, channel, len, fuzz);
    } else {
        close(cli);
    }
    stun_free(response);
}

//------------------------------------------------------------------------------
static int
mocksrv_do_send_stun(char *buf, int len, struct sockaddr *addr, socklen_t alen)
{
    struct stun_message *request;
    int chan;

    request = mocktcpsrv_read();
    fail_if(request == NULL, "Bad request");
    fail_unless(request->message_type == TURN_SEND_INDICATION, "Bad request");
    fail_unless(request->data_len == len, "Bad length");
    fail_if(request->data == NULL, "Bad data");
    fail_unless(memcmp(buf, request->data, len) == 0, "Incorrect data");
    check_sockaddr(addr, alen, request->peer_address, request->peer_address_len);
    fail_if(request->channel == -1, "Bad channel");
    chan = request->channel;
    stun_free(request);
    return chan;
}

//------------------------------------------------------------------------------
static void
mocksrv_do_send_raw(char *rbuf, int len, int chan)
{
    struct stun_message *request;

    request = mocktcpsrv_read();
    fail_unless(request == NULL, "Bad frame");
    fail_unless(length == len, "Bad length");
    fail_unless(channel == chan, "Bad channel");
    fail_unless(memcmp(rbuf, buf, len) == 0, "Incorrect data");
}


//------------------------------------------------------------------------------
static void
tcpsock_teardown()
{
    turn_close(tsock);
    close(srv);
    close(cli);
}

//------------------------------------------------------------------------------
START_TEST(tcpsock_init)
{
    turn_socket_t turn;
    struct sockaddr saddr;

    turn = turn_socket(PF_INET, SOCK_STREAM, IPPROTO_UDP);
    fail_unless(turn == NULL, "Accepted bad parameters");
    turn = turn_socket(PF_INET, SOCK_DGRAM, IPPROTO_TCP);
    fail_unless(turn == NULL, "Accepted bad parameters");
    turn = turn_socket(PF_LOCAL, SOCK_STREAM, IPPROTO_UDP);
    fail_unless(turn == NULL, "Accepted bad parameters");

    turn = turn_socket(PF_INET, SOCK_STREAM, 0);
    fail_if(turn == NULL, "Not initialized correctly");
    memset(&saddr, 0, sizeof(saddr));
    saddr.sa_family = AF_LOCAL;
    fail_unless(turn_init(turn, &saddr, sizeof(saddr)) == -1,
                "Accepted bad server address");
    turn_close(turn);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_bind)
{
    int ret;
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_ERROR,
        F_READERR_SHUT,
        F_READERR_INTERRUPTED,
        F_WRITEERR,
        F_XACT_ID,
        F_NO_RELAY_ADDRESS,
        F_NO_XOR_MAPPED_ADDRESS,
        F_NO_BANDWIDTH,
        F_NO_LIFETIME,
        F_CHANNEL,
    };

    if (fuzzes[_i] & F_WRITEERR) {
        shutdown(turn_get_selectable_fd(tsock), SHUT_WR);
        ret = turn_bind(tsock, NULL, 0);
        fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
        tcpsock_opmutex(~0);
        return;
    }

    ret = turn_bind(tsock, NULL, 0);
    fail_unless(ret == -1 && errno == EAGAIN, "Not waiting for response");
    tcpsock_opmutex(~(T_BIND|T_LISTEN));

    mocksrv_do_bind(fuzzes[_i]);

    ret = turn_bind(tsock, NULL, 0);
    switch (fuzzes[_i]) {
        case F_SUCCESS:
            fail_unless(ret == 0, "Bind failed");
            tcpsock_opmutex(~(T_GETSOCKNAME|T_LISTEN));
            break;

        case F_XACT_ID:
        case F_CHANNEL:
            fail_unless(ret == -1 && errno == EAGAIN, "Expecting soft error");
            break;

        case F_READERR_INTERRUPTED:
            if (ret == -1 && errno == EAGAIN)
                ret = turn_bind(tsock, NULL, 0);
            // Fallthrough

        case F_ERROR:
        case F_READERR_SHUT:
        case F_NO_RELAY_ADDRESS:
        case F_NO_XOR_MAPPED_ADDRESS:
            fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
            tcpsock_opmutex(~0);
            break;

        case F_NO_BANDWIDTH:
        case F_NO_LIFETIME:
            fail_unless(ret == 0, "Expecting no error");
            break;

        default:
            fail_if(1, "Unhandled fuzz case");
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_getsockname)
{
    int ret;
    struct sockaddr addr;
    socklen_t alen = sizeof(addr);

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_bind(tsock, NULL, 0);

    ret = turn_getsockname(tsock, &addr, &alen);
    fail_unless(ret == 0, "Getsockname failed");
    check_sockaddr(&addr, alen, &raddr, sizeof(struct sockaddr_in));
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_listen)
{
    int ret;
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_SUCCESS,
        F_ERROR,
        F_READERR_SHUT,
        F_WRITEERR,
        F_XACT_ID,
        F_CHANNEL,
    };

    switch (_i) {
        case 1: // Listen without bind
            ret = turn_listen(tsock, 5);
            fail_unless(ret == -1 && errno == EAGAIN, "Not waiting for response");
            tcpsock_opmutex(~(T_BIND|T_LISTEN));
            mocksrv_do_bind(F_SUCCESS);
            break;

        default: // Bind first
            ret = turn_bind(tsock, NULL, 0);
            mocksrv_do_bind(F_SUCCESS);
            ret = turn_bind(tsock, NULL, 0);
            break;
    }

    if (fuzzes[_i] & F_WRITEERR) {
        shutdown(turn_get_selectable_fd(tsock), SHUT_WR);
        ret = turn_listen(tsock, 5);
        fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
        tcpsock_opmutex(~0);
        return;
    }

    ret = turn_listen(tsock, 5);
    fail_unless(ret == -1 && errno == EAGAIN, "Not waiting for response");
    tcpsock_opmutex(~(T_GETSOCKNAME|T_LISTEN|T_PERMIT));

    mocksrv_do_listen(fuzzes[_i]);
    ret = turn_listen(tsock, 5);
    switch (fuzzes[_i]) {
        case F_SUCCESS:
            fail_unless(ret == 0, "Listen failed");
            tcpsock_opmutex(~(T_GETSOCKNAME|T_PERMIT|T_RECVFROM|T_SENDTO));
            break;

        case F_XACT_ID:
        case F_CHANNEL:
            fail_unless(ret == -1 && errno == EAGAIN, "Expecting soft error");
            break;

        case F_ERROR:
        case F_READERR_SHUT:
            fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
            tcpsock_opmutex(~0);
            break;

        default:
            fail_if(1, "Unhandled fuzz case");
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_permit)
{
    int ret;
    struct sockaddr_in sin;
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_WRITEERR,
    };

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = rand();
    sin.sin_port = rand();

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_listen(tsock, 5);
    mocksrv_do_listen(fuzzes[_i]);

    if (fuzzes[_i] & F_WRITEERR) {
        shutdown(turn_get_selectable_fd(tsock), SHUT_WR);
        ret = turn_permit(tsock, (struct sockaddr *) &sin, sizeof(sin));
        fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
        tcpsock_opmutex(~0);
        return;
    }

    ret = turn_permit(tsock, (struct sockaddr *) &sin, sizeof(sin));
    mocksrv_do_permit();
    switch (fuzzes[_i]) {
        case F_SUCCESS:
            fail_unless(ret == 0, "Permit failed");
            tcpsock_opmutex(~(T_GETSOCKNAME|T_PERMIT|T_RECVFROM|T_SENDTO));
            break;

        default:
            fail_if(1, "Unhandled fuzz case");
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_recvfrom_accept)
{
    int ret;
    struct sockaddr_in sina, sinb;
    socklen_t blen = sizeof(sinb);
    char rbuf[1024];
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_ERROR,
        F_READERR_SHUT,
        F_READERR_CORRUPTED,
        F_CHANNEL,
        F_NO_PEER_ADDRESS,
        F_NO_CHANNEL,
        F_NO_CONNECT_STATUS,
    };

    sina.sin_family = AF_INET;
    sina.sin_addr.s_addr = rand();
    sina.sin_port = rand();

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_listen(tsock, 5);
    mocksrv_do_listen(F_SUCCESS);
    ret = turn_permit(tsock, (struct sockaddr *) &sina, sizeof(sina));
    mocksrv_do_permit();

    /* "Accept" the socket */
    mocksrv_do_accept((struct sockaddr *) &sina, sizeof(sina), CHAN_1, fuzzes[_i]);
    ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
    switch (fuzzes[_i]) {
        case F_SUCCESS:
            fail_unless(ret == -2 && errno == EAGAIN, "Expecting retry request");
            check_sockaddr(SA(&sina), sizeof(struct sockaddr_in), SA(&sinb), blen);
            break;

        case F_ERROR:
        case F_NO_PEER_ADDRESS:
        case F_NO_CHANNEL:
        case F_NO_CONNECT_STATUS:
        case F_CHANNEL:
        case F_READERR_CORRUPTED:
            fail_unless(ret == -1 && errno == EAGAIN, "Expecting retry request");
            break;

        case F_READERR_SHUT:
            fail_unless(ret == -1 && errno != EAGAIN, "Expecting retry request");
            break;

        default:
            fail_if(1, "Unhandled fuzz case");
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_recvfrom_small)
{
    int ret, len, i;
    struct sockaddr_in sina, sinb;
    socklen_t blen = sizeof(sinb);
    char rbuf[1024];
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_READERR_SHUT,
        F_CHANNEL,
    };

    sina.sin_family = AF_INET;
    sina.sin_addr.s_addr = rand();
    sina.sin_port = rand();

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_listen(tsock, 5);
    mocksrv_do_listen(F_SUCCESS);
    ret = turn_permit(tsock, (struct sockaddr *) &sina, sizeof(sina));
    mocksrv_do_permit();
    mocksrv_do_accept((struct sockaddr *) &sina, sizeof(sina), CHAN_1, F_SUCCESS);
    ret = turn_recvfrom(tsock, buf, sizeof(buf), NULL, 0);

    /* Read tiny data */
    for (i = 0; i < 10; i++) {
        len = rand() & 0xFF;
        mocksrv_do_recv(len, CHAN_1, fuzzes[_i]);
        ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
        switch (fuzzes[_i]) {
            case F_SUCCESS:
                fail_unless(ret == len, "Invalid size");
                fail_unless(memcmp(rbuf, buf, len) == 0, "Invalid data");
                check_sockaddr(SA(&sina), sizeof(struct sockaddr_in), SA(&sinb), blen);
                tcpsock_opmutex(~(T_GETSOCKNAME|T_PERMIT|T_RECVFROM|T_SENDTO|T_SHUTDOWN));
                break;

            case F_CHANNEL:
                fail_unless(ret == -1 && errno == EAGAIN, "Expecting retry request");
                return;

            case F_READERR_SHUT:
                fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
                tcpsock_opmutex(~0);
                return;

            default:
                fail_if(1, "Unhandled fuzz case");
        }
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_recvfrom_large)
{
    int ret, len, tot, i;
    struct sockaddr_in sina, sinb;
    socklen_t blen = sizeof(sinb);
    char rbuf[1024];
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_READERR_SHUT,
        F_CHANNEL,
    };

    sina.sin_family = AF_INET;
    sina.sin_addr.s_addr = rand();
    sina.sin_port = rand();

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_listen(tsock, 5);
    mocksrv_do_listen(F_SUCCESS);
    ret = turn_permit(tsock, (struct sockaddr *) &sina, sizeof(sina));
    mocksrv_do_permit();
    mocksrv_do_accept((struct sockaddr *) &sina, sizeof(sina), CHAN_1, F_SUCCESS);
    ret = turn_recvfrom(tsock, buf, sizeof(buf), (struct sockaddr *) &sinb, &blen);

    /* Read big data */
    for (i = 0; i < 10; i++) {
        len = sizeof(rbuf) + (rand() & 0xFF);
        mocksrv_do_recv(len, CHAN_1, fuzzes[_i]);
        switch (fuzzes[_i]) {
            case F_SUCCESS:
                tot = 0;
                while (tot < len) {
                    ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
                    if (ret == -1 && errno == EAGAIN)
                        continue;
                    fail_unless(ret > 0, "Invalid size");
                    fail_unless(memcmp(rbuf, buf + tot, ret) == 0, "Invalid data");
                    tot += ret;
                    if (tot < len)
                        tcpsock_opmutex(~(T_GETSOCKNAME|T_RECVFROM|T_SENDTO));
                }
                // Ensure no more data is pending
                ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
                fail_unless(ret == -1 && errno == EAGAIN, "Not waiting for data");
                break;

            case F_CHANNEL:
                ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
                fail_unless(ret == -1 && errno == EAGAIN, "Expecting retry request");
                return;

            case F_READERR_SHUT:
                ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
                fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
                tcpsock_opmutex(~0);
                return;

            default:
                fail_if(1, "Unhandled fuzz case");
        }
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_recvfrom_eof)
{
    int ret, len, tot, i;
    struct sockaddr_in sina, sinb;
    socklen_t blen = sizeof(sinb);
    char rbuf[1024];
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_ERROR,
        F_READERR_SHUT,
        F_READERR_CORRUPTED,
        F_CHANNEL,
        F_NO_PEER_ADDRESS,
        F_NO_CHANNEL,
        F_NO_CONNECT_STATUS,
    };

    sina.sin_family = AF_INET;
    sina.sin_addr.s_addr = rand();
    sina.sin_port = rand();

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_listen(tsock, 5);
    mocksrv_do_listen(F_SUCCESS);
    ret = turn_permit(tsock, (struct sockaddr *) &sina, sizeof(sina));
    mocksrv_do_permit();
    mocksrv_do_accept((struct sockaddr *) &sina, sizeof(sina), CHAN_1, F_SUCCESS);
    ret = turn_recvfrom(tsock, buf, sizeof(buf), (struct sockaddr *) &sinb, &blen);

    for (i = 0; i < 10; i++) {
        len = sizeof(rbuf) + (rand() & 0xFF);
        mocksrv_do_recv(len, CHAN_1, F_SUCCESS);
        mocksrv_do_shut((struct sockaddr *) &sina, sizeof(sina), 1, fuzzes[_i]);

        tot = 0;
        while (tot < len) {
            ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
            if (ret == -1 && errno == EAGAIN)
                continue;
            fail_unless(ret > 0, "Invalid size");
            tot += ret;
        }

        ret = turn_recvfrom(tsock, rbuf, sizeof(rbuf), (struct sockaddr *) &sinb, &blen);
        switch (fuzzes[_i]) {
            case F_SUCCESS:
                fail_unless(ret == 0, "Not end of file");
                tcpsock_opmutex(~(T_GETSOCKNAME|T_RECVFROM|T_SENDTO|T_SHUTDOWN|T_PERMIT));
                return;

            case F_ERROR:
            case F_CHANNEL:
            case F_NO_PEER_ADDRESS:
            case F_NO_CHANNEL:
            case F_NO_CONNECT_STATUS:
            case F_READERR_CORRUPTED:
                fail_unless(ret == -1 && errno == EAGAIN, "Expecting retry request");
                break;

            case F_READERR_SHUT:
                fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
                tcpsock_opmutex(~0);
                return;

            default:
                fail_if(1, "Unhandled fuzz case");
        }
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_sendto_small)
{
    int ret, len, i, j, chan;
    struct sockaddr_in sina, sinb;
    socklen_t blen = sizeof(sinb);
    char rbuf[1024];

    sina.sin_family = AF_INET;
    sina.sin_addr.s_addr = rand();
    sina.sin_port = rand();

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_listen(tsock, 5);
    mocksrv_do_listen(F_SUCCESS);
    ret = turn_permit(tsock, (struct sockaddr *) &sina, sizeof(sina));
    mocksrv_do_permit();

    sina.sin_port = rand();
    mocksrv_do_accept((struct sockaddr *) &sina, sizeof(sina), CHAN_1, F_SUCCESS);
    ret = turn_recvfrom(tsock, buf, sizeof(buf), (struct sockaddr *) &sinb, &blen);

    /* Read tiny data */
    for (i = 0; i < 10; i++) {
        len = rand() & 0xFF;
        for (j = 0; j < len; j++)
            rbuf[j] = rand();
        switch (_i) {
            case 0: // F_SUCCESS
                ret = turn_sendto(tsock, rbuf, len, (struct sockaddr *) &sinb, blen);
                if (i == 0)
                    chan = mocksrv_do_send_stun(rbuf, len, (struct sockaddr *) &sinb, blen);
                else
                    mocksrv_do_send_raw(rbuf, len, chan);
                break;

            case 1: // F_WRITEERR
                shutdown(turn_get_selectable_fd(tsock), SHUT_WR);
                ret = turn_sendto(tsock, rbuf, len, (struct sockaddr *) &sinb, blen);
                fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
                tcpsock_opmutex(~0);
                return;

            case 2: // Send to non existend
                sinb.sin_port ^= 0xFFFF;
                ret = turn_sendto(tsock, rbuf, len, (struct sockaddr *) &sinb, blen);
                fail_unless(ret == -1 && errno != EAGAIN, "Expecting error");
                return;

            default:
                fail_if(1, "Unhandled fuzz case");
        }
    }
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_shutdown)
{
    int ret;
    struct sockaddr_in sina, sinb;
    socklen_t blen = sizeof(sinb);

    sina.sin_family = AF_INET;
    sina.sin_addr.s_addr = rand();
    sina.sin_port = rand();

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_listen(tsock, 5);
    mocksrv_do_listen(F_SUCCESS);
    ret = turn_permit(tsock, (struct sockaddr *) &sina, sizeof(sina));
    mocksrv_do_permit();

    sina.sin_port = rand();
    mocksrv_do_accept((struct sockaddr *) &sina, sizeof(sina), CHAN_1, F_SUCCESS);
    ret = turn_recvfrom(tsock, buf, sizeof(buf), (struct sockaddr *) &sinb, &blen);

    switch (_i) {
        case 0: // F_SUCCESS
            ret = turn_shutdown(tsock, (struct sockaddr *) &sinb, blen);
            fail_unless(ret == 0, "Failed to shutdown");
            break;

        case 1: // F_WRITEERR
            shutdown(turn_get_selectable_fd(tsock), SHUT_WR);
            ret = turn_shutdown(tsock, (struct sockaddr *) &sinb, blen);
            fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
            tcpsock_opmutex(~0);
            return;

        case 2: // Shutdown non existent
            sinb.sin_port ^= 0xFFFF;
            ret = turn_shutdown(tsock, (struct sockaddr *) &sinb, blen);
            fail_unless(ret == -1 && errno != EAGAIN, "Expecting error");
            return;

        default:
            fail_if(1, "Unhandled fuzz case");
    }
}
END_TEST



//------------------------------------------------------------------------------
Suite *
check_turn()
{
    Suite *turn;
    TCase *test;

    turn = suite_create("libstern turn");

    test = tcase_create("tcp_socket");
    tcase_add_checked_fixture(test, tcpsock_setup, tcpsock_teardown);
    tcase_add_test(test, tcpsock_init);
    tcase_add_loop_test(test, tcpsock_bind, 0, 11);
    tcase_add_test(test, tcpsock_getsockname);
    tcase_add_loop_test(test, tcpsock_listen, 0, 7);
    tcase_add_loop_test(test, tcpsock_permit, 0, 2);
    tcase_add_loop_test(test, tcpsock_recvfrom_accept, 0, 8);
    tcase_add_loop_test(test, tcpsock_recvfrom_small, 0, 3);
    tcase_add_loop_test(test, tcpsock_recvfrom_large, 0, 3);
    tcase_add_loop_test(test, tcpsock_recvfrom_eof, 0, 8);
    tcase_add_loop_test(test, tcpsock_sendto_small, 0, 3);
    tcase_add_loop_test(test, tcpsock_shutdown, 0, 3);
    suite_add_tcase(turn, test);

    return turn;
}
