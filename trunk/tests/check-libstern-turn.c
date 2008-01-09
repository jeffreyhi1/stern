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

turn_socket_t tsock;
int srv, cli;
struct sockaddr caddr, raddr;
socklen_t caddrlen = sizeof(caddr);
unsigned int channel, length;
char buf[1024];

enum fuzz {
    F_SUCCESS               = 0,
    F_ERROR                 = 1 << 0,
    F_READERR               = 1 << 1,
    F_WRITEERR              = 1 << 2,
    F_XACT_ID               = 1 << 3,
    F_CHANNEL               = 1 << 4,
    F_NO_PEER_ADDRESS       = 1 << 5,
    F_NO_XOR_MAPPED_ADDRESS = 1 << 6,
    F_NO_BANDWIDTH          = 1 << 7,
    F_NO_LIFETIME           = 1 << 8,
    F_NO_RELAY_ADDRESS      = 1 << 9,
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

    if (op & T_GETSOCKNAME) {
        ret = turn_getsockname(tsock, NULL, 0);
        fail_unless(ret == -1 && errno == EINVAL, "Getsockname should not be allowed");
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

}

//------------------------------------------------------------------------------
static void
tcpsock_setup()
{
    struct sockaddr addr;
    socklen_t addrlen = sizeof(addr);
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

    ret = turn_set_nonblocking(tsock);
    fail_if(ret == -1, "Failed nonblocking IO");

    fcntl(cli, F_SETFL, O_NONBLOCK);

    tcpsock_opmutex(~(T_BIND|T_LISTEN));
}

//------------------------------------------------------------------------------
static struct stun_message *
mocktcpsrv_read()
{
    int ret;
    uint16_t val;
    struct stun_message *turn;

    ret = read(cli, &val, sizeof(val));
    fail_unless(ret == 2, "Invalid read");
    channel = ntohs(val);

    ret = read(cli, &val, sizeof(val));
    fail_unless(ret == 2, "Invalid read");
    length = ntohs(val);

    ret = read(cli, buf, length);
    fail_unless(ret == length, "Invalid read");

    if (channel == TURN_CHANNEL_CTRL) {
        turn = stun_from_bytes(buf, &length);
        fail_if(turn == NULL, "Invalid message");
        return turn;
    }
    return NULL;
}

//------------------------------------------------------------------------------
static void
mocktcpsrv_write_stun(char *buf, int channel, int len)
{
    uint16_t val1, val2;

    val1 = htons(channel);
    val2 = htons(len);
    fail_if(send(cli, &val1, sizeof(val1), MSG_MORE) != 2, "Invalid write");
    fail_if(send(cli, &val2, sizeof(val2), MSG_MORE) != 2, "Invalid write");
    fail_if(send(cli, buf, len, 0) != len, "Invalid write");
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

    if (fuzz & F_ERROR)
        response = stun_init_response(TURN_ALLOCATION_ERROR, request);
    else
        response = stun_init_response(TURN_ALLOCATION_SUCCESS, request);

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

    if (fuzz & F_CHANNEL)
        channel = rand();
    else
        channel = TURN_CHANNEL_CTRL;

    if (!(fuzz & F_READERR)) {
        len = stun_to_bytes(buf, sizeof(buf), response);
        mocktcpsrv_write_stun(buf, channel, len);
    } else {
        close(cli);
    }
    stun_free(request);
    stun_free(response);
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

    if (fuzz & F_ERROR)
        response = stun_init_response(TURN_LISTEN_ERROR, request);
    else
        response = stun_init_response(TURN_LISTEN_SUCCESS, request);

    if (fuzz & F_XACT_ID)
        response->xact_id[5] ^= 0xff;
    if (!(fuzz & F_NO_LIFETIME))
        response->lifetime = 600;

    if (fuzz & F_CHANNEL)
        channel = rand();
    else
        channel = TURN_CHANNEL_CTRL;

    if (!(fuzz & F_READERR)) {
        len = stun_to_bytes(buf, sizeof(buf), response);
        mocktcpsrv_write_stun(buf, channel, len);
    } else {
        close(cli);
    }
    stun_free(request);
    stun_free(response);
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
        F_READERR,
        F_WRITEERR,
        F_XACT_ID,
        F_NO_RELAY_ADDRESS,
        F_NO_XOR_MAPPED_ADDRESS,
        F_NO_BANDWIDTH,
        F_NO_LIFETIME,
        F_CHANNEL,
    };

    if (fuzzes[_i] & F_WRITEERR) {
        close(cli);
        ret = turn_bind(tsock, NULL, 0);
        fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
        tcpsock_opmutex(~0);
        return;
    }

    ret = turn_bind(tsock, NULL, 0);
    fail_unless(ret == -1 && errno == EAGAIN, "Not waiting for response");
    tcpsock_opmutex(~T_BIND);

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

        case F_ERROR:
        case F_READERR:
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
    struct sockaddr_in *sina = (struct sockaddr_in *) &addr;
    struct sockaddr_in *sinb = (struct sockaddr_in *) &raddr;
    socklen_t alen = sizeof(addr);

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_bind(tsock, NULL, 0);

    ret = turn_getsockname(tsock, &addr, &alen);
    fail_unless(ret == 0, "Getsockname failed");
    fail_unless(addr.sa_family == raddr.sa_family, "Bad family");
    fail_unless(alen == sizeof(struct sockaddr_in), "Bad size");
    fail_unless(sina->sin_addr.s_addr == sinb->sin_addr.s_addr, "Bad address");
    fail_unless(sina->sin_port == sinb->sin_port, "Bad port");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(tcpsock_listen)
{
    int ret;
    enum fuzz fuzzes[] = {
        F_SUCCESS,
        F_ERROR,
        F_READERR,
        F_WRITEERR,
        F_XACT_ID,
        F_CHANNEL,
    };

    ret = turn_bind(tsock, NULL, 0);
    mocksrv_do_bind(F_SUCCESS);
    ret = turn_bind(tsock, NULL, 0);

    if (fuzzes[_i] & F_WRITEERR) {
        close(cli);
        ret = turn_listen(tsock, 5);
        fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
        tcpsock_opmutex(~0);
        return;
    }

    ret = turn_listen(tsock, 5);
    fail_unless(ret == -1 && errno == EAGAIN, "Not waiting for response");
    tcpsock_opmutex(~(T_GETSOCKNAME|T_LISTEN));

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
        case F_READERR:
            fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
            tcpsock_opmutex(~0);
            break;

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
    tcase_add_loop_test(test, tcpsock_bind, 0, 10);
    tcase_add_test(test, tcpsock_getsockname);
    tcase_add_loop_test(test, tcpsock_listen, 0, 6);
    suite_add_tcase(turn, test);

    return turn;
}
