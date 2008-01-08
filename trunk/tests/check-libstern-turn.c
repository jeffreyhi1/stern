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
struct sockaddr caddr;
socklen_t caddrlen = sizeof(caddr);
int channel, length;
char buf[1024];

enum fuzz {
    F_SUCCESS               = 0,
    F_ERROR                 = 1 << 0,
    F_XACT_ID               = 1 << 1,
    F_NO_PEER_ADDRESS       = 1 << 2,
    F_NO_XOR_MAPPED_ADDRESS = 1 << 3,
    F_NO_BANDWIDTH          = 1 << 4,
    F_NO_LIFETIME           = 1 << 5,
    F_NO_RELAY_ADDRESS      = 1 << 6,
};

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
}

//------------------------------------------------------------------------------
static struct stun_message *
mocktcpsrv_read()
{
    int ret;
    uint16_t val;
    struct turn_message *turn;

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
mocktcpsrv_write_stun(struct stun_message *stun)
{
    int len, ret;
    uint16_t val;

    len = stun_to_bytes(buf, sizeof(buf), stun);

    val = htons(TURN_CHANNEL_CTRL);
    ret = send(cli, &val, sizeof(val), MSG_MORE);
    fail_if(ret != 2, "Invalid write");

    val = htons(len);
    ret = send(cli, &val, sizeof(val), MSG_MORE);
    fail_if(ret != 2, "Invalid write");

    ret = send(cli, buf, len, 0);
    fail_if(ret != len, "Invalid write");
}

//------------------------------------------------------------------------------
static void
mocksrv_do_allocate(enum fuzz fuzz)
{
    struct sockaddr_in sin;
    struct stun_message *request, *response;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = rand();
    sin.sin_port = rand();

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
        stun_set_relay_address(response, &sin, sizeof(sin));
    if (!(fuzz & F_NO_XOR_MAPPED_ADDRESS))
        stun_set_xor_mapped_address(response, &caddr, caddrlen);
    if (!(fuzz & F_NO_BANDWIDTH))
        response->bandwidth = 10;
    if (!(fuzz & F_NO_LIFETIME))
        response->lifetime = 600;

    mocktcpsrv_write_stun(response);
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
        F_XACT_ID,
        F_NO_RELAY_ADDRESS,
        F_NO_XOR_MAPPED_ADDRESS,
        F_NO_BANDWIDTH,
        F_NO_LIFETIME,
    };

    ret = turn_bind(tsock, NULL, 0);
    fail_unless(ret == -1 && errno == EAGAIN, "Not waiting for response");

    mocksrv_do_allocate(fuzzes[_i]);

    switch (fuzzes[_i]) {
        case F_SUCCESS:
            ret = turn_bind(tsock, NULL, 0);
            fail_unless(ret == 0, "Bind failed");
            break;

        case F_XACT_ID:
            ret = turn_bind(tsock, NULL, 0);
            fail_unless(ret == -1 && errno == EAGAIN, "Expecting soft error");
            break;

        case F_ERROR:
        case F_NO_RELAY_ADDRESS:
        case F_NO_XOR_MAPPED_ADDRESS:
            ret = turn_bind(tsock, NULL, 0);
            fail_unless(ret == -1 && errno != EAGAIN, "Expecting hard error");
            break;

        case F_NO_BANDWIDTH:
        case F_NO_LIFETIME:
            ret = turn_bind(tsock, NULL, 0);
            fail_unless(ret == 0, "Expecting no error");
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
    tcase_add_loop_test(test, tcpsock_bind, 0, 7);
    suite_add_tcase(turn, test);

    return turn;
}
