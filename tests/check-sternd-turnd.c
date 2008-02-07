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
#include "check-sternd.h"

#include <netinet/tcp.h>

#define CHAN_1    0x4001
#define CHAN_2    0x4002
#define CHAN_42   0x4042

int srv, cli;

//------------------------------------------------------------------------------
static void
check_address(struct sockaddr *addr1, struct sockaddr *addr2)
{
    struct sockaddr_in *ain = (struct sockaddr_in *) addr1;
    struct sockaddr_in *bin = (struct sockaddr_in *) addr2;

    fail_if(addr1 == NULL, "Address missaddr");
    fail_unless(addr1->sa_family == addr2->sa_family, "Bad address family");
    fail_unless(ain->sin_addr.s_addr == bin->sin_addr.s_addr, "Bad address");
    fail_unless(ain->sin_port == bin->sin_port, "Bad port");
}

//------------------------------------------------------------------------------
static void
cli_send(struct stun_message *stun, int cli)
{
    char buf[8192];
    int len;

    len = stun_to_bytes(buf, sizeof(buf), stun);
    fail_if(len == -1, "Bad message");
    fail_if(send(cli, buf, len, 0) != len, "Cannot send");
    stun_free(stun);
}

//------------------------------------------------------------------------------
static void
cli_sendraw(int chan, char *buf, size_t len, int cli)
{
    uint16_t tchan;
    uint16_t tlen;

    tchan = htons(chan);
    tlen = htons(len);
    fail_if(send(cli, &tchan, sizeof(tchan), 0) != sizeof(tchan), "Cannot send");
    fail_if(send(cli, &tlen, sizeof(tlen), 0) != sizeof(tlen), "Cannot send");
    fail_if(send(cli, buf, len, 0) != len, "Cannot send");
}

//------------------------------------------------------------------------------
static struct stun_message *
cli_recv(int cli)
{
    char buf[8192];
    struct stun_message *stun;
    size_t len;
    int olen;

    olen = recv(cli, buf, sizeof(buf), 0);
    if (olen <= 0)
        return NULL;
    len = olen;
    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Bad message");
    fail_if(olen != len, "Extra bytes");
    return stun;
}

//------------------------------------------------------------------------------
static void
srv_loop()
{
    sternd_loop();
}

//------------------------------------------------------------------------------
static int
turntcp_client()
{
    struct sockaddr_in sin;
    socklen_t len;
    int cli;

    len = sizeof(sin);
    cli = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    fail_unless(getsockname(srv, (struct sockaddr *)&sin, &len) == 0, "No address");
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    fail_unless(connect(cli, (struct sockaddr *)&sin, len) == 0, "Cannot connect");

    return cli;
}

//------------------------------------------------------------------------------
static void
turntcp_setup()
{
    int ret;
    static int one = 1;

    sternd_init();

    srv = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    ret = sternd_set_turn_socket(IPPROTO_TCP, srv, PORT_TURN);
    fail_if(ret != 0, "Initialization failed");

    cli = turntcp_client();
    setsockopt(cli, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    srv_loop();
    fail_if(LIST_FIRST(&sternd.turntcp.clients) == NULL, "No client accepted");
}

//------------------------------------------------------------------------------
static void
turntcp_teardown()
{
    sternd_quit();
    close(srv);
    close(cli);
}

//------------------------------------------------------------------------------
START_TEST(turntcp_init)
{
    // Do nothing
}
END_TEST

static void
do_allocate(int cli, struct sockaddr *relay, socklen_t *rlen)
{
    struct stun_message *stun;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);

    stun = stun_new(TURN_ALLOCATION_REQUEST);
    stun->requested_transport = TURN_TRANSPORT_TCP;

    cli_send(stun, cli);
    srv_loop();
    stun = cli_recv(cli);

    fail_if(stun == NULL, "No message");
    fail_if(stun->message_type != TURN_ALLOCATION_SUCCESS, "Allocation failed");
    fail_if(stun->lifetime == -1, "No lifetime");
    fail_if(stun->bandwidth == -1, "No bandwidth");
    fail_if(stun->relay_address == NULL, "No relay response");
    fail_if(stun->xor_mapped_address == NULL, "No mapping response");
    getsockname(cli, &addr, &len);
    check_address(stun->xor_mapped_address, &addr);

    if (relay) {
        *rlen = stun->relay_address_len;
        memcpy(relay, stun->relay_address, *rlen);
    }

    stun_free(stun);

    fail_if(LIST_FIRST(&sternd.turntcp.clients) == NULL, "No client");
}

static void
do_listen(int cli)
{
    struct stun_message *stun;

    stun = stun_new(TURN_LISTEN_REQUEST);
    cli_send(stun, cli);
    srv_loop();
    stun = cli_recv(cli);
    fail_if(stun == NULL, "No message");
    fail_if(stun->message_type != TURN_LISTEN_SUCCESS, "Listen failed");
    stun_free(stun);
}

static void
do_permit(int cli)
{
    struct stun_message *stun;
    struct sockaddr_in sin;
    struct turn_client *client;

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    sin.sin_port = 0;

    stun = stun_new(TURN_SEND_INDICATION);
    stun_set_peer_address(stun, (struct sockaddr *)&sin, sizeof(sin));

    cli_send(stun, cli);
    srv_loop();

    client = LIST_FIRST(&sternd.turntcp.clients);
    fail_if(LIST_FIRST(&client->permissions) == NULL, "No permissions");
}

static void
do_accept(int cli, int fd, struct sockaddr *relay, struct sockaddr *peer, int *ch, socklen_t rlen)
{
    struct stun_message *stun;
    struct sockaddr addr;
    socklen_t len;


    fail_if(connect(fd, relay, rlen) != 0, "Connect failed");
    srv_loop();
    stun = cli_recv(cli);
    fail_if(stun == NULL, "No message");
    fail_if(stun->message_type != TURN_CHAN_CONF_INDICATION, "Bad type");
    fail_if(stun->connect_status != TURN_CONNSTAT_ESTABLISHED, "Bad status");
    fail_if(stun->peer_address == NULL, "No peer");
    fail_if(stun->channel == -1, "No channel");

    len = sizeof(addr);
    getsockname(fd, &addr, &len);
    check_address(stun->peer_address, &addr);

    memcpy(peer, stun->peer_address, stun->peer_address_len);
    *ch = stun->channel;
    stun_free(stun);
}

static void
do_stun_send(int cli, struct sockaddr *peer, socklen_t rlen, int chan, int fd)
{
    struct stun_message *stun;
    int i, len;
    char buffer[128], buf2[128];

    stun = stun_new(TURN_SEND_INDICATION);
    stun_set_peer_address(stun, peer, rlen);
    stun->channel = chan;
    for(i = 0; i < sizeof(buffer); i++)
        buffer[i] = random();
    stun_set_data(stun, buffer, sizeof(buffer));

    cli_send(stun, cli);
    srv_loop();

    stun = cli_recv(cli);
    fail_if(stun == NULL, "No message");
    fail_if(stun->message_type != TURN_CHAN_CONF_INDICATION, "Bad type");
    fail_if(stun->connect_status != TURN_CONNSTAT_ESTABLISHED, "Bad status");
    stun_free(stun);

    len = 0;
    while (len < sizeof(buffer)) {
        i = recv(fd, buf2 + len, sizeof(buf2) - len, 0);
        fail_if(i <= 0, "Incomplete read");
        len += i;
    }

    fail_unless(memcmp(buffer, buf2, len) == 0, "Incorrect data");
}

static void
do_raw_send(int cli, int chan, int fd)
{
    int i, len;
    char buffer[128], buf2[128];

    for(i = 0; i < sizeof(buffer); i++)
        buffer[i] = random();
    cli_sendraw(chan, buffer, sizeof(buffer), cli);
    srv_loop();

    len = 0;
    while (len < sizeof(buffer)) {
        i = recv(fd, buf2 + len, sizeof(buf2) - len, 0);
        fail_if(i <= 0, "Incomplete read");
        len += i;
    }

    fail_unless(memcmp(buffer, buf2, len) == 0, "Incorrect data");
}

static void
do_stun_send_close(int cli, struct sockaddr *peer, socklen_t rlen, int chan, int fd)
{
    struct stun_message *stun;
    int i;
    char buf2[128];

    stun = stun_new(TURN_CHAN_CONF_INDICATION);
    stun_set_peer_address(stun, peer, rlen);
    stun->channel = chan;
    stun->connect_status = TURN_CONNSTAT_CLOSED;

    cli_send(stun, cli);
    srv_loop();

    i = recv(fd, buf2, sizeof(buf2), 0);
    fail_if(i != 0, "Expending close");
}

static void
do_raw_recv(int cli, int chan, int fd)
{
    int i, len;
    char buffer[128], buf2[8192];
    uint16_t tchan;
    uint16_t tlen;

    for(i = 0; i < sizeof(buffer); i++)
        buffer[i] = random();
    fail_if(send(fd, buffer, sizeof(buffer), 0) != sizeof(buffer), "Cannot send");
    tchan = htons(chan);
    tlen = htons(sizeof(buffer));

    srv_loop();
    len = recv(cli, buf2, sizeof(buf2), 0);
    fail_if(len != sizeof(buffer) + TURN_TAGLEN, "Bad data length");
    fail_unless(memcmp(&tchan, buf2, 2) == 0, "Incorrect channel");
    fail_unless(memcmp(&tlen, buf2 + 2, 2) == 0, "Incorrect length");
    fail_unless(memcmp(buffer, buf2 + TURN_TAGLEN, len - TURN_TAGLEN) == 0, "Incorrect data");
}

static void
do_stun_recv_close(int cli, struct sockaddr *peer, socklen_t rlen, int chan, int fd)
{
    struct stun_message *stun;

    close(fd);

    srv_loop();
    stun = cli_recv(cli);
    fail_if(stun == NULL, "No message");
    fail_if(stun->message_type != TURN_CHAN_CONF_INDICATION, "Bad type");
    fail_if(stun->connect_status != TURN_CONNSTAT_CLOSED, "Bad status");
    fail_unless(stun->channel == chan, "Wrong channel");
    fail_if(stun->peer_address == NULL, "No peer");
    check_address(stun->peer_address, peer);
    stun_free(stun);
}


//------------------------------------------------------------------------------
START_TEST(turntcp_alloc_request)
{
    do_allocate(cli, NULL, NULL);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(turntcp_listen_request)
{
    do_allocate(cli, NULL, NULL);
    do_listen(cli);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(turntcp_permit)
{
    do_allocate(cli, NULL, NULL);
    do_listen(cli);
    do_permit(cli);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(turntcp_accept)
{
    struct sockaddr relay, peer;
    socklen_t len;
    int fd, cfd;

    do_allocate(cli, &relay, &len);
    do_listen(cli);
    do_permit(cli);

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    do_accept(cli, fd, &relay, &peer, &cfd, len);
    close(fd);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(turntcp_send)
{
    struct sockaddr relay, peer;
    socklen_t len;
    int fd, cfd;

    do_allocate(cli, &relay, &len);
    do_listen(cli);
    do_permit(cli);

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    do_accept(cli, fd, &relay, &peer, &cfd, len);

    do_stun_send(cli, &peer, len, CHAN_1, fd);
    do_raw_send(cli, CHAN_1, fd);
    do_stun_send_close(cli, &peer, len, CHAN_1, fd);
    close(fd);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(turntcp_recv)
{
    struct sockaddr relay, peer;
    socklen_t len;
    int fd, cfd;

    do_allocate(cli, &relay, &len);
    do_listen(cli);
    do_permit(cli);

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    do_accept(cli, fd, &relay, &peer, &cfd, len);

    do_raw_recv(cli, cfd, fd);
    do_stun_recv_close(cli, &peer, len, cfd, fd);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(turntcp_multi_seq)
{
    struct sockaddr relay, peer;
    socklen_t len;
    int fd, cfd;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    do_allocate(cli, &relay, &len);
    do_listen(cli);
    do_permit(cli);
    do_accept(cli, fd, &relay, &peer, &cfd, len);
    do_raw_recv(cli, cfd, fd);
    do_stun_recv_close(cli, &peer, len, cfd, fd);

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    do_accept(cli, fd, &relay, &peer, &cfd, len);
    do_raw_recv(cli, cfd, fd);
    do_stun_recv_close(cli, &peer, len, cfd, fd);
}
END_TEST

//------------------------------------------------------------------------------
Suite *
check_turnd()
{
    Suite *turnd;
    TCase *test;

    turnd = suite_create("sternd turn server");

    test = tcase_create("turntcp");
    tcase_add_checked_fixture(test, turntcp_setup, turntcp_teardown);
    tcase_add_test(test, turntcp_init);
    tcase_add_test(test, turntcp_alloc_request);
    tcase_add_test(test, turntcp_listen_request);
    tcase_add_test(test, turntcp_permit);
    tcase_add_test(test, turntcp_accept);
    tcase_add_test(test, turntcp_send);
    tcase_add_test(test, turntcp_recv);
    tcase_add_test(test, turntcp_multi_seq);
    suite_add_tcase(turnd, test);

    return turnd;
}
