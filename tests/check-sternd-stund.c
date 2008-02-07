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

int srv, cli;

//------------------------------------------------------------------------------
void
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
static struct stun_message *
cli_recv(int cli)
{
    char buf[8192];
    struct stun_message *stun;
    unsigned int len, olen;

    len = recv(cli, buf, sizeof(buf), 0);
    if (len <= 0)
        return NULL;
    olen = len;
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
static void
stunudp_setup()
{
    int ret;
    struct sockaddr_in sin;
    socklen_t len;

    sternd_init();
    srv = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    ret = sternd_set_stun_socket(IPPROTO_UDP, srv, PORT_STUN);
    fail_if(ret != 0, "Initialization failed");

    len = sizeof(sin);
    cli = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    fail_unless(getsockname(srv, (struct sockaddr *)&sin, &len) == 0, "No address");
    sin.sin_addr.s_addr = inet_addr("127.0.0.1");
    fail_unless(connect(cli, (struct sockaddr *)&sin, len) == 0, "Cannot connect");
}

//------------------------------------------------------------------------------
static void
stunudp_teardown()
{
    sternd_quit();
}

//------------------------------------------------------------------------------
static int
stuntcp_client()
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
stuntcp_setup()
{
    int ret;

    sternd_init();
    sternd_set_stun_timeout(0, 100000);

    srv = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    ret = sternd_set_stun_socket(IPPROTO_TCP, srv, PORT_STUN);
    fail_if(ret != 0, "Initialization failed");

    cli = stuntcp_client();

    srv_loop();
    fail_if(LIST_FIRST(&sternd.stuntcp.clients) == NULL, "No client accepted");
}

//------------------------------------------------------------------------------
static void
stuntcp_teardown()
{
    sternd_quit();
}

//------------------------------------------------------------------------------
START_TEST(stunudp_init)
{
    // Do nothing
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(stunudp_binding_request)
{
    struct stun_message *stun = stun_new(STUN_BINDING_REQUEST);
    struct sockaddr addr;
    socklen_t len = sizeof(addr);

    cli_send(stun, cli);
    srv_loop();
    stun = cli_recv(cli);
    fail_if(stun == NULL, "No message");
    fail_if(stun->mapped_address == NULL, "No mapping response");
    getsockname(cli, &addr, &len);
    check_address(stun->mapped_address, &addr);
    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(stuntcp_init)
{
    // Do nothing
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(stuntcp_binding_request)
{
    struct stun_message *stun = stun_new(STUN_BINDING_REQUEST);
    struct sockaddr addr;
    socklen_t len = sizeof(addr);

    cli_send(stun, cli);
    srv_loop();
    stun = cli_recv(cli);
    fail_if(stun == NULL, "No message");
    fail_if(stun->mapped_address == NULL, "No mapping response");
    getsockname(cli, &addr, &len);
    check_address(stun->mapped_address, &addr);
    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(stuntcp_close)
{
    struct stun_message *stun = stun_new(STUN_BINDING_REQUEST);

    shutdown(cli, SHUT_WR);
    srv_loop();
    fail_unless(LIST_FIRST(&sternd.stuntcp.clients) == NULL, "Client not reaped");
    fail_unless(cli_recv(cli) == NULL, "No response expected");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(stuntcp_timeo)
{
    struct stun_message *stun = stun_new(STUN_BINDING_REQUEST);

    usleep(200000);
    srv_loop();
    fail_unless(LIST_FIRST(&sternd.stuntcp.clients) == NULL, "Client not reaped");
    fail_unless(cli_recv(cli) == NULL, "No response expected");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(stuntcp_multiple)
{
    struct stun_message *stun;
    int i;
    int clis[6];
    struct sockaddr addr;
    socklen_t len = sizeof(addr);

    clis[0] = cli;
    for (i = 1; i < 6; i++)
        clis[i] = stuntcp_client();
    srv_loop();

    for (i = 0; i < 4; i++) {
        stun = stun_new(STUN_BINDING_REQUEST);
        cli_send(stun, clis[i]);
    }
    close(clis[3]);
    shutdown(clis[4], SHUT_WR);
    usleep(200000);

    srv_loop();

    for (i = 0; i < 3; i++) {
        stun = cli_recv(clis[i]);
        fail_if(stun == NULL, "No message");
        fail_if(stun->mapped_address == NULL, "No mapping response");
        getsockname(clis[i], &addr, &len);
        check_address(stun->mapped_address, &addr);
        stun_free(stun);
    }
    fail_unless(cli_recv(clis[4]) == NULL, "EOF expected");
    fail_unless(cli_recv(clis[5]) == NULL, "EOF expected");

    for (i = 1; i < 6; i++)
        close(clis[i]);
}
END_TEST

//------------------------------------------------------------------------------
Suite *
check_stund()
{
    Suite *stund;
    TCase *test;

    stund = suite_create("sternd stun server");

    test = tcase_create("stunudp");
    tcase_add_checked_fixture(test, stunudp_setup, stunudp_teardown);
    tcase_add_test(test, stunudp_init);
    tcase_add_test(test, stunudp_binding_request);
    suite_add_tcase(stund, test);

    test = tcase_create("stuntcp");
    tcase_add_checked_fixture(test, stuntcp_setup, stuntcp_teardown);
    tcase_add_test(test, stuntcp_init);
    tcase_add_test(test, stuntcp_binding_request);
    tcase_add_test(test, stuntcp_close);
    tcase_add_test(test, stuntcp_timeo);
    tcase_add_test(test, stuntcp_multiple);
    suite_add_tcase(stund, test);

    return stund;
}
