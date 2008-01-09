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

struct sockaddr saddr;

//------------------------------------------------------------------------------
void
check_address(struct sockaddr *addr)
{
    struct sockaddr_in *ain = (struct sockaddr_in *) addr;
    struct sockaddr_in *sin = (struct sockaddr_in *) &saddr;

    fail_if(addr == NULL, "Address missaddrg");
    fail_unless(addr->sa_family == saddr.sa_family, "Bad address family");
    fail_unless(ain->sin_addr.s_addr == sin->sin_addr.s_addr, "Bad address");
    fail_unless(ain->sin_port == sin->sin_port, "Bad port");
}

//------------------------------------------------------------------------------
void
init_sockaddr(struct sockaddr *addr, socklen_t len)
{
    struct sockaddr_in *sin = (struct sockaddr_in *) addr;

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = rand();
    sin->sin_port = rand();
}

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
START_TEST(binding_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x00,     // type = 0x01, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
    };
    size_t len = sizeof(buf);
    struct stun_message *response, *request;

    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);

    fail_unless(response->message_type == STUN_BINDING_RESPONSE, "Bad response");
    fail_unless(stun_is_ok_response(response, request), "Response not OK");
    fail_if(stun_is_err_response(response, request), "Response considered error");
    check_address(response->mapped_address);
    check_address(response->xor_mapped_address);

    stun_free(NULL);
    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_badint)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x18,     // type = 0x01, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x00, 0x08, 0x00, 0x14,     // message integrity
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    size_t len = sizeof(buf);
    struct stun_message *response, *request;

    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);

    fail_unless(response->message_type == STUN_BINDING_ERROR, "Bad response");
    fail_unless(stun_is_err_response(response, request), "Response not error as expected");
    fail_if(stun_is_ok_response(response, request), "Response considered OK");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_notreq)
{
    char buf[] = {
        0x01, 0x01, 0x00, 0x00,     // type = 0x11, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
    };
    size_t len = sizeof(buf);
    struct stun_message *response, *request;

    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);

    fail_unless(response == NULL, "Response not expected for non-request");
    fail_if(stun_is_ok_response(response, request), "Response considered OK");
    fail_if(stun_is_err_response(response, request), "Response considered error");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_notxact)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x00,     // type = 0x01, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
    };
    size_t len = sizeof(buf);
    struct stun_message *response, *request;

    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);
    response->xact_id[0] = 0;

    fail_if(stun_is_ok_response(response, request), "Response considered OK");
    fail_if(stun_is_err_response(response, request), "Response considered error");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_notcompr)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x04,     // type = 0x11, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x00, 0xff, 0x00, 0x00,     // unknown
    };
    size_t len = sizeof(buf);
    struct stun_message *response, *request;

    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);

    fail_unless(stun_is_err_response(response, request), "Response not error as expected");
    fail_unless(response->error_code == 420, "Bad error code");
    fail_if(response->unknown_attributes == NULL, "Unknown attributes missaddrg");
    fail_unless(response->unknown_attributes[0] == 0xff, "Bad unknown attribute");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_ok_unknown)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x04,     // type = 0x11, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x80, 0xff, 0x00, 0x00,     // unknown
    };
    size_t len = sizeof(buf);
    struct stun_message *response, *request;

    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);

    fail_unless(response->message_type == STUN_BINDING_RESPONSE, "Bad response");
    fail_unless(stun_is_ok_response(response, request), "Response not OK");
    check_address(response->mapped_address);
    check_address(response->xor_mapped_address);

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_notbinding)
{
    char buf[] = {
        0x00, 0x21, 0x00, 0x00,     // type = 0x21, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
    };
    size_t len = sizeof(buf);
    struct stun_message *response, *request;

    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);

    fail_unless(stun_is_err_response(response, request), "Response not error as expected");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_ok_msgint)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x28,     // type = 0x01, len = 0x20
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
        0x00, 0x06, 0x00, 0x09,     // USERNAME attribute header
        0x65, 0x76, 0x74, 0x6a,     //
        0x3a, 0x68, 0x36, 0x76,     //
        0x59, 0x20, 0x20, 0x20,     //
        0x00, 0x08, 0x00, 0x14,     // message integrity
        0xcf, 0xd2, 0x90, 0xef,
        0xa0, 0xa1, 0x5a, 0xd9,
        0x73, 0xb9, 0x66, 0xa6,
        0xf3, 0x01, 0x34, 0x9a,
        0x37, 0xe3, 0x96, 0x73,
    };
    char *username = "evtj:h6vY";
    char *password = "VOkJxbRl1RmTxUk/WvJxBt";
    size_t len = sizeof(buf);
    struct stun_message *response, *request;
    char buf2[128];

    stun_add_user_password(username, password, strlen(password));
    request = stun_from_bytes(buf, &len);
    response = stun_respond_to(request, &saddr);

    fail_unless(request->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Bad request");
    fail_unless(request->_password_length == strlen(password), "Bad password length");
    fail_if(request->_password == NULL, "Password missing");
    fail_unless(memcmp(request->_password, password, strlen(password)) == 0, "Bad password");

    // Reserialize for message integrity check.
    len = stun_to_bytes(buf2, sizeof(buf2), response);
    stun_free(response);

    // Add xact password after serialization to check password handoff
    stun_add_xact_password(request->xact_id, password, strlen(password));
    response = stun_from_bytes(buf2, &len);
    fail_unless(response->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Missing integrity");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(accessor_data)
{
    struct stun_message *stun = stun_new(1);
    int buf[] = {rand(), rand(), rand(), rand()};

    stun_set_data(stun, buf, sizeof(buf));
    fail_unless(stun->data_len == sizeof(buf), "Incorrect length");
    fail_unless(memcmp(stun->data, buf, sizeof(buf)) == 0, "Incorrect value");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(accessor_mapped_address)
{
    struct stun_message *stun = stun_new(1);
    struct sockaddr addr;

    init_sockaddr(&addr, sizeof(addr));
    stun_set_mapped_address(stun, &addr, sizeof(addr));
    check_sockaddr(stun->mapped_address, stun->mapped_address_len, &addr, sizeof(addr));

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(accessor_xor_mapped_address)
{
    struct stun_message *stun = stun_new(1);
    struct sockaddr addr;

    init_sockaddr(&addr, sizeof(addr));
    stun_set_xor_mapped_address(stun, &addr, sizeof(addr));
    check_sockaddr(stun->xor_mapped_address, stun->xor_mapped_address_len, &addr, sizeof(addr));

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(accessor_relay_address)
{
    struct stun_message *stun = stun_new(1);
    struct sockaddr addr;

    init_sockaddr(&addr, sizeof(addr));
    stun_set_relay_address(stun, &addr, sizeof(addr));
    check_sockaddr(stun->relay_address, stun->relay_address_len, &addr, sizeof(addr));

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(accessor_peer_address)
{
    struct stun_message *stun = stun_new(1);
    struct sockaddr addr;

    init_sockaddr(&addr, sizeof(addr));
    stun_set_peer_address(stun, &addr, sizeof(addr));
    check_sockaddr(stun->peer_address, stun->peer_address_len, &addr, sizeof(addr));

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
Suite *
check_stun()
{
    Suite *stun;
    TCase *test;
    struct sockaddr_in *sin = (struct sockaddr_in *) &saddr;

    stun = suite_create("libstern stun");

    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = rand();
    sin->sin_port = rand();

    test = tcase_create("binding");
    tcase_add_test(test, binding_ok);
    tcase_add_test(test, binding_badint);
    tcase_add_test(test, binding_ok_unknown);
    tcase_add_test(test, binding_ok_msgint);
    tcase_add_test(test, binding_notreq);
    tcase_add_test(test, binding_notcompr);
    tcase_add_test(test, binding_notxact);
    tcase_add_test(test, binding_notbinding);
    suite_add_tcase(stun, test);

    test = tcase_create("accessors");
    tcase_add_test(test, accessor_data);
    tcase_add_test(test, accessor_mapped_address);
    tcase_add_test(test, accessor_xor_mapped_address);
    tcase_add_test(test, accessor_relay_address);
    tcase_add_test(test, accessor_peer_address);
    suite_add_tcase(stun, test);

    return stun;
}
