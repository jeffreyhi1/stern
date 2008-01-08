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

struct sockaddr_in sin;

void
check_address(struct sockaddr *addr)
{
    struct sockaddr_in *ain = (struct sockaddr_in *) addr;
    fail_if(addr == NULL, "Address missing");
    fail_unless(addr->sa_family == sin.sin_family, "Bad address family");
    fail_unless(ain->sin_addr.s_addr == sin.sin_addr.s_addr, "Bad address");
    fail_unless(ain->sin_port == sin.sin_port, "Bad port");
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
    response = stun_respond_to(request, &sin);

    fail_unless(response->message_type == STUN_BINDING_RESPONSE, "Bad response");
    fail_unless(stun_is_ok_response(response, request), "Response not OK");
    check_address(response->mapped_address);
    check_address(response->xor_mapped_address);

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
    response = stun_respond_to(request, &sin);

    fail_unless(response->message_type == STUN_BINDING_ERROR, "Bad response");
    fail_unless(stun_is_err_response(response, request), "Response not error as expected");

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
    response = stun_respond_to(request, &sin);

    fail_unless(response == NULL, "Response not expected for non-request");

    stun_free(request);
    if (response)
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
    response = stun_respond_to(request, &sin);

    fail_unless(stun_is_err_response(response, request), "Response not error as expected");
    fail_unless(response->error_code == 420, "Bad error code");
    fail_if(response->unknown_attributes == NULL, "Unknown attributes missing");
    fail_unless(response->unknown_attributes[0] == 0xff, "Bad unknown attribute");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(binding_ok_with_unknown)
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
    response = stun_respond_to(request, &sin);

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
    response = stun_respond_to(request, &sin);

    fail_unless(stun_is_err_response(response, request), "Response not error as expected");

    stun_free(request);
    stun_free(response);
}
END_TEST

//------------------------------------------------------------------------------
Suite *
check_stun()
{
    Suite *stun;
    TCase *test;

    stun = suite_create("libstern stun");

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = rand();
    sin.sin_port = rand();

    test = tcase_create("binding");
    tcase_add_test(test, binding_ok);
    tcase_add_test(test, binding_badint);
    tcase_add_test(test, binding_notreq);
    tcase_add_test(test, binding_notcompr);
    tcase_add_test(test, binding_ok_with_unknown);
    tcase_add_test(test, binding_notbinding);
    suite_add_tcase(stun, test);

    return stun;
}
