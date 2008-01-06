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
#include <check.h>

#include <stern/stun.h>

//------------------------------------------------------------------------------
START_TEST(msghdr_short)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x00,     // type = 0x01, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x00, 0x00, 0x00, 0x00,     // xact_id = 0x000000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    size_t len = 19;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_unless(stun == NULL, "Parsed short header");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(msghdr_badtype)
{
    char buf[] = {
        0x80, 0x01, 0x00, 0x00,     // type = 0x8001, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x00, 0x00, 0x00, 0x00,     // xact_id = 0x000000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    size_t len = 20;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_unless(stun == NULL, "Parsed bad message type");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(msghdr_badlen)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x01,     // type = 0x01, len = 0x01
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x00, 0x00, 0x00, 0x00,     // xact_id = 0x000000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00
    };
    size_t len = 21;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_unless(stun == NULL, "Parsed bad len");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(msghdr_badmagic)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x00,     // type = 0x01, len = 0x01
        0x42, 0xa4, 0x12, 0x21,     // magic = 0x42a41221
        0x00, 0x00, 0x00, 0x00,     // xact_id = 0x000000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    size_t len = 20;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_unless(stun == NULL, "Parsed bad magic");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(msghdr_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x00,     // type = 0x01, len = 0x01
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
    };
    size_t len = 20;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_unless(stun->message_type == 0x01, "Bad message type");
    fail_unless(memcmp(stun->xact_id, buf+8, 12) == 0, "Bad xact_id");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_mapped_address_short)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x01
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08,
        0x00, 0x01, 0x00, 0x00
    };
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_unless(stun == NULL, "Parsed message with errors");
}
END_TEST

//------------------------------------------------------------------------------
Suite *
check_parser()
{
    Suite *parser;
    TCase *test;

    parser = suite_create("libstern STUN parser");

    test = tcase_create("Message_Header");
    tcase_add_test(test, msghdr_short);
    tcase_add_test(test, msghdr_badlen);
    tcase_add_test(test, msghdr_badmagic);
    tcase_add_test(test, msghdr_ok);
    suite_add_tcase(parser, test);

    test = tcase_create("Attributes");
    tcase_add_test(test, attr_mapped_address_short);
    suite_add_tcase(parser, test);

    return parser;
}
