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
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <check.h>

#include <stern/stun.h>

//------------------------------------------------------------------------------
void
mask_buf(char *buf, char *mask, size_t len)
{
    int i;

    for (i = 0; i < len; i++)
        buf[i] = (buf[i] & 0xFF) & mask[i];
}

//------------------------------------------------------------------------------
void
print_buf(char *buf, size_t len)
{
    int i;

    for (i = 0; i < len; i++) {
        printf("0x%02x ", buf[i] & 0xFF);
        if (i % 4 == 3) printf("\n");
    }
    printf("\n");
}

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
        0x00, 0x01, 0x00, 0x00,     // type = 0x01, len = 0x00
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
        0x00, 0x01, 0x00, 0x00,     // type = 0x01, len = 0x00
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000002000000000300
        0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x03, 0x00,
    };
    char buf2[64];
    size_t len = 21;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_unless(stun->message_type == 0x01, "Bad message type");
    fail_unless(memcmp(stun->xact_id, buf+8, 12) == 0, "Bad xact_id");
    fail_unless(len == 20, "Bad consumed length");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_toobig)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08,     // mapped_address; len = 8
        0x00, 0x01, 0x00, 0x00
    };
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_unless(stun == NULL, "Parsed oversized attribute");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_mapped_address_badlen)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x04,     // mapped_address; len = 4
        0x00, 0x01, 0x00, 0x00
    };
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_unless(stun == NULL, "Parsed bad length mapped address");
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_mapped_address_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x0c,     // type = 0x01, len = 0x0c
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x01, 0x00, 0x08,     // mapped_address; len = 8
        0x00, 0x01, 0x12, 0x34,     // family = IPv4, port = 0x1234
        0x01, 0x02, 0x03, 0x04      // addr = 1.2.3.4
    };
    char buf2[64];
    size_t len = 32;
    struct stun_message *stun;
    struct sockaddr_in *sin;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->mapped_address == NULL, "Mapped address not parsed");
    fail_if(stun->mapped_address->sa_family != AF_INET, "Mapped address family incorrect");
    fail_if(stun->mapped_address_len != sizeof(struct sockaddr_in),
            "Mapped address size incorrect");
    sin = (struct sockaddr_in *) stun->mapped_address;
    fail_if(sin->sin_port != htons(0x1234),
            "Mapped address port incorrect");
    fail_if(sin->sin_addr.s_addr != htonl(0x01020304),
            "Mapped address address incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_xor_mapped_address_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x0c,     // type = 0x01, len = 0x0c
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x00, 0x08,     // xor_mapped_address; len = 8
        0x00, 0x01, 0x33, 0x26,     // family = IPv4, port = 0x1234
        0x20, 0x10, 0xa7, 0x46      // addr = 1.2.3.4
    };
    char buf2[64];
    size_t len = 32;
    struct stun_message *stun;
    struct sockaddr_in *sin;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->xor_mapped_address == NULL, "Xor mapped address not parsed");
    fail_if(stun->xor_mapped_address->sa_family != AF_INET, "Xor mapped address family incorrect");
    fail_if(stun->xor_mapped_address_len != sizeof(struct sockaddr_in),
            "Xor mapped address size incorrect");
    sin = (struct sockaddr_in *) stun->xor_mapped_address;
    fail_if(sin->sin_port != htons(0x1234),
            "Xor mapped address port incorrect");
    fail_if(sin->sin_addr.s_addr != htonl(0x01020304),
            "Xor mapped address address incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_relay_address_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x0c,     // type = 0x01, len = 0x0c
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x16, 0x00, 0x08,     // relay_address; len = 8
        0x00, 0x01, 0x33, 0x26,     // family = IPv4, port = 0x1234
        0x20, 0x10, 0xa7, 0x46      // addr = 1.2.3.4
    };
    char buf2[64];
    size_t len = 32;
    struct stun_message *stun;
    struct sockaddr_in *sin;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->relay_address == NULL, "Relay address not parsed");
    fail_if(stun->relay_address->sa_family != AF_INET, "Relay address family incorrect");
    fail_if(stun->relay_address_len != sizeof(struct sockaddr_in),
            "Relay address size incorrect");
    sin = (struct sockaddr_in *) stun->relay_address;
    fail_if(sin->sin_port != htons(0x1234),
            "Relay address port incorrect");
    fail_if(sin->sin_addr.s_addr != htonl(0x01020304),
            "Relay address address incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_peer_address_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x0c,     // type = 0x01, len = 0x0c
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x12, 0x00, 0x08,     // peer_address; len = 8
        0x00, 0x01, 0x33, 0x26,     // family = IPv4, port = 0x1234
        0x20, 0x10, 0xa7, 0x46      // addr = 1.2.3.4
    };
    char buf2[64];
    size_t len = 32;
    struct stun_message *stun;
    struct sockaddr_in *sin;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->peer_address == NULL, "Peer address not parsed");
    fail_if(stun->peer_address->sa_family != AF_INET, "Peer address family incorrect");
    fail_if(stun->peer_address_len != sizeof(struct sockaddr_in),
            "Peer address size incorrect");
    sin = (struct sockaddr_in *) stun->peer_address;
    fail_if(sin->sin_port != htons(0x1234),
            "Peer address port incorrect");
    fail_if(sin->sin_addr.s_addr != htonl(0x01020304),
            "Peer address address incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_username_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x06, 0x00, 0x03,     // username; len = 3
        0x6d, 0x6f, 0x6f, 0x20,     // moo
    };
    char mask[] = {
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x00,
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->username == NULL, "Username not parsed");
    fail_if(strlen(stun->username) != 3, "Username length incorrect");
    fail_if(strcmp(stun->username, "moo") != 0, "Username incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    mask_buf(buf, mask, len);
    mask_buf(buf2, mask, len);
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_server_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x80, 0x22, 0x00, 0x03,     // server; len = 3
        0x6d, 0x6f, 0x6f, 0x20,     // moo
    };
    char mask[] = {
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x00,
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->server == NULL, "Server not parsed");
    fail_if(strlen(stun->server) != 3, "Server length incorrect");
    fail_if(strcmp(stun->server, "moo") != 0, "Server incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    mask_buf(buf, mask, len);
    mask_buf(buf2, mask, len);
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_realm_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x14, 0x00, 0x03,     // realm; len = 3
        0x6d, 0x6f, 0x6f, 0x20,     // moo
    };
    char mask[] = {
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x00,
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->realm == NULL, "Realm not parsed");
    fail_if(strlen(stun->realm) != 3, "Realm length incorrect");
    fail_if(strcmp(stun->realm, "moo") != 0, "Realm incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    mask_buf(buf, mask, len);
    mask_buf(buf2, mask, len);
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_data_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x13, 0x00, 0x03,     // data; len = 3
        0x6d, 0x00, 0x6f, 0x20,     // m\x00o
    };
    char mask[] = {
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x00,
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->data == NULL, "Data not parsed");
    fail_if(stun->data_len != 3, "Data length incorrect");
    fail_if(memcmp(stun->data, "m\x00o", 3) != 0, "Data incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    mask_buf(buf, mask, len);
    mask_buf(buf2, mask, len);
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_requested_transport_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x19, 0x00, 0x04,     // requested_trasnport; len = 4
        0x00, 0x00, 0x01, 0x02,     // 0x0102
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->requested_transport == -1, "Requested transport not parsed");
    fail_if(stun->requested_transport != 0x0102, "Requested transport incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_bandwidth_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x04,     // bandwidth; len = 4
        0x00, 0x00, 0x01, 0x02,     // 0x0102
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->bandwidth == 0, "Bandwidth not parsed");
    fail_if(stun->bandwidth != 0x0102, "Bandwidth incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_connect_status_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x23, 0x00, 0x04,     // connect_status; len = 4
        0x00, 0x00, 0x01, 0x02,     // 0x0102
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->connect_status == -1, "Connection status not parsed");
    fail_if(stun->connect_status != 0x0102, "Connection status incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_channel_number_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x0c, 0x00, 0x04,     // channel_number; len = 4
        0x01, 0x02, 0x00, 0x00,     // 0x0102
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->channel == -1, "Channel not parsed");
    fail_if(stun->channel != 0x0102, "Channel incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_lifetime_ok)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x08,     // type = 0x01, len = 0x08
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x0d, 0x00, 0x04,     // lifetime; len = 4
        0x00, 0x00, 0x01, 0x02,     // 0x0102
    };
    char buf2[64];
    size_t len = 28;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->lifetime == -1, "Lifetime not parsed");
    fail_if(stun->lifetime != 0x0102, "Lifetime incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_error_ok)
{
    char buf[] = {
        0x01, 0x11, 0x00, 0x14,     // type = 0x01, len = 0x14
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x09, 0x00, 0x0f,     // error; len = 15
        0x00, 0x00, 0x04, 0x14,     // code = 420
        0x74, 0x65, 0x73, 0x74,
        0x20, 0x72, 0x65, 0x61,
        0x73, 0x6f, 0x6e, 0x20,
    };
    char mask[] = {
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0x00,
    };
    char buf2[64];
    size_t len = 40;
    struct stun_message *stun;
    char *reason = "test reason";

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_unless(stun->error_code == 420, "Incorrect error code");
    fail_if(stun->error_reason == NULL, "Reason missing");
    fail_unless(strlen(stun->error_reason) == strlen(reason), "Reason length incorrect");
    fail_unless(strcmp(stun->error_reason, reason) == 0, "Reason incorrect");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    mask_buf(buf, mask, len);
    mask_buf(buf2, mask, len);
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(attr_unknown_attributes_ok)
{
    char buf[] = {
        0x01, 0x11, 0x00, 0x0c,     // type = 0x01, len = 0x0c
        0x21, 0x12, 0xa4, 0x42,     // magic = 0x2112a442
        0x01, 0x00, 0x00, 0x00,     // xact_id = 0x010000000000000000000000
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x0a, 0x00, 0x06,     // unknown_attributes; len = 6
        0x01, 0x00, 0x00, 0x02,     // code = 420
        0x00, 0x03, 0x40, 0x00,
    };
    char mask[] = {
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0x00, 0x00,
    };
    char buf2[64];
    size_t len = 32;
    struct stun_message *stun;

    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");
    fail_if(stun->unknown_attributes == NULL, "Missing unknown attributes");
    fail_unless(stun->unknown_attributes[0] == 0x0100, "Incorrect unknown attributes");
    fail_unless(stun->unknown_attributes[1] == 0x0002, "Incorrect unknown attributes");
    fail_unless(stun->unknown_attributes[2] == 0x0003, "Incorrect unknown attributes");
    fail_unless(stun->unknown_attributes[3] == 0x0000, "Incorrect unknown attributes");

    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");
    mask_buf(buf, mask, len);
    mask_buf(buf2, mask, len);
    fail_if(memcmp(buf, buf2, len) != 0, "Incorrect message bytes");

    stun_free(stun);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(vector_2_1)
{
    char buf[] = {
        0x00, 0x01, 0x00, 0x44,  // Request type and message length
        0x21, 0x12, 0xa4, 0x42,  // Message cookie
        0xb7, 0xe7, 0xa7, 0x01,  //
        0xbc, 0x34, 0xd6, 0x86,  // Transaction ID
        0xfa, 0x87, 0xdf, 0xae,  //
        0x00, 0x24, 0x00, 0x04,  //
        0x6e, 0x00, 0x01, 0xff,  //
        0x80, 0x29, 0x00, 0x08,  //
        0x93, 0x2f, 0xf9, 0xb1,  //
        0x51, 0x26, 0x3b, 0x36,  //
        0x00, 0x06, 0x00, 0x09,  // USERNAME attribute header
        0x65, 0x76, 0x74, 0x6a,  //
        0x3a, 0x68, 0x36, 0x76,  // Username (9 bytes) and padding (3 bytes)
        0x59, 0x20, 0x20, 0x20,  //
        0x00, 0x08, 0x00, 0x14,  // MESSAGE-INTEGRITY attribute header
        0x62, 0x4e, 0xeb, 0xdc,  //
        0x3c, 0xc9, 0x2d, 0xd8,  //
        0x4b, 0x74, 0xbf, 0x85,  // HMAC-SHA1 fingerprint
        0xd1, 0xc0, 0xf5, 0xde,  //
        0x36, 0x87, 0xbd, 0x33,  //
        0x80, 0x28, 0x00, 0x04,  // FINGERPRINT attribute header
        0xad, 0x8a, 0x85, 0xff,  // CRC32 fingerprint
    };
    size_t len = sizeof(buf);
    char buf2[128];
    struct stun_message *stun, *stun2;
    char *username = "evtj:h6vY";
    char *password = "VOkJxbRl1RmTxUk/WvJxBt";
    char *xact_id = "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae";

    stun_add_user_password(username, password, strlen(password));
    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");

    /* Message type */
    fail_unless(stun->message_type == 1, "Incorrect message type");

    /* Xact ID */
    fail_unless(memcmp(stun->xact_id, xact_id, 12) == 0, "Incorrect transaction ID");

    /* Username */
    fail_if(stun->username == NULL, "Missing username");
    fail_unless(strlen(stun->username) == strlen(username), "Incorrect username length");
    fail_unless(strcmp(stun->username, username) == 0, "Incorrect username");

    /* Unknown attributes */
    fail_if(stun->other == NULL, "Unknown attributes incorrectly parsed");
    fail_unless(stun->other[2].type == 0, "Incorrect number of unknown attributes");

    /* First unknown */
    fail_unless(stun->other[0].type == 0x24, "Incorrect type");
    fail_unless(stun->other[0].len == 4, "Incorrect length");
    fail_unless(memcmp(stun->other[0].value, "\x6e\x00\x01\xff", 4) == 0, "Incorrect value");

    /* Second unknown */
    fail_unless(stun->other[1].type == 0x8029, "Incorrect type");
    fail_unless(stun->other[1].len == 8, "Incorrect length");
    fail_unless(memcmp(stun->other[1].value,
                       "\x93\x2f\xf9\xb1\x51\x26\x3b\x36", 4) == 0, "Incorrect value");

    /* Message integrity */
    fail_unless(stun->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Message integrity mismatch");

    /* Fingerprint */
    fail_unless(stun->fingerprint == STUN_ATTR_PRESENT_AND_VALIDATED, "Fingerprint mismatch");

    /* re-serialize */
    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");

    /* Cannot check directly against buf because of attribute ordering and padding
     * differences. Since de-serialization worked uptil here, check after re-deserializing */
    stun2 = stun_from_bytes(buf2, &len);
    fail_unless(stun2->fingerprint == STUN_ATTR_PRESENT_AND_VALIDATED, "Fingerprint mismatch");
    fail_unless(stun2->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Message integrity mismatch");

    stun_free(stun);
    stun_free(stun2);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(vector_2_2)
{
    char buf[] = {
        0x01, 0x01, 0x00, 0x3c,  // Response type and message length
        0x21, 0x12, 0xa4, 0x42,  // Message cookie
        0xb7, 0xe7, 0xa7, 0x01,  //
        0xbc, 0x34, 0xd6, 0x86,  // Transaction ID
        0xfa, 0x87, 0xdf, 0xae,  //
        0x80, 0x22, 0x00, 0x0b,  //
        0x74, 0x65, 0x73, 0x74,  //
        0x20, 0x76, 0x65, 0x63,  //
        0x74, 0x6f, 0x72, 0x20,  //
        0x00, 0x20, 0x00, 0x08,  //
        0x00, 0x01, 0xa1, 0x47,  //
        0xe1, 0x12, 0xa6, 0x43,  //
        0x00, 0x08, 0x00, 0x14,  // MESSAGE-INTEGRITY attribute header
        0x2b, 0x91, 0xf5, 0x99,  //
        0xfd, 0x9e, 0x90, 0xc3,  //
        0x8c, 0x74, 0x89, 0xf9,  // HMAC-SHA1 fingerprint
        0x2a, 0xf9, 0xba, 0x53,  //
        0xf0, 0x6b, 0xe7, 0xd7,  //
        0x80, 0x28, 0x00, 0x04,  // FINGERPRINT attribute header
        0xc0, 0x7d, 0x4c, 0x96,  // CRC32 fingerprint
    };
    size_t len = sizeof(buf);
    char buf2[128];
    struct stun_message *stun, *stun2;
    char *password = "VOkJxbRl1RmTxUk/WvJxBt";
    char *server = "test vector";
    int port = 32853;
    int ip = 0xc0000201;
    char *xact_id = "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae";
    struct sockaddr_in *sin;

    stun_add_xact_password(xact_id, password, strlen(password));
    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");

    /* Message type */
    fail_unless(stun->message_type == 0x101, "Incorrect message type");

    /* Xact ID */
    fail_unless(memcmp(stun->xact_id, xact_id, 12) == 0, "Incorrect transaction ID");

    /* Server */
    fail_if(stun->server == NULL, "Missing server");
    fail_unless(strlen(stun->server) == strlen(server), "Incorrect server length");
    fail_unless(strcmp(stun->server, server) == 0, "Incorrect server");

    /* Xor mapped address */
    fail_if(stun->xor_mapped_address == NULL, "Xor mapped address not parsed");
    fail_if(stun->xor_mapped_address->sa_family != AF_INET, "Xor mapped address family incorrect");
    fail_if(stun->xor_mapped_address_len != sizeof(struct sockaddr_in),
            "Xor mapped address size incorrect");
    sin = (struct sockaddr_in *) stun->xor_mapped_address;
    fail_if(sin->sin_port != htons(port), "Xor mapped address port incorrect");
    fail_if(sin->sin_addr.s_addr != htonl(ip), "Xor mapped address address incorrect");

    /* Message integrity */
    fail_unless(stun->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Message integrity mismatch");

    /* Fingerprint */
    fail_unless(stun->fingerprint == STUN_ATTR_PRESENT_AND_VALIDATED, "Fingerprint mismatch");

    /* re-serialize */
    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");

    /* Cannot check directly against buf because of attribute ordering and padding
     * differences. Since de-serialization worked uptil here, check after re-deserializing */
    stun2 = stun_from_bytes(buf2, &len);
    fail_unless(stun2->fingerprint == STUN_ATTR_PRESENT_AND_VALIDATED, "Fingerprint mismatch");
    fail_unless(stun2->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Message integrity mismatch");

    stun_free(stun);
    stun_free(stun2);
}
END_TEST

//------------------------------------------------------------------------------
START_TEST(vector_2_3)
{
    char buf[] = {
        0x01, 0x01, 0x00, 0x48,  // Response type and message length
        0x21, 0x12, 0xa4, 0x42,  // Message cookie
        0xb7, 0xe7, 0xa7, 0x01,  //
        0xbc, 0x34, 0xd6, 0x86,  // Transaction ID
        0xfa, 0x87, 0xdf, 0xae,  //
        0x80, 0x22, 0x00, 0x0b,  //
        0x74, 0x65, 0x73, 0x74,  //
        0x20, 0x76, 0x65, 0x63,  //
        0x74, 0x6f, 0x72, 0x20,  //
        0x00, 0x20, 0x00, 0x14,  //
        0x00, 0x02, 0xa1, 0x47,  //
        0x01, 0x13, 0xa9, 0xfa,  //
        0xa5, 0xd3, 0xf1, 0x79,  //
        0xbc, 0x25, 0xf4, 0xb5,  //
        0xbe, 0xd2, 0xb9, 0xd9,  //
        0x00, 0x08, 0x00, 0x14,  // MESSAGE-INTEGRITY attribute header
        0xa3, 0x82, 0x95, 0x4e,  //
        0x4b, 0xe6, 0x7b, 0xf1,  //
        0x17, 0x84, 0xc9, 0x7c,  // HMAC-SHA1 fingerprint
        0x82, 0x92, 0xc2, 0x75,  //
        0xbf, 0xe3, 0xed, 0x41,  //
        0x80, 0x28, 0x00, 0x04,  // FINGERPRINT attribute header
        0xc8, 0xfb, 0x0b, 0x4c,  // CRC32 fingerprint
    };
    size_t len = sizeof(buf);
    char buf2[128];
    struct stun_message *stun, *stun2;
    char *password = "VOkJxbRl1RmTxUk/WvJxBt";
    char *server = "test vector";
    int port = 32853;
    char *ip = "\x20\x01\x0d\xb8\x12\x34\x56\x78\x00\x11\x22\x33\x44\x55\x66\x77";
    char *xact_id = "\xb7\xe7\xa7\x01\xbc\x34\xd6\x86\xfa\x87\xdf\xae";
    struct sockaddr_in6 *sin6;

    stun_add_xact_password(xact_id, password, strlen(password));
    stun = stun_from_bytes(buf, &len);
    fail_if(stun == NULL, "Not parsed OK message");

    /* Message type */
    fail_unless(stun->message_type == 0x101, "Incorrect message type");

    /* Xact ID */
    fail_unless(memcmp(stun->xact_id, xact_id, 12) == 0, "Incorrect transaction ID");

    /* Server */
    fail_if(stun->server == NULL, "Missing server");
    fail_unless(strlen(stun->server) == strlen(server), "Incorrect server length");
    fail_unless(strcmp(stun->server, server) == 0, "Incorrect server");

    /* Xor mapped address */
    fail_if(stun->xor_mapped_address == NULL, "Xor mapped address not parsed");
    fail_if(stun->xor_mapped_address->sa_family != AF_INET6, "Xor mapped address family incorrect");
    fail_if(stun->xor_mapped_address_len != sizeof(struct sockaddr_in6),
            "Xor mapped address size incorrect");
    sin6 = (struct sockaddr_in6 *) stun->xor_mapped_address;
    fail_if(sin6->sin6_port != htons(port), "Xor mapped address port incorrect");
    fail_if(memcmp(sin6->sin6_addr.s6_addr, ip, 16), "Xor mapped address address incorrect");

    /* Message integrity */
    fail_unless(stun->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Message integrity mismatch");

    /* Fingerprint */
    fail_unless(stun->fingerprint == STUN_ATTR_PRESENT_AND_VALIDATED, "Fingerprint mismatch");

    /* re-serialize */
    fail_if(stun_to_bytes(buf2, sizeof(buf2), stun) != len, "Incorrect message size");

    /* Cannot check directly against buf because of attribute ordering and padding
     * differences. Since de-serialization worked uptil here, check after re-deserializing */
    stun2 = stun_from_bytes(buf2, &len);
    fail_unless(stun2->fingerprint == STUN_ATTR_PRESENT_AND_VALIDATED, "Fingerprint mismatch");
    fail_unless(stun2->message_integrity == STUN_ATTR_PRESENT_AND_VALIDATED, "Message integrity mismatch");

    stun_free(stun);
    stun_free(stun2);
}
END_TEST

//------------------------------------------------------------------------------
Suite *
check_parser()
{
    Suite *parser;
    TCase *test;

    parser = suite_create("libstern STUN parser");

    test = tcase_create("header");
    tcase_add_test(test, msghdr_short);
    tcase_add_test(test, msghdr_badtype);
    tcase_add_test(test, msghdr_badlen);
    tcase_add_test(test, msghdr_badmagic);
    tcase_add_test(test, msghdr_ok);
    suite_add_tcase(parser, test);

    test = tcase_create("attributes");
    tcase_add_test(test, attr_toobig);
    tcase_add_test(test, attr_mapped_address_badlen);
    tcase_add_test(test, attr_mapped_address_ok);
    tcase_add_test(test, attr_xor_mapped_address_ok);
    tcase_add_test(test, attr_relay_address_ok);
    tcase_add_test(test, attr_peer_address_ok);
    tcase_add_test(test, attr_username_ok);
    tcase_add_test(test, attr_server_ok);
    tcase_add_test(test, attr_realm_ok);
    tcase_add_test(test, attr_data_ok);
    tcase_add_test(test, attr_requested_transport_ok);
    tcase_add_test(test, attr_bandwidth_ok);
    tcase_add_test(test, attr_connect_status_ok);
    tcase_add_test(test, attr_channel_number_ok);
    tcase_add_test(test, attr_lifetime_ok);
    tcase_add_test(test, attr_error_ok);
    tcase_add_test(test, attr_unknown_attributes_ok);
    suite_add_tcase(parser, test);

    test = tcase_create("draft-ietf-behave-stun-test-vectors");
    tcase_add_test(test, vector_2_1);
    tcase_add_test(test, vector_2_2);
    tcase_add_test(test, vector_2_3);
    suite_add_tcase(parser, test);

    return parser;
}
