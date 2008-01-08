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
#ifndef __STUN_H
#define __STUN_H

#define STUN_BINDING_REQUEST    0x0001
#define STUN_BINDING_RESPONSE   0x0101
#define STUN_BINDING_ERROR      0x0111

enum stun_validity {
    STUN_ATTR_NOT_PRESENT,
    STUN_ATTR_PRESENT,
    STUN_ATTR_PRESENT_AND_VALIDATED,
    STUN_ATTR_PRESENT_BUT_INVALID
};

struct stun_attribute {
    int type;
    int is_unknown;
    size_t len;
    void *value;
};

struct stun_message {
    int                    message_type;
    unsigned char          xact_id[12];
    int                    error_code;
    char                  *error_reason;
    char                  *username;
    char                  *realm;
    char                  *server;
    int                   *unknown_attributes;
    struct sockaddr       *mapped_address;
    size_t                 mapped_address_len;
    struct sockaddr       *xor_mapped_address;
    size_t                 xor_mapped_address_len;
    struct sockaddr       *alternate_server;
    size_t                 alternate_server_len;
    enum stun_validity     fingerprint;
    enum stun_validity     message_integrity;

    /* TURN Attributes */
    int                    channel;
    int                    lifetime;
    int                    bandwidth;
    struct sockaddr       *peer_address;
    size_t                 peer_address_len;
    struct sockaddr       *relay_address;
    size_t                 relay_address_len;
    void                  *data;
    size_t                 data_len;
    int                    requested_transport;
    struct sockaddr       *requested_ip_port;
    size_t                 requested_ip_port_len;
    int                    requested_port_align;
    int                    connect_status;

    // Unknown attributes
    struct stun_attribute *other;

    char                  *_password;
    int                    _password_length;
};

void
stun_free();

struct stun_message *
stun_new(int type);

struct stun_message *
stun_init_response(int type, struct stun_message *req);

struct stun_message *
stun_from_bytes(char *buf, size_t *len);

void
stun_add_user_password(char *username, char *password, int len);

void
stun_add_xact_password(char *xact_id, char *password, int len);

int
stun_to_bytes(char *buf, size_t len, struct stun_message *stun);

struct stun_message *
stun_respond_to(struct stun_message *request, struct sockaddr *addr);

int
stun_xid_matches(struct stun_message *a, struct stun_message *b);

int
stun_is_ok_response(struct stun_message *response, struct stun_message *request);

void
stun_set_data(struct stun_message *stun, char *buf, size_t len);

void
stun_set_mapped_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len);

void
stun_set_xor_mapped_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len);

void
stun_set_peer_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len);

void
stun_set_relay_address(struct stun_message *stun, struct sockaddr *addr, socklen_t len);

#endif
