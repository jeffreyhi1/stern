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
#include "libstern.h"

#define CACHE_TIMEOUT       120
#define CACHE_FULL          64

#pragma pack(push)
typedef struct {
    uint16_t type;
    uint16_t len;
    uint32_t magic;
    uint8_t xact_id[12];
} message_t;

typedef struct {
    uint16_t type;
    uint16_t len;
    union {
        uint8_t bytes[0];
        struct {
            uint8_t zero;
            uint8_t family;
            uint16_t port;
            union {
                uint32_t addr4;
                uint8_t addr6[16];
            } ip;
        } addr;
        struct {
            uint16_t zero;
            uint8_t class;
            uint8_t number;
            uint8_t reason[0];
        } error;
        struct {
            uint16_t attr[0];
        } attrs;
        struct {
            uint16_t num[2];
        } u16;
        uint32_t u32;
    } v;
} attribute_t;
#pragma pack(pop)

typedef struct password {
    uint8_t *xact_id;
    char *username;
    char *password;
    time_t expire;
    int len;
} password_t;
static password_t *passwords = NULL;
static int num_passwords;

#if 0
static attribute_t *
find_attribute(uint16_t attribute, uint8_t *buf, size_t len)
{
    int i;

    for (i = STUN_HLEN; i < len;
         i += STUN_AHLEN + PAD4(ntohs(((attribute_t *) &buf[i])->len))) {
        if (ntohs(((attribute_t *) &buf[i])->type) == attribute)
            return (attribute_t *) &buf[i];
    }
    return NULL;
}
#endif

//------------------------------------------------------------------------------
static void
reap_auth_keys()
{
    int live_passwords = 0;
    int i;
    time_t now;

    now = time(NULL);
    for (i = 0; i < num_passwords; i++) {
        if (passwords[i].expire == 0 ||
            passwords[i].expire < now ||
            i == live_passwords)
            continue;
        passwords[live_passwords++] = passwords[i];
    }
    passwords = (password_t *) s_realloc(
            passwords, live_passwords * sizeof(password_t));
    num_passwords = live_passwords;
}

//------------------------------------------------------------------------------
static void
add_auth_key_by_xid(char *key, int len, uint8_t *xact_id)
{
    password_t *pass;

    passwords = (password_t *) s_realloc(
            passwords, (++num_passwords) * sizeof(password_t));
    pass = &passwords[num_passwords - 1];
    pass->password = (char *) s_malloc(len);
    memcpy(pass->password, key, len);
    pass->xact_id = (uint8_t *) s_malloc(STUN_XIDLEN);
    memcpy(pass->xact_id, xact_id, STUN_XIDLEN);
    pass->username = NULL;
    pass->len = len;
    pass->expire = time(NULL) + CACHE_TIMEOUT;

    if (num_passwords > CACHE_FULL)
        reap_auth_keys();
}

//------------------------------------------------------------------------------
static void
add_auth_key_by_username(char *key, int len, char *username)
{
    password_t *pass;

    passwords = (password_t *) s_realloc(
            passwords, (++num_passwords) * sizeof(password_t));
    pass = &passwords[num_passwords - 1];
    pass->password = (char *) s_malloc(len);
    memcpy(pass->password, key, len);
    pass->xact_id = NULL;
    pass->username = strdup(username);
    pass->len = len;
    pass->expire = 0;

    if (num_passwords > CACHE_FULL)
        reap_auth_keys();
}

//------------------------------------------------------------------------------
static int
matches_xid(uint8_t *xida, uint8_t *xidb)
{
    return memcmp(xida, xidb, STUN_XIDLEN) == 0;
}

#if 0
//------------------------------------------------------------------------------
static int
get_auth_key_default(char **key, int *len, struct stun_message *stun)
{
    if (stun->username && stun->realm)
        if (strcmp(stun->username, DEFAULT_USERNAME) == 0
            && strcmp(stun->realm, DEFAULT_REALM) == 0) {
            *key = DEFAULT_PASSWORD;
            *len = DEFAULT_PASSWORD_LEN;
            return 0;
        }
    return -1;
}
#endif

//------------------------------------------------------------------------------
static int
get_auth_key_from_installed(char **key, int *len, struct stun_message *stun)
{
    int i;

    if (!stun->username)
        return -1;

    for (i = 0; i < num_passwords; i++) {
        if (passwords[i].username &&
            strcmp(stun->username, passwords[i].username) == 0) {
            *len = passwords[i].len;
            *key = passwords[i].password;
            return 0;
        }
    }

    return -1;
}

//------------------------------------------------------------------------------
static int
get_auth_key_from_cache(char **key, int *len, struct stun_message *stun)
{
    int i;
    password_t *pass;

    for (i = 0; i < num_passwords; i++) {
        pass = &passwords[i];
        if ((pass->xact_id && matches_xid(pass->xact_id, stun->xact_id))
            || (pass->username && stun->username
                && strcmp(pass->username, stun->username) == 0)) {
            *key = pass->password;
            *len = pass->len;
            return 0;
        }
    }
    return -1;
}

//------------------------------------------------------------------------------
static int
get_auth_key_from_message(char **key, int *len, struct stun_message *stun)
{
    if (stun->_password) {
        *key = stun->_password;
        *len = stun->_password_length;
        return 0;
    }
    return -1;
}

//------------------------------------------------------------------------------
static int
get_auth_key(char **key, int *len, struct stun_message *stun)
{
    /* Check user installed keys */
    if (get_auth_key_from_installed(key, len, stun) == 0)
        return 0;

    /* Use password used to validate request, if any */
    if (get_auth_key_from_message(key, len, stun) == 0)
        return 0;

    /* Check cache */
    if (get_auth_key_from_cache(key, len, stun) == 0)
        return 0;

#if 0
    /* Try default password for testing purposes */
    if (get_auth_key_default(key, len, stun) == 0)
        return 0;
#endif

    return -1;
}

//------------------------------------------------------------------------------
static int
is_stun_message(char *buf, size_t len)
{
    message_t *stun = (message_t *) buf;

    /* Minimum message length */
    if (len < 20)
        return 0;
    /* Top two bits, and last two bits of length should be 0 */
    if ((buf[0] & 0xC0) != 0 || (buf[3] & 0x3) != 0)
        return 0;
    /* Magic cookie */
    if (ntohl(stun->magic) != STUN_MAGIC)
        return 0;
    /* Have full message? */
    if (len < STUN_HLEN + ntohs(stun->len))
        return 0;

    return 1;
}

//------------------------------------------------------------------------------
static int
set_fingerprint_from_attr(struct stun_message *stun, char *buf,
                          attribute_t * attr)
{
    uint32_t crc;

    if (ntohs(attr->len) != 4)
        return -1;
    stun->fingerprint = STUN_ATTR_PRESENT_AND_VALIDATED;
    crc = crc32(0, (uint8_t *) buf, ((char *) attr) - buf);
    crc ^= STUN_FINGERPRINT_MAGIC;
    if (crc != ntohl(attr->v.u32))
        stun->fingerprint = STUN_ATTR_PRESENT_BUT_INVALID;
    return 0;
}

//------------------------------------------------------------------------------
static int
set_message_integrity_from_attr(struct stun_message *stun, char *buf,
                                attribute_t * attr)
{
    uint8_t hmac[20];
    unsigned int hmac_len = sizeof(hmac);
    char *key;
    int len, blen;
    uint16_t msglen;
    message_t *msg;

    if (ntohs(attr->len) != hmac_len)
        return -1;

    stun->message_integrity = STUN_ATTR_PRESENT;
    if (get_auth_key(&key, &len, stun) == -1)
        return 0;

    /* RFC3489bis 14.4: Message length should include only upto message integrity */
    msg = (message_t *) buf;
    msglen = msg->len;
    blen = ((char *) attr) - buf;
    msg->len = htons(blen - STUN_HLEN + STUN_AHLEN + hmac_len);
    HMAC(EVP_sha1(), key, len, (uint8_t *) buf, blen, hmac, &hmac_len);
    msg->len = msglen;

#if 0
    int i;
    for (i = 0; i < sizeof(hmac); i++)
        printf("0x%02x, \n", hmac[i]);
    printf("\n");
#endif

    if (memcmp(attr->v.bytes, hmac, hmac_len) != 0) {
        stun->message_integrity = STUN_ATTR_PRESENT_BUT_INVALID;
    } else {
        stun->message_integrity = STUN_ATTR_PRESENT_AND_VALIDATED;
        if (IS_REQUEST(stun->message_type)) {
            stun->_password_length = len;
            stun->_password = s_malloc(len);
            memcpy(stun->_password, key, len);
        }
    }
    return 0;
}

//------------------------------------------------------------------------------
static struct stun_message *
allocate_stun_from_bytes(char *buf, size_t *len)
{
    struct stun_message *stun;
    message_t *msg;

    if (!is_stun_message(buf, *len))
        return NULL;
    msg = (message_t *) buf;
    stun = stun_new(ntohs(msg->type));
    memcpy(stun->xact_id, msg->xact_id, STUN_XIDLEN);
    *len = STUN_HLEN + ntohs(msg->len);
    return stun;
}

//------------------------------------------------------------------------------
static int
reallocate_other_from_attr(struct stun_message *stun, int num_other,
                         attribute_t * attr)
{
    struct stun_attribute *stun_attr;

    stun->other = (struct stun_attribute *) s_realloc(
            stun->other,
            (++num_other + 1) * sizeof(struct stun_attribute));

    stun_attr = &stun->other[num_other - 1];
    stun_attr->type = ntohs(attr->type);
    stun_attr->len = ntohs(attr->len);
    stun_attr->is_unknown = 1;
    stun_attr->value = NULL;
    if (stun_attr->len) {
        stun_attr->value = s_malloc(stun_attr->len + 1);
        memcpy(stun_attr->value, attr->v.bytes, stun_attr->len);
        ((uint8_t *) stun_attr->value)[stun_attr->len] = '\0';
    }

    /* end marker type=0 */
    stun_attr = &stun->other[num_other];
    stun_attr->type = 0;
    stun_attr->len = 0;
    stun_attr->value = NULL;
    return num_other;
}

//------------------------------------------------------------------------------
static int
allocate_string_from_attr(char **str, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);
    char *buf;

    *str = NULL;
    if (alen == 0)
        return 0;
    buf = s_malloc(alen + 1);
    memcpy(buf, attr->v.bytes, alen);
    buf[alen] = '\0';
    *str = buf;
    return 0;
}

//------------------------------------------------------------------------------
static int
allocate_buf_from_attr(void **buf, size_t *len, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);

    *buf = NULL;
    if (alen == 0)
        return 0;
    *buf = s_malloc(alen);
    memcpy(*buf, attr->v.bytes, alen);
    *len = alen;
    return 0;
}

//------------------------------------------------------------------------------
static int
copy_uint32_from_attr(unsigned int *val, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);

    if (alen != 4)
        return -1;
    *val = ntohl(attr->v.u32);
    return 0;
}

//------------------------------------------------------------------------------
static int
copy_uint16_from_attr(unsigned int *val, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);

    if (alen != 4)
        return -1;
    *val = ntohs(attr->v.u16.num[0]);
    return 0;
}

//------------------------------------------------------------------------------
static int
allocate_error_from_attr(struct stun_message *stun, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);
    char *buf;

    stun->error_reason = NULL;
    if (alen < 4)
        return -1;
    stun->error_code = attr->v.error.class * 100 + attr->v.error.number;
    if (alen == 4)
        return 0;
    buf = s_malloc(alen - 4 + 1);
    memcpy(buf, attr->v.error.reason, alen - 4);
    buf[alen - 4] = '\0';
    stun->error_reason = buf;
    return 0;
}

//------------------------------------------------------------------------------
static int
allocate_unkown_attrs_from_attr(struct stun_message *stun, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);
    int i, num = alen / 2;

    stun->unknown_attributes = NULL;
    if (alen < 2)
        return -1;
    stun->unknown_attributes = s_malloc((num + 1) * sizeof(int));
    for (i = 0; i < num; i++)
        stun->unknown_attributes[i] = ntohs(attr->v.attrs.attr[i]);
    stun->unknown_attributes[i] = 0;
    return 0;
}

//------------------------------------------------------------------------------
static int
allocate_sockaddr_from_attr(struct sockaddr **addr, size_t *addrlen, attribute_t * attr)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    int i;

    *addr = NULL;
    *addrlen = 0;
    if (attr->v.addr.family == STUN_ADDR_IP4) {
        if (ntohs(attr->len) != 8)
            return -1;
        sin = s_malloc(sizeof(struct sockaddr_in));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = attr->v.addr.ip.addr4;
        sin->sin_port = attr->v.addr.port;
        *addr = (struct sockaddr *) sin;
        *addrlen = sizeof(struct sockaddr_in);
        return 0;
    } else if (attr->v.addr.family == STUN_ADDR_IP6) {
        if (ntohs(attr->len) != 20)
            return -1;
        sin6 = s_malloc(sizeof(struct sockaddr_in6));
        sin6->sin6_family = AF_INET6;
        for (i = 0; i < 16; i++)
            sin6->sin6_addr.s6_addr[i] = attr->v.addr.ip.addr6[i];
        sin6->sin6_port = attr->v.addr.port;
        *addr = (struct sockaddr *) sin6;
        *addrlen = sizeof(struct sockaddr_in6);
        return 0;
    }
    return -1;
}

//------------------------------------------------------------------------------
static int
allocate_sockaddr_from_xor_attr(struct sockaddr **addr, size_t *addrlen, attribute_t * attr, uint8_t *buf)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    int i;

    if (allocate_sockaddr_from_attr(addr, addrlen, attr) == -1)
        return -1;

    if (attr->v.addr.family == STUN_ADDR_IP4) {
        sin = (struct sockaddr_in *) *addr;
        sin->sin_port ^= htons((STUN_MAGIC >> 16) & 0xFFFF);
        sin->sin_addr.s_addr ^= htonl(STUN_MAGIC);
    } else if (attr->v.addr.family == STUN_ADDR_IP6) {
        sin6 = (struct sockaddr_in6 *) *addr;
        sin6->sin6_port ^= htons((STUN_MAGIC >> 16) & 0xFFFF);
        for (i = 0; i < 16; i++)
            sin6->sin6_addr.s6_addr[i] ^= buf[i + 4];
    }
    return 0;
}

//------------------------------------------------------------------------------
static int
copy_string_to_attr(attribute_t * attr, size_t len, char *str)
{
    size_t alen = strlen(str);

    if (PAD4(alen) + STUN_AHLEN > len)
        return -1;
    memset((void *) attr, 0, STUN_AHLEN + PAD4(alen));
    attr->len = htons(alen);
    memcpy(attr->v.bytes, str, alen);
    return PAD4(alen) + STUN_AHLEN;
}

//------------------------------------------------------------------------------
static int
copy_buf_to_attr(attribute_t * attr, size_t len, char *buf, size_t blen)
{
    if (PAD4(blen) + STUN_AHLEN > len)
        return -1;
    attr->len = htons(blen);
    memcpy(attr->v.bytes, buf, blen);
    memset(STUN_AHLEN + blen + (void *) attr, 0, PAD4(blen) - blen);
    return PAD4(blen) + STUN_AHLEN;
}

//------------------------------------------------------------------------------
static int
copy_uint16_to_attr(attribute_t * attr, size_t len, uint16_t val)
{
    if (4 + STUN_AHLEN > len)
        return -1;
    attr->len = htons(4);
    attr->v.u16.num[0] = htons(val);
    attr->v.u16.num[1] = 0;
    return 4 + STUN_AHLEN;
}

//------------------------------------------------------------------------------
static int
copy_uint32_to_attr(attribute_t * attr, size_t len, unsigned int val)
{
    if (4 + STUN_AHLEN > len)
        return -1;
    attr->len = htons(4);
    attr->v.u32 = htonl(val);
    return 4 + STUN_AHLEN;
}

//------------------------------------------------------------------------------
static int
copy_sockaddr_to_attr(attribute_t * attr, size_t len, struct sockaddr *addr)
{
    size_t alen = addr->sa_family == AF_INET ? 8 : 20;
    struct sockaddr_in *sin = (struct sockaddr_in *) addr;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) addr;

    if (alen + STUN_AHLEN > len)
        return -1;
    if (addr->sa_family == AF_INET) {
        attr->len = htons(8);
        attr->v.addr.family = STUN_ADDR_IP4;
        attr->v.addr.port = sin->sin_port;
        attr->v.addr.ip.addr4 = sin->sin_addr.s_addr;
        attr->v.addr.zero = 0;
        return STUN_AHLEN + 8;
    } else if (addr->sa_family == AF_INET6) {
        attr->len = htons(20);
        attr->v.addr.family = STUN_ADDR_IP6;
        attr->v.addr.port = sin6->sin6_port;
        memcpy(attr->v.addr.ip.addr6, sin6->sin6_addr.s6_addr, 16);
        attr->v.addr.zero = 0;
        return STUN_AHLEN + 20;
    } else {
        return -1;
    }
}

//------------------------------------------------------------------------------
static int
copy_sockaddr_to_xor_attr(attribute_t * attr, size_t len, struct sockaddr *addr, uint8_t *buf)
{
    int ret, i;

    ret = copy_sockaddr_to_attr(attr, len, addr);
    if (ret == -1)
        return -1;
    attr->v.addr.port ^= htons((STUN_MAGIC >> 16) & 0xFFFF);
    if (addr->sa_family == AF_INET) {
        attr->v.addr.ip.addr4 ^= htonl(STUN_MAGIC);
    } else if (addr->sa_family == AF_INET6) {
        for (i = 0; i < 16; i++)
            attr->v.addr.ip.addr6[i] ^= ((uint8_t *) buf)[i + 4];
    }
    return ret;
}

//------------------------------------------------------------------------------
static void
fix_fingerprint_bytes(char *buf, attribute_t * fingerprint)
{
    uint32_t crc;

    crc = crc32(0, (uint8_t *) buf, ((char *) fingerprint) - buf);
    crc ^= STUN_FINGERPRINT_MAGIC;
    fingerprint->v.u32 = htonl(crc);
}

//------------------------------------------------------------------------------
static int
fingerprint_to_bytes(char *buf, size_t pos, size_t len,
                     attribute_t ** fingerprint)
{
    attribute_t *attr = (attribute_t *) (buf + pos);

    if (pos + STUN_AHLEN + 4 > len)
        return pos;
    *fingerprint = attr;
    attr->type = htons(ATTR_FINGERPRINT);
    attr->len = htons(4);
    return pos + STUN_AHLEN + 4;
}

//------------------------------------------------------------------------------
static void
fix_message_integrity_bytes(char *buf, attribute_t * message_integrity,
                            struct stun_message *stun)
{
    uint8_t hmac[20];
    unsigned int hmac_len = sizeof(hmac);
    char *key;
    int len;
    int i, blen;
    uint16_t msglen;
    message_t *msg;

    if (get_auth_key(&key, &len, stun) == -1)
        return;

    /* RFC3489bis 14.4: Message length should include only upto message integrity */
    msg = (message_t *) buf;
    msglen = msg->len;
    blen = ((char *) message_integrity) - buf;
    msg->len = htons(blen - STUN_HLEN + STUN_AHLEN + hmac_len);
    HMAC(EVP_sha1(), key, len, (uint8_t *) buf, blen, hmac, &hmac_len);
    msg->len = msglen;

    for (i = 0; i < sizeof(hmac); i++)
        message_integrity->v.bytes[i] = hmac[i];
    if (IS_REQUEST(stun->message_type))
        add_auth_key_by_xid(key, len, stun->xact_id);
}

//------------------------------------------------------------------------------
static int
message_integrity_to_bytes(char *buf, size_t pos, size_t len,
                           attribute_t ** messageintegrity)
{
    attribute_t *attr = (attribute_t *) (buf + pos);

    if (pos + STUN_AHLEN + 20 > len)
        return pos;
    *messageintegrity = attr;
    attr->type = htons(ATTR_MESSAGE_INTEGRITY);
    attr->len = htons(20);
    memset(attr->v.bytes, 0, 20);
    return pos + STUN_AHLEN + 20;
}

//------------------------------------------------------------------------------
static int
unknown_attributes_to_bytes(char *buf, size_t pos, size_t len,
                            struct stun_message *stun)
{
    int i;
    attribute_t *attr = (attribute_t *) (buf + pos);

    for (i = 0; stun->unknown_attributes[i]; i++) {
        if (pos + STUN_AHLEN + PAD4(2 * (1 + i)) > len)
            return pos;
        attr->v.attrs.attr[i] = htons(stun->unknown_attributes[i] & 0xFFFF);
    }
    if (i % 2 == 1)
        attr->v.attrs.attr[i] = 0;
    attr->type = htons(ATTR_UNKNOWN_ATTRIBUTES);
    attr->len = htons(2 * i);
    return pos + STUN_AHLEN + PAD4(2 * i);
}

//------------------------------------------------------------------------------
static int
other_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    int i;
    attribute_t *attr;

    for (i = 0; stun->other[i].type; i++) {
        if (pos + STUN_AHLEN + PAD4(stun->other[i].len) > len)
            return pos;
        attr = (attribute_t *) (buf + pos);
        attr->type = htons(stun->other[i].type);
        attr->len = htons(stun->other[i].len);
        memcpy(attr->v.bytes, stun->other[i].value, stun->other[i].len);
        pos += STUN_AHLEN + PAD4(stun->other[i].len);
    }
    return pos;
}

//------------------------------------------------------------------------------
static int
error_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    const char *reason = stun->error_reason;
    size_t slen;

    if (!reason)
        reason = stun_error_reason(stun->error_code);
    slen = strlen(reason);

    if (pos + STUN_AHLEN + 4 + PAD4(slen) > len)
        return pos;
    attr->type = htons(ATTR_ERROR_CODE);
    attr->len = htons(4 + slen);
    attr->v.error.zero = 0;
    attr->v.error.class = stun->error_code / 100;
    attr->v.error.number = stun->error_code % 100;
    memcpy(attr->v.error.reason, reason, slen);
    if (slen % 4)
        memset(attr->v.error.reason + slen, 0, PAD4(slen) - slen);
    return pos + STUN_AHLEN + 4 + PAD4(slen);
}

//------------------------------------------------------------------------------
static int
xor_mapped_address_to_bytes(char *buf, size_t pos, size_t len,
                            struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_sockaddr_to_xor_attr(attr, len - pos, stun->xor_mapped_address, (uint8_t *) buf);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_XOR_MAPPED_ADDRESS);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
peer_address_to_bytes(char *buf, size_t pos, size_t len,
                            struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_sockaddr_to_xor_attr(attr, len - pos, stun->peer_address, (uint8_t *) buf);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_PEER_ADDRESS);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
relay_address_address_to_bytes(char *buf, size_t pos, size_t len,
                            struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_sockaddr_to_xor_attr(attr, len - pos, stun->relay_address, (uint8_t *) buf);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_RELAY_ADDRESS);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
mapped_address_to_bytes(char *buf, size_t pos, size_t len,
                        struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_sockaddr_to_attr(attr, len - pos, stun->mapped_address);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_MAPPED_ADDRESS);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
realm_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_string_to_attr(attr, len - pos, stun->realm);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_REALM);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
data_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_buf_to_attr(attr, len - pos, stun->data, stun->data_len);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_DATA);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
lifetime_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_uint32_to_attr(attr, len - pos, (uint32_t) stun->lifetime);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_LIFETIME);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
channel_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_uint16_to_attr(attr, len - pos, (uint16_t) stun->channel);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_CHANNEL_NUMBER);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
connect_status_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_uint32_to_attr(attr, len - pos, (uint32_t) stun->connect_status);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_CONNECT_STATUS);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
bandwidth_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_uint32_to_attr(attr, len - pos, (uint32_t) stun->bandwidth);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_BANDWIDTH);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
requested_transport_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_uint32_to_attr(attr, len - pos, (uint32_t) stun->requested_transport);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_REQUESTED_TRANSPORT);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
server_to_bytes(char *buf, size_t pos, size_t len, struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_string_to_attr(attr, len - pos, stun->server);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_SERVER);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
username_to_bytes(char *buf, size_t pos, size_t len,
                  struct stun_message *stun)
{
    attribute_t *attr = (attribute_t *) (buf + pos);
    int ret = copy_string_to_attr(attr, len - pos, stun->username);

    if (ret == -1)
        return pos;
    attr->type = htons(ATTR_USERNAME);
    return pos + ret;
}

//------------------------------------------------------------------------------
static int
header_to_bytes(char *buf, size_t len, struct stun_message *stun,
                message_t ** message)
{
    message_t *msg = (message_t *) buf;

    if (len < STUN_HLEN)
        return -1;
    msg->type = htons(stun->message_type);
    msg->magic = htonl(STUN_MAGIC);
    msg->len = 0;
    memcpy(msg->xact_id, stun->xact_id, STUN_XIDLEN);
    *message = msg;
    return STUN_HLEN;
}

//------------------------------------------------------------------------------
int
stun_to_bytes(char *buf, size_t len, struct stun_message *stun)
{
    size_t pos;
    message_t *message;
    attribute_t *fingerprint = NULL, *messageintegrity = NULL;

    /* Header */
    pos = header_to_bytes(buf, len, stun, &message);
    if (pos == -1)
        return -1;

    /* Username */
    if (stun->username)
        pos = username_to_bytes(buf, pos, len, stun);

    /* Server */
    if (stun->server)
        pos = server_to_bytes(buf, pos, len, stun);

    /* Realm */
    if (stun->realm)
        pos = realm_to_bytes(buf, pos, len, stun);

    /* Data */
    if (stun->data)
        pos = data_to_bytes(buf, pos, len, stun);

    /* Mapped address */
    if (stun->mapped_address)
        pos = mapped_address_to_bytes(buf, pos, len, stun);

    /* Xor Mapped address */
    if (stun->xor_mapped_address)
        pos = xor_mapped_address_to_bytes(buf, pos, len, stun);

    /* Peer address */
    if (stun->peer_address)
        pos = peer_address_to_bytes(buf, pos, len, stun);

    /* Relay address */
    if (stun->relay_address)
        pos = relay_address_address_to_bytes(buf, pos, len, stun);

    /* Requested transport */
    if (stun->requested_transport != -1)
        pos = requested_transport_to_bytes(buf, pos, len, stun);

    /* Channel */
    if (stun->channel != -1)
        pos = channel_to_bytes(buf, pos, len, stun);

    /* Connect Status */
    if (stun->connect_status != -1)
        pos = connect_status_to_bytes(buf, pos, len, stun);

    /* Bandwidth */
    if (stun->bandwidth != 0)
        pos = bandwidth_to_bytes(buf, pos, len, stun);

    /* Lifetime */
    if (stun->lifetime != -1)
        pos = lifetime_to_bytes(buf, pos, len, stun);

    /* Error */
    if (stun->error_code)
        pos = error_to_bytes(buf, pos, len, stun);

    /* Unknown attributes */
    if (stun->unknown_attributes)
        pos = unknown_attributes_to_bytes(buf, pos, len, stun);

    /* Other */
    if (stun->other)
        pos = other_to_bytes(buf, pos, len, stun);

    /* Message integrity */
    if (stun->message_integrity != STUN_ATTR_NOT_PRESENT)
        pos = message_integrity_to_bytes(buf, pos, len, &messageintegrity);

    /* Fingerprint */
    if (stun->fingerprint != STUN_ATTR_NOT_PRESENT)
        pos = fingerprint_to_bytes(buf, pos, len, &fingerprint);

    message->len = htons(pos - STUN_HLEN);

    /* Message integrity calculation */
    if (messageintegrity)
        fix_message_integrity_bytes(buf, messageintegrity, stun);

    /* Fingerprint calculation */
    if (fingerprint)
        fix_fingerprint_bytes(buf, fingerprint);

    return pos;
}

//------------------------------------------------------------------------------
struct stun_message *
stun_from_bytes(char *buf, size_t *len)
{
    struct stun_message *stun;
    attribute_t *attr;
    size_t alen;
    int num_other = 0, err = 0;
    int stop_attr = 0;

    stun = allocate_stun_from_bytes(buf, len);
    if (!stun) return NULL;

    attr = (attribute_t *) (buf + STUN_HLEN);
    while (err == 0 && (STUN_AHLEN + (char *) attr) <= (buf + *len)) {
        alen = ntohs(attr->len);
        if ((STUN_AHLEN + PAD4(alen) + (char *) attr) > (buf + *len)) {
            err = 1;
            break;
        }
        switch ((stop_attr << 16) | ntohs(attr->type)) {
            case (1 << 16 | ATTR_FINGERPRINT):
            case ATTR_FINGERPRINT:
                err = set_fingerprint_from_attr(stun, buf, attr);
                break;

            case ATTR_MESSAGE_INTEGRITY:
                err = set_message_integrity_from_attr(stun, buf, attr);
                stop_attr = 1;
                break;

            case ATTR_USERNAME:
                if (stun->username) s_free(stun->username);
                err = allocate_string_from_attr(&stun->username, attr);
                break;

            case ATTR_SERVER:
                if (stun->server) s_free(stun->server);
                err = allocate_string_from_attr(&stun->server, attr);
                break;

            case ATTR_DATA:
                if (stun->data) s_free(stun->data);
                err = allocate_buf_from_attr(&stun->data, &stun->data_len, attr);
                break;

            case ATTR_REALM:
                if (stun->realm) s_free(stun->realm);
                err = allocate_string_from_attr(&stun->realm, attr);
                break;

            case ATTR_MAPPED_ADDRESS:
                if (stun->mapped_address) s_free(stun->mapped_address);
                err = allocate_sockaddr_from_attr(&stun->mapped_address, &stun->mapped_address_len, attr);
                break;

            case ATTR_XOR_MAPPED_ADDRESS:
                if (stun->xor_mapped_address) s_free(stun->xor_mapped_address);
                err = allocate_sockaddr_from_xor_attr(&stun->xor_mapped_address, &stun->xor_mapped_address_len, attr, (uint8_t *) buf);
                break;

            case ATTR_PEER_ADDRESS:
                if (stun->peer_address) s_free(stun->peer_address);
                err = allocate_sockaddr_from_xor_attr(&stun->peer_address, &stun->peer_address_len, attr, (uint8_t *) buf);
                break;

            case ATTR_RELAY_ADDRESS:
                if (stun->relay_address) s_free(stun->relay_address);
                err = allocate_sockaddr_from_xor_attr(&stun->relay_address, &stun->relay_address_len, attr, (uint8_t *) buf);
                break;

            case ATTR_ERROR_CODE:
                if (stun->error_reason) s_free(stun->error_reason);
                err = allocate_error_from_attr(stun, attr);
                break;

            case ATTR_UNKNOWN_ATTRIBUTES:
                if (stun->unknown_attributes) s_free(stun->unknown_attributes);
                err = allocate_unkown_attrs_from_attr(stun, attr);
                break;

            case ATTR_REQUESTED_TRANSPORT:
                err = copy_uint32_from_attr((uint32_t *)&stun->requested_transport, attr);
                break;

            case ATTR_BANDWIDTH:
                err = copy_uint32_from_attr((uint32_t *)&stun->bandwidth, attr);
                break;

            case ATTR_CONNECT_STATUS:
                err = copy_uint32_from_attr((uint32_t *)&stun->connect_status, attr);
                break;

            case ATTR_CHANNEL_NUMBER:
                err = copy_uint16_from_attr((uint32_t *)&stun->channel, attr);
                break;

            case ATTR_LIFETIME:
                err = copy_uint32_from_attr((uint32_t *)&stun->lifetime, attr);
                break;

            default:
                if (!stop_attr)
                    num_other = reallocate_other_from_attr(stun, num_other, attr);
                break;
        }
        attr = (attribute_t *) (STUN_AHLEN + PAD4(alen) + (char *) attr);
    }
    if (err) {
        stun_free(stun);
        return NULL;
    }

    return stun;
}

//------------------------------------------------------------------------------
const char *
stun_error_reason(int error_code)
{
    switch (error_code) {
        case 300: return "Try Alternate";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 420: return "Unknown Attribute";
        case 430: return "Stale Credentials";
        case 431: return "Integrity Check Failure";
        case 432: return "Missing Username";
        case 433: return "Use TLS";
        case 434: return "Missing Realm";
        case 435: return "Missing Nonce";
        case 436: return "Unknown Username";
        case 437: return "Allocation Mismatch";
        case 438: return "Stale Nonce";
        case 442: return "Unsupported Transport Protocol";
        case 443: return "Invalid IP Address";
        case 444: return "Invalid Port";
        case 445: return "Operation for TCP Only";
        case 446: return "Connection Already Exists";
        case 486: return "Allocation Quota Reached";
        case 500: return "Server Error";
        case 507: return "Insufficient Capacity";
        case 600: return "Global Failure";
        default:  return "Internal error";
    }
}

//------------------------------------------------------------------------------
void
stun_add_user_password(char *username, char *password, int len)
{
    add_auth_key_by_username(password, len, username);
}

//------------------------------------------------------------------------------
void
stun_add_xact_password(char *xact_id, char *password, int len)
{
    add_auth_key_by_xid(password, len, (uint8_t *) xact_id);
}

//------------------------------------------------------------------------------
void
stun_free(struct stun_message *stun)
{
    int i;

    if (stun->error_reason)
        s_free(stun->error_reason);
    if (stun->username)
        s_free(stun->username);
    if (stun->realm)
        s_free(stun->realm);
    if (stun->server)
        s_free(stun->server);
    if (stun->mapped_address)
        s_free(stun->mapped_address);
    if (stun->xor_mapped_address)
        s_free(stun->xor_mapped_address);
    if (stun->alternate_server)
        s_free(stun->alternate_server);
    if (stun->unknown_attributes)
        s_free(stun->unknown_attributes);
    if (stun->peer_address)
        s_free(stun->peer_address);
    if (stun->relay_address)
        s_free(stun->relay_address);
    if (stun->requested_ip_port)
        s_free(stun->requested_ip_port);
    if (stun->data)
        s_free(stun->data);
    if (stun->_password)
        s_free(stun->_password);
    if (stun->other) {
        for (i = 0; stun->other[i].type; i++) {
            if (stun->other[i].value)
                s_free(stun->other[i].value);
        }
        s_free(stun->other);
    }

    s_free(stun);
}

//------------------------------------------------------------------------------
struct stun_message *
stun_new(int type)
{
    struct stun_message *stun;
    int i;

    stun = s_malloc(sizeof(struct stun_message));
    memset(stun, 0, sizeof(struct stun_message));

    // Fields where 0 is a valid value
    stun->channel = -1;
    stun->requested_transport = -1;
    stun->lifetime = -1;
    stun->requested_port_align = -1;
    stun->connect_status = -1;

    stun->message_type = type;
    for (i = 0; i < STUN_XIDLEN; i++)
        stun->xact_id[i] = rand() & 0xFF;
    return stun;
}

