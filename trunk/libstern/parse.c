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

#define DEFAULT_USERNAME    "username"
#define DEFAULT_REALM       "realm"
#define DEFAULT_PASSWORD    (\
    "\x7c\xac\xc1\x13"       \
    "\xe6\x1f\xca\x28"       \
    "\x91\x72\x07\x4f"       \
    "\x40\x03\x90\x95"       \
)                               /* MD5("alice:realm:password") */
#define DEFAULT_PASSWORD_LEN 16

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
        if (passwords[i].expire < now || i == live_passwords)
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
    pass->expire = time(NULL) + CACHE_TIMEOUT;

    if (num_passwords > CACHE_FULL)
        reap_auth_keys();
}

//------------------------------------------------------------------------------
static int
matches_xid(uint8_t *xida, uint8_t *xidb)
{
    return memcmp(xida, xidb, STUN_XIDLEN) == 0;
}

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
    /* Use password used to validate request, if any */
    if (get_auth_key_from_message(key, len, stun) == 0)
        return 0;

    /* Check cache */
    if (get_auth_key_from_cache(key, len, stun) == 0)
        return 0;

    /* Try default password for testing purposes */
    if (get_auth_key_default(key, len, stun) == 0)
        return 0;

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
static void
set_fingerprint_from_attr(struct stun_message *stun, char *buf,
                          attribute_t * attr)
{
    uint32_t crc;

    if (ntohs(attr->len) != 4)
        return;
    stun->fingerprint = STUN_ATTR_PRESENT_AND_VALIDATED;
    crc = crc32(0, (uint8_t *) buf, ((char *) attr) - buf);
    crc ^= STUN_FINGERPRINT_MAGIC;
    if (crc != ntohl(attr->v.u32))
        stun->fingerprint = STUN_ATTR_PRESENT_BUT_INVALID;
}

//------------------------------------------------------------------------------
static void
set_message_integrity_from_attr(struct stun_message *stun, char *buf,
                                attribute_t * attr)
{
    uint8_t hmac[20];
    unsigned int hmac_len = sizeof(hmac);
    char *key;
    int len;

    if (ntohs(attr->len) != hmac_len)
        return;
    stun->message_integrity = STUN_ATTR_PRESENT;
    if (get_auth_key(&key, &len, stun) == -1)
        return;
    HMAC(EVP_sha1(), key, len, (uint8_t *) buf, ((char *) attr) - buf,
         hmac, &hmac_len);
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
allocate_other_from_attr(struct stun_message *stun, int num_other,
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
    stun_attr->value = s_malloc(stun_attr->len + 1);
    memcpy(stun_attr->value, attr->v.bytes, stun_attr->len);
    ((uint8_t *) stun_attr->value)[stun_attr->len] = '\0';

    /* end marker type=0 */
    stun_attr = &stun->other[num_other];
    stun_attr->type = 0;
    stun_attr->len = 0;
    stun_attr->value = NULL;
    return num_other;
}

//------------------------------------------------------------------------------
static void
allocate_string_from_attr(char **str, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);
    char *buf;

    if (alen == 0)
        return;
    buf = s_malloc(alen + 1);
    memcpy(buf, attr->v.bytes, alen);
    buf[alen] = '\0';
    *str = buf;
}

//------------------------------------------------------------------------------
static void
copy_uint32_from_attr(unsigned int *val, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);

    if (alen != 4)
        return;
    *val = ntohl(attr->v.u32);
}

//------------------------------------------------------------------------------
static void
copy_uint16_from_attr(unsigned int *val, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);

    if (alen != 4)
        return;
    *val = ntohs(attr->v.u16.num[0]);
}

//------------------------------------------------------------------------------
static void
allocate_error_from_attr(struct stun_message *stun, attribute_t * attr)
{
    size_t alen = ntohs(attr->len);
    char *buf;

    if (alen < 4)
        return;
    stun->error_code = attr->v.error.class * 100 + attr->v.error.number;
    if (alen == 4)
        return;
    buf = s_malloc(alen - 4 + 1);
    memcpy(buf, attr->v.error.reason, alen - 4);
    buf[alen] = '\0';
    stun->error_reason = buf;
}

//------------------------------------------------------------------------------
static void
allocate_sockaddr_from_attr(struct sockaddr **addr, size_t *addrlen, attribute_t * attr)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    int i;

    if (attr->v.addr.family == STUN_ADDR_IP4) {
        if (ntohs(attr->len) != 8)
            return;
        sin = s_malloc(sizeof(struct sockaddr_in));
        sin->sin_family = AF_INET;
        sin->sin_addr.s_addr = attr->v.addr.ip.addr4;
        sin->sin_port = attr->v.addr.port;
        *addr = (struct sockaddr *) sin;
        *addrlen = sizeof(struct sockaddr_in);
    } else if (attr->v.addr.family == STUN_ADDR_IP6) {
        if (ntohs(attr->len) != 20)
            return;
        sin6 = s_malloc(sizeof(struct sockaddr_in6));
        sin6->sin6_family = AF_INET;
        for (i = 0; i < 16; i++)
            sin6->sin6_addr.s6_addr[i] = attr->v.addr.ip.addr6[i];
        sin6->sin6_port = attr->v.addr.port;
        *addr = (struct sockaddr *) sin6;
        *addrlen = sizeof(struct sockaddr_in6);
    }
}

//------------------------------------------------------------------------------
static void
allocate_sockaddr_from_xor_attr(struct sockaddr **addr, size_t *addrlen, attribute_t * attr, uint8_t *buf)
{
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    int i;

    allocate_sockaddr_from_attr(addr, addrlen, attr);
    if (!*addr) return;

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
    int i;

    if (get_auth_key(&key, &len, stun) == -1)
        return;
    HMAC(EVP_sha1(), key, len, (uint8_t *) buf,
         ((char *) message_integrity) - buf, hmac, &hmac_len);
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
    attr->type = htons(ATTR_UNKNOWN_ATTRIBUTES);
    attr->len = htons(PAD4(2 * i));
    return pos + STUN_AHLEN + PAD4(2 * i);
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
    if (stun->connect_status != 0)
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
    int num_other = 0;

    stun = allocate_stun_from_bytes(buf, len);

    attr = (attribute_t *) (buf + STUN_HLEN);
    while ((STUN_AHLEN + (char *) attr) < (buf + *len)) {
        alen = ntohs(attr->len);
        if ((STUN_AHLEN + PAD4(alen) + (char *) attr) > (buf + *len))
            break;
        switch (ntohs(attr->type)) {
            case ATTR_FINGERPRINT:
                set_fingerprint_from_attr(stun, buf, attr);
                break;

            case ATTR_MESSAGE_INTEGRITY:
                set_message_integrity_from_attr(stun, buf, attr);
                break;

            case ATTR_USERNAME:
                allocate_string_from_attr(&stun->username, attr);
                break;

            case ATTR_SERVER:
                allocate_string_from_attr(&stun->server, attr);
                break;

            case ATTR_REALM:
                allocate_string_from_attr(&stun->realm, attr);
                break;

            case ATTR_MAPPED_ADDRESS:
                allocate_sockaddr_from_attr(&stun->mapped_address, &stun->mapped_address_len, attr);
                break;

            case ATTR_XOR_MAPPED_ADDRESS:
                allocate_sockaddr_from_xor_attr(&stun->xor_mapped_address, &stun->xor_mapped_address_len, attr, (uint8_t *) buf);
                break;

            case ATTR_PEER_ADDRESS:
                allocate_sockaddr_from_xor_attr(&stun->peer_address, &stun->peer_address_len, attr, (uint8_t *) buf);
                break;

            case ATTR_RELAY_ADDRESS:
                allocate_sockaddr_from_xor_attr(&stun->relay_address, &stun->relay_address_len, attr, (uint8_t *) buf);
                break;

            case ATTR_ERROR_CODE:
                allocate_error_from_attr(stun, attr);
                break;

            case ATTR_REQUESTED_TRANSPORT:
                copy_uint32_from_attr((uint32_t *)&stun->requested_transport, attr);
                break;

            case ATTR_BANDWIDTH:
                copy_uint32_from_attr((uint32_t *)&stun->bandwidth, attr);
                break;

            case ATTR_CONNECT_STATUS:
                copy_uint32_from_attr((uint32_t *)&stun->connect_status, attr);
                break;

            case ATTR_CHANNEL_NUMBER:
                copy_uint16_from_attr((uint32_t *)&stun->channel, attr);
                break;

            case ATTR_LIFETIME:
                copy_uint32_from_attr((uint32_t *)&stun->lifetime, attr);
                break;

            default:
                num_other = allocate_other_from_attr(stun, num_other, attr);
                break;
        }
        attr = (attribute_t *) (STUN_AHLEN + PAD4(alen) + (char *) attr);
    }

    return stun;
}

//------------------------------------------------------------------------------
void
stun_add_password(char *username, char *password, int len)
{
    add_auth_key_by_username(password, len, username);
}
