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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <event.h>
#include <stdio.h>
#include <assert.h>

#include <stern/stun.h>

#define PORT_STUN     3478
#define REQUEST_SIZE  4192
#define RESPONSE_SIZE  4192

#define SERVER_TIMEOUT 1

static struct sockaddr_in local;
static struct sockaddr_in server;

static struct timeval timeout = {SERVER_TIMEOUT, 0};

const char *test_ok_response(struct stun_message *, struct stun_message *);
const char *test_err_response(struct stun_message *, struct stun_message *);
const char *test_mapped_address(struct stun_message *, struct sockaddr *);
void reconnect();

//------------------------------------------------------------------------------
struct stun_message *
test1_req()
{
    struct stun_message *req = stun_new(STUN_BINDING_REQUEST);
    return req;
}

const char *
test1_resp(struct stun_message *resp, struct stun_message *req)
{
    const char *ret;

    ret = test_ok_response(resp, req);
    if (ret) return ret;

    ret = test_mapped_address(resp, (struct sockaddr *)&local);
    if (ret) return ret;

    return "OK";
}

//------------------------------------------------------------------------------
struct stun_message *
test2_req()
{
    struct stun_message *req = stun_new(STUN_BINDING_REQUEST);
    req->fingerprint = STUN_ATTR_PRESENT;
    return req;
}

const char *
test2_resp(struct stun_message *resp, struct stun_message *req)
{
    const char *ret;

    ret = test_ok_response(resp, req);
    if (ret) return ret;

    ret = test_mapped_address(resp, (struct sockaddr *)&local);
    if (ret) return ret;

    if (resp->fingerprint != STUN_ATTR_PRESENT_AND_VALIDATED)
        return "FAIL (Fingerprint missing or invalid)";

    return "OK";
}

//------------------------------------------------------------------------------
struct stun_message *
test3_req()
{
    struct stun_message *req = stun_new(STUN_BINDING_REQUEST);
    return req;
}

void
test3_polish(char *buf, size_t len)
{
    /* Tamper with Magic */
    buf[4] = 0x00;
}

const char *
test3_resp(struct stun_message *resp, struct stun_message *req)
{
    if (resp)
        return "FAIL (Expect no response)";

    return "OK";
}

//------------------------------------------------------------------------------
struct stun_message *
test4_req()
{
    struct stun_message *req = stun_new(STUN_BINDING_REQUEST);
    req->fingerprint = STUN_ATTR_PRESENT;
    return req;
}

void
test4_polish(char *buf, size_t len)
{
    /* Tamper with fingerprint (last attribute) */
    buf[len-1] = 0x00;
}

const char *
test4_resp(struct stun_message *resp, struct stun_message *req)
{
    const char *ret;

    ret = test_err_response(resp, req);
    if (ret) return ret;

    if (resp->error_code != 400)
        return "FAIL (Wrong error code)";

    return "OK";
}

//------------------------------------------------------------------------------
struct stun_message *
test5_req()
{
    struct stun_message *req = stun_new(STUN_BINDING_REQUEST);
    req->username = strdup("username");
    req->realm = strdup("realm");
    req->message_integrity = STUN_ATTR_PRESENT;
    req->fingerprint = STUN_ATTR_PRESENT;
    return req;
}

const char *
test5_resp(struct stun_message *resp, struct stun_message *req)
{
    const char *ret;

    ret = test_ok_response(resp, req);
    if (ret) return ret;

    ret = test_mapped_address(resp, (struct sockaddr *)&local);
    if (ret) return ret;

    if (resp->message_integrity != STUN_ATTR_PRESENT_AND_VALIDATED)
        return "FAIL (Message integrity missing or invalid)";

    return "OK";
}

//------------------------------------------------------------------------------
struct stun_message *
test6_req()
{
    struct stun_message *req = stun_new(STUN_BINDING_REQUEST);
    req->username = strdup("alice");
    stun_add_password("alice", "wonderland", 10);
    req->message_integrity = STUN_ATTR_PRESENT;
    req->fingerprint = STUN_ATTR_PRESENT;
    return req;
}

const char *
test6_resp(struct stun_message *resp, struct stun_message *req)
{
    const char *ret;

    ret = test_err_response(resp, req);
    if (ret) return ret;

    if (resp->error_code != 431)
        return "FAIL (Wrong error code)";

    return "OK";
}

//------------------------------------------------------------------------------
typedef struct stun_message *(fn_test_request)();
typedef const char *(fn_test_response)(struct stun_message *resp, struct stun_message *req);
typedef void(fn_test_polish)(char *, size_t);
struct {
    const char *desc;
    fn_test_request *request;
    fn_test_polish *polish;
    fn_test_response *response;
} tests[] = {
    {NULL, NULL, NULL, NULL},
    {"Binding request", test1_req, NULL, test1_resp},
    {"Fingerprint", test2_req, NULL, test2_resp},
    {"No magic", test3_req, test3_polish, test3_resp},
    {"Invalid fingerprint", test4_req, test4_polish, test4_resp},
    {"Message integrity", test5_req, NULL, test5_resp},
    {"Unverifyable message integrity", test6_req, NULL, test6_resp},
    {NULL, NULL, NULL, NULL}
};

//------------------------------------------------------------------------------
void sternd_read(int fd, short event, void *args)
{
    static int test = 0;
    struct event *ev_sternd = (struct event *) args;
    char buf[REQUEST_SIZE];
    static struct stun_message *resp, *req;
    int ret;
    size_t len;

    if (tests[test].response && req) {
        if (event != EV_TIMEOUT) {
            ret = read(fd, buf, sizeof(buf));
            if (ret <= 0) return;
            len = ret;
            resp = stun_from_bytes(buf, &len);
        } else {
            resp = NULL;
        }
        printf("%s\n", tests[test].response(resp, req));
        if (req) stun_free(req);
        if (resp) stun_free(resp);

        if (event == EV_TIMEOUT) {
            req = NULL;
            free(ev_sternd);
            reconnect();
            return;
        }
    }

    test++;

    if (tests[test].request) {
        req = tests[test].request();
        ret = stun_to_bytes(buf, sizeof(buf), req);
        if (ret <= 0) return;
        if (tests[test].polish)
            tests[test].polish(buf, ret);
        if (write(fd, buf, ret) != ret)
            return;
        printf("Test %d (%s): ", test, tests[test].desc);
        event_add(ev_sternd, &timeout);
        fflush(stdout);
    }
}

//------------------------------------------------------------------------------
void reconnect()
{
    socklen_t len;
    int sock;
    struct event *ev_sternd = malloc(sizeof(struct event));

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    event_set(ev_sternd, sock, EV_READ, sternd_read, ev_sternd);
    event_add(ev_sternd, &timeout);

    len = sizeof(local);
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        getsockname(sock, (struct sockaddr *)&local, &len);
        sternd_read(sock, EV_READ, ev_sternd);
    }
    getsockname(sock, (struct sockaddr *)&local, &len);
}

//------------------------------------------------------------------------------
int main(int argc, char **argv)
{
    event_init();

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr("127.0.0.1");
    server.sin_port = htons(PORT_STUN);

    reconnect();

    event_dispatch();

    return 0;
}

