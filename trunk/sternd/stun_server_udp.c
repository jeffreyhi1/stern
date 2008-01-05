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
#include <sys/time.h>
#include <unistd.h>
#include <event.h>

#include <common.h>

#define PORT_STUN     3478
#define BUFFER_MAX    8192

struct server {
    int sock;
    struct sockaddr_in addr;
    struct event ev_recv;
};

//------------------------------------------------------------------------------
static void
on_recv(int fd, short ev, void *arg)
{
    struct server *server = (struct server *) arg;
    struct stun_message *request, *response;
    struct sockaddr addr;
    socklen_t len = sizeof(addr);
    char buf[BUFFER_MAX];
    int ret;

    /* Receive message */
    ret = recvfrom(fd, buf, sizeof(buf), 0, &addr, &len);
    if (ret <= 0) return;

    /* Process request */
    len = ret;
    request = stun_from_bytes(buf, &len);
    if (request) {
        response = stun_respond_to(request, &addr);
        if (response) {
            ret = stun_to_bytes(buf, sizeof(buf), response);
            if (ret > 0)
                sendto(fd, buf, ret, 0, &addr, len);
            stun_free(response);
        }
        stun_free(request);
    }
}

//------------------------------------------------------------------------------
void *
stun_udp_init()
{
    struct server *server;
    static int one = 1;

    server = (struct server *) s_malloc(sizeof(struct server));

    server->addr.sin_family = AF_INET;
    server->addr.sin_addr.s_addr = INADDR_ANY;
    server->addr.sin_port = htons(PORT_STUN);

    server->sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    setsockopt(server->sock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(server->sock, (struct sockaddr *)&server->addr, sizeof(server->addr))) {
        close(server->sock);
        s_free(server);
        return NULL;
    }

    event_set(&server->ev_recv, server->sock, EV_READ|EV_PERSIST, on_recv, server);
    event_add(&server->ev_recv, NULL);

    return server;
}

