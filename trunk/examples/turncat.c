#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>
#include "turn.h"


int main(int argc, char **argv)
{
    struct sockaddr_in srv, self, peer;
    char buf[1024], sbuf[16];
    unsigned int len;
    int ret;
    turn_socket_t sock;

    /* Connect to the server */
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = inet_addr("127.0.0.1");
    srv.sin_port = htons(8778);

    if ((sock = turn_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == NULL)
        error(-1, errno, "turn_socket");

    if (turn_init(sock, (struct sockaddr *)&srv, sizeof(srv)) == -1)
        error(-1, errno, "turn_init");

    if (turn_listen(sock, 1) == -1)
        error(-1, errno, "turn_listen");

    peer.sin_family = AF_INET;
    peer.sin_addr.s_addr = inet_addr("127.0.0.1");
    peer.sin_port = 0;

    if (turn_permit(sock, (struct sockaddr *)&peer, sizeof(peer)) == -1)
        error(-1, errno, "turn_permit");

    len = sizeof(self);
    turn_getsockname(sock, (struct sockaddr *)&self, &len);
    fprintf(stderr, "Listening on %s port %d\n",
            inet_ntoa(self.sin_addr), ntohs(self.sin_port));

    do {
        if ((ret = turn_recvfrom(sock, buf, sizeof(buf),
                                 (struct sockaddr *) &self, &len)) > 0) {
            snprintf(sbuf, sizeof(sbuf), "%%.%ds", ret);
            printf(sbuf, buf);
        }
    } while (ret > 0 || (ret == -1 && errno == EAGAIN));

    return 0;
}
