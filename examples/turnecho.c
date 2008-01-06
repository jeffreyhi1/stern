#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
#include <errno.h>

#include <stern/turn.h>

int main(int argc, char **argv)
{
    struct sockaddr srv, self, peer;
    struct sockaddr_in *sin;
    char buf[8192];
    unsigned int len;
    int ret;
    turn_socket_t sock;

    /* Connect to the server */
    sin = (struct sockaddr_in *) &srv;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr("127.0.0.1");
    sin->sin_port = htons(8778);

    if ((sock = turn_socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) == NULL)
        error(-1, errno, "turn_socket");

    if (turn_init(sock, &srv, sizeof(srv)) == -1)
        error(-1, errno, "turn_init");

    if (turn_listen(sock, 1) == -1)
        error(-1, errno, "turn_listen");

    sin = (struct sockaddr_in *) &peer;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = inet_addr("127.0.0.1");
    sin->sin_port = 0;

    if (turn_permit(sock, &peer, sizeof(peer)) == -1)
        error(-1, errno, "turn_permit");

    sin = (struct sockaddr_in *) &self;
    len = sizeof(self);
    turn_getsockname(sock, &self, &len);
    fprintf(stderr, "Listening on %s port %d\n",
            inet_ntoa(sin->sin_addr), ntohs(sin->sin_port));

    sin = (struct sockaddr_in *) &peer;
    while (1) {
        ret = turn_recvfrom(sock, buf, 8192, &peer, &len);
        if (ret == -1 && errno != EAGAIN)
            error(-1, errno, "turn_recvfrom");
        else if (ret == 0)
            turn_shutdown(sock, &peer, len);
        else if (ret > 0) {
            if (turn_sendto(sock, buf, ret, &peer, len) == -1)
                error(-1, errno, "turn_sendto");
        }
    }

    return 0;
}
