#include <stdio.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <stun.h>

int main(int argc, char **argv)
{
    struct sockaddr_in srv, *cli;
    char buf[1024];
    unsigned int sock, len;
    struct stun_message *stun;

    /* Connect to the server */
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = inet_addr("127.0.0.1");
    srv.sin_port = htons(3478);

    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect(sock, (struct sockaddr *)&srv, sizeof(srv)) != 0) {
        perror("connect");
        exit(1);
    }

    /* Send binding request */
    stun = stun_new(STUN_BINDING_REQUEST);
    len = stun_to_bytes(buf, sizeof(buf), stun);
    if (write(sock, buf, len) != len) {
        perror("write");
        exit(1);
    }

    /* Receive binding response */
    len = read(sock, buf, sizeof(buf));
    if (len <= 0 || (stun = stun_from_bytes(buf, &len)) == NULL) {
        perror("read");
        exit(1);
    }

    if (!stun->mapped_address) {
        fprintf(stderr, "stun: Server error");
        exit(1);
    }

    /* Print mapped IP address */
    cli = (struct sockaddr_in *)stun->mapped_address;
    inet_ntop(AF_INET, &cli->sin_addr, buf, sizeof(buf));
    printf("%s\n", buf);

    return 0;
}
