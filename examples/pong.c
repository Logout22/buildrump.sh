#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>
#include <signal.h>

#define ERR(...) { \
    fprintf(stderr, "srv: "); \
    fprintf(stderr, __VA_ARGS__); \
}

int tcpsock = -1;

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{
    if (msg)
        warn("%s: %d", msg, e);
    exit(e);
}

void __attribute__((__noreturn__))
cleanup(int signum) {
    close(tcpsock);
    die(signum, NULL);
}

int main(int argc, char *argv[]) {
    ERR("Creating Socket\n");
    tcpsock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpsock <= 0) {
        die(errno, "socket");
    }

    char const *srv_address = "10.93.48.100";
    short const portnum = 26420;
    ERR("Connecting to %s:%d\n", srv_address, portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
    inet_aton(srv_address, &sin.sin_addr);
    int res = connect(
            tcpsock, (struct sockaddr*) &sin, sizeof(sin));
    if (res != 0) {
        die(errno, "connect");
    }

    struct sigaction sigact = {
        .sa_handler = cleanup
    };
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    int i;
    int const bufsize = 50;
    char rbuf[bufsize + 1];
    rbuf[bufsize] = 0;
    for(i = 0; i < 4; i++) {
        char const wbuf[] = "Ping.\0";
        res = write(tcpsock, wbuf, sizeof(wbuf));
        if (res <= 0) {
            die(errno, "write");
        }
        res = read(tcpsock, rbuf, bufsize);
        if (res <= 0) {
            die(errno, "read");
        }
        ERR("rcvd %s\n", rbuf);
        sleep(1);
    }

    close(tcpsock);


    exit(0);
}
