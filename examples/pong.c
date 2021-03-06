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
    fprintf(stderr, "clt: "); \
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

    char srv_address[] = "255.255.255.255";
    long req_port = 26420;
    if (argc > 1) {
        strncpy(srv_address, argv[1], strlen(srv_address));
    } else {
        strcpy(srv_address, "10.93.48.100");
    }
    if (argc > 2) {
        req_port = strtol(argv[2], NULL, 0);
        if (req_port < 0 || req_port > 65535) {
            die(26, "invalid port number");
        }
    }
    uint16_t const portnum = (uint16_t) req_port;
    ERR("Connecting to %s:%d\n", srv_address, portnum);
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(portnum);
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
