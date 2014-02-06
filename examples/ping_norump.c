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

    long req_port = 26420;
    if (argc > 1) {
        req_port = strtol(argv[1], NULL, 0);
        if (req_port < 0 || req_port > 65535) {
            die(26, "invalid port number");
        }
    }
    uint16_t const portnum = (uint16_t) req_port;
    ERR("Binding to port %d\n", portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
    // listen from all addresses
    memset(&sin.sin_addr, 0, sizeof(sin.sin_addr));

    int res = bind(tcpsock, (struct sockaddr*) &sin, sizeof(sin));
    if (res != 0) {
        die(errno, "bind");
    }

    ERR("Listening (Queue length 120)\n");
    res = listen(tcpsock, 120);
    if (res != 0) {
        die(errno, "listen");
    }

    for(;;) {
        ERR("Accepting...\n");
        int rcvsock = accept(tcpsock, NULL, 0);
        if (rcvsock <= 0) {
            die(errno, "accept");
        }

        int const bufsize = 50;
        char rbuf[bufsize + 1];
        rbuf[bufsize] = 0;
        //ERR("Reading at most %d bytes\n", bufsize);
        //int i;
        while((res = read(rcvsock, rbuf, bufsize)) > 0) {
            /*
            if (res <= 0) {
                die(errno, "read");
            }
            */
            ERR("rcvd %s\n", rbuf);
            sleep(1);
            char const wbuf[] = "Pong.\0";
            res = write(rcvsock, wbuf, sizeof(wbuf));
            if (res <= 0) {
                die(errno, "write");
            }
        }
        close(rcvsock);
    }

    ERR("Closing\n");

    exit(0);
}

