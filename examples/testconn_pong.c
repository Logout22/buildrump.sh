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
#include <time.h>

#define ERR(...) { \
    fprintf(stderr, "clt: "); \
    fprintf(stderr, __VA_ARGS__); \
}

int tcpsock = -1;
long roundtrips = 0;

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
    ERR("Roundtrips: %ld\n", roundtrips);
    die(signum, NULL);
}

int main(int argc, char *argv[]) {
    ERR("Creating Socket\n");

    char const *srv_address = "10.93.49.100";
    long req_port = 26420;
    if (argc > 1) {
        req_port = strtol(argv[1], NULL, 0);
        if (req_port < 0 || req_port > 65535) {
            die(26, "invalid port number");
        }
    }
    uint16_t const portnum = (uint16_t) req_port;
    ERR("Connecting to %s:%d\n", srv_address, portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
    inet_aton(srv_address, &sin.sin_addr);

    struct sigaction sigact = {
        .sa_handler = cleanup
    };
    sigaction(SIGINT, &sigact, NULL);
    sigaction(SIGTERM, &sigact, NULL);

    struct timespec pause_between = {
        .tv_sec = 0,
        .tv_nsec = 100*1000,
    };
    while(1) {
        tcpsock = socket(AF_INET, SOCK_STREAM, 0);
        if (tcpsock <= 0) {
            die(errno, "socket");
        }

        int res = connect(
                tcpsock, (struct sockaddr*) &sin, sizeof(sin));
        if (res != 0) {
            die(errno, "connect");
        }

        nanosleep(&pause_between, NULL);

        close(tcpsock);
        roundtrips++;
    }

    exit(0);
}
