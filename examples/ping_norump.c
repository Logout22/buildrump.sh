#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/stat.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stropts.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <inttypes.h>

#include "benchmarks.h"

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{

	if (msg)
		warnx("%s: %d", msg, e);
	exit(e);
}

void __attribute__((__noreturn__))
cleanup(int signum) {
	die(signum, NULL);
}

#define ERR(...) { \
	fprintf(stderr, "clt: "); \
	fprintf(stderr, __VA_ARGS__); \
}

int main(int argc, char *argv[]) {
	struct sigaction sigact = {
		.sa_handler = cleanup
	};
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

	ERR("Creating Socket\n");
    int tcpsock = socket(PF_INET, SOCK_STREAM, 0);
    if (tcpsock <= 0) {
        die(errno, "socket");
    }

	char const *srv_address = "10.93.48.2";
	short const portnum = 26417;
	ERR("Connecting to %s:%d\n", srv_address, portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
    inet_aton(srv_address, &sin.sin_addr);
    int res = connect(tcpsock, (struct sockaddr*) &sin, sizeof(sin));
    if (res != 0) {
        die(errno, "connect");
    }

    int i;
    int const bufsize = 50;
    char rbuf[bufsize + 1];
    rbuf[bufsize] = 0;
	for(i = 0; i < BM_COUNT; i++) {
        char const wbuf[] = STR_PING;
        res = write(tcpsock, wbuf, sizeof(wbuf));
        if (res <= 0) {
            die(errno, "write");
        }
        res = read(tcpsock, rbuf, bufsize);
        if (res <= 0 || strcmp(rbuf, STR_PONG) != 0) {
            die(errno, "read");
        }
        /*ERR("rcvd %s\n", rbuf);
		sleep(1);*/
        runs++;
    }

	ERR("Closing after %d runs\n", runs);
    close(tcpsock);

	die(0, NULL);
}
