#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <err.h>

#include "benchmarks.h"

#define ERR(...) { \
	fprintf(stderr, "srv: "); \
	fprintf(stderr, __VA_ARGS__); \
}

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{
	if (msg)
		warn("%s: %d", msg, e);
	exit(e);
}

int main(int argc, char *argv[]) {
	ERR("Creating Socket\n");
    int tcpsock = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpsock <= 0) {
        die(errno, "socket");
    }

	short const portnum = 26417;
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

	ERR("Accepting...\n");
    int rcvsock = accept(tcpsock, NULL, 0);
    if (rcvsock <= 0) {
        die(errno, "accept");
    }

	int const bufsize = 50;
    char rbuf[bufsize + 1];
    rbuf[bufsize] = 0;
	//ERR("Reading at most %d bytes\n", bufsize);
	for(int i = 0; i < BM_COUNT; i++) {
		res = read(rcvsock, rbuf, bufsize);
		if (res <= 0  || strcmp(rbuf, STR_PING) != 0) {
			die(errno, "read");
		}
		/*ERR("rcvd %s\n", rbuf);
		sleep(1);*/
        char const wbuf[] = STR_PONG;
        res = write(rcvsock, wbuf, sizeof(wbuf));
        if (res <= 0) {
            die(errno, "write");
        }
        runs++;
	}
    close(rcvsock);

	ERR("Closing after %d runs\n", runs);
    close(tcpsock);
}
