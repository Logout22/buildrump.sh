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

#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rump/rump.h>
#include <rump/netconfig.h>
#include <rump/rump_syscalls.h>
#include <rump/rumpnet_if_pub.h>

#include "common.h"

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{

	if (msg)
		warnx("%s: %d", msg, e);
	rump_sys_reboot(0, NULL);
	exit(e);
}

void __attribute__((__noreturn__))
cleanup(int signum) {
	die(signum, NULL);
}

#define err(...) { \
	fprintf(stderr, "clt: "); \
	fprintf(stderr, __VA_ARGS__); \
}

int main(int argc, char *argv[]) {
	rump_init();

	struct sigaction sigact = {
		.sa_handler = cleanup
	};
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

    err("Fetching bus name\n");
    int unix_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(unix_socket);

    struct sockaddr_un sockaddr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCK_FN,
    };
    if (connect(unix_socket,
                (struct sockaddr *)&sockaddr,
                sizeof(sockaddr))) {
        die(errno, "connect");
    }

    int const bufsize = 50;
    char rbuf[bufsize + 1];
    rbuf[bufsize] = 0;
    if (read(unix_socket, rbuf, bufsize) <= 0) {
        die(errno, "read");
    }
    close(unix_socket);

    // bus file must be local and stat()-able
    struct stat statstruct = {};
    if (stat(rbuf, &statstruct) != 0) {
        die(errno, "stat");
    }

	err("Creating Bus\n");
    rump_pub_shmif_create(rbuf, 0);

	char const *ip_address = "10.165.8.2";
	err("Setting IP address %s\n", ip_address);
    rump_pub_netconfig_ipv4_ifaddr("shmif0", ip_address, "255.255.255.0");
    rump_pub_netconfig_ifup("shmif0");

	err("Creating Socket\n");
    int tcpsock = rump_sys_socket(PF_INET, SOCK_STREAM, 0);
    if (tcpsock <= 0) {
        die(errno, "socket");
    }

	char const *srv_address = "10.165.8.1";
	short const portnum = 26417;
	err("Connecting to %s:%d\n", srv_address, portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
    inet_aton(srv_address, &sin.sin_addr);
    int res = rump_sys_connect(tcpsock, (struct sockaddr*) &sin, sizeof(sin));
    if (res != 0) {
        die(errno, "connect");
    }

    for(;;) {
        char const wbuf[] = "Ping.\0";
        res = rump_sys_write(tcpsock, wbuf, sizeof(wbuf));
        if (res <= 0) {
            die(errno, "write");
        }
        res = rump_sys_read(tcpsock, rbuf, bufsize);
        if (res <= 0) {
            die(errno, "read");
        }
        err("rcvd %s\n", rbuf);
		sleep(1);
    }

    rump_sys_close(tcpsock);

	die(0, NULL);
}
