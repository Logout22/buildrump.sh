#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>

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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rump/rump.h>
#include <rump/netconfig.h>
#include <rump/rump_syscalls.h>
#include <rump/rumpnet_if_pub.h>

char tmpbus_name[] = "busXXXXXX\0";
int tmpbus_hdl = -1;

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
	close(tmpbus_hdl);
	unlink(tmpbus_name);
	die(signum, NULL);
}

#define err(...) { \
	fprintf(stderr, "srv: "); \
	fprintf(stderr, __VA_ARGS__); \
}

int main(int argc, char *argv[]) {
	rump_init();

	struct sigaction sigact = {
		.sa_handler = cleanup
	};
	sigaction(SIGINT, &sigact, NULL);
	sigaction(SIGTERM, &sigact, NULL);

	err("Creating Bus\n");
	assert(*mktemp(tmpbus_name) != 0);
	tmpbus_hdl = creat(tmpbus_name, 0600);
    rump_pub_shmif_create(tmpbus_name, 0);

	char const *ip_address = "10.165.8.1";
	err("Setting IP address %s\n", ip_address);
    rump_pub_netconfig_ipv4_ifaddr("shmif0", ip_address, "255.255.255.0");
	rump_pub_netconfig_ifup("shmif0");

	err("Creating Socket\n");
    int tcpsock = rump_sys_socket(PF_INET, SOCK_STREAM, 0);
    if (tcpsock <= 0) {
        die(errno, "socket");
    }

	short const portnum = 26417;
	err("Binding to port %d\n", portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
	// listen from all addresses
    memset(&sin.sin_addr, 0, sizeof(sin.sin_addr));
    int res = rump_sys_bind(tcpsock, (struct sockaddr*) &sin, sizeof(sin));
    if (res != 0) {
        die(errno, "bind");
    }

	err("Listening (Queue length 120)\n");
    res = rump_sys_listen(tcpsock, 120);
    if (res != 0) {
        die(errno, "listen");
    }

	err("Accepting...\n");
    int rcvsock = rump_sys_accept(tcpsock, NULL, 0);
    if (rcvsock <= 0) {
        die(errno, "accept");
    }

	int const bufsize = 50;
	//err("Reading at most %d bytes\n", bufsize);
	for(;;) {
		char rbuf[bufsize];
		res = rump_sys_read(rcvsock, rbuf, sizeof(rbuf));
		if (res <= 0) {
			die(errno, "read");
		}
		err("rcvd %s\n", rbuf);
		sleep(1);
        char const wbuf[] = "Pong.\0";
        res = rump_sys_write(rcvsock, wbuf, sizeof(wbuf));
        if (res <= 0) {
            die(errno, "write");
        }
	}
    rump_sys_close(rcvsock);

	err("Closing\n");
    rump_sys_close(tcpsock);

	die(0, NULL);
}

