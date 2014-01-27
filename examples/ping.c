#include <sys/types.h>
#include <sys/cdefs.h>
#include <sys/stat.h>

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

#include <inttypes.h>
#include <rump/rump.h>
#include <rump/netconfig.h>
#include <rump/rump_syscalls.h>
#include <rump/rumpnet_if_pub.h>

#include "swarm.h"
#include "swarm_ipc.h"

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{

    if (msg)
        warnx("%s: %d", msg, e);
    rump_sys_reboot(0, NULL);
    exit(e);
}

int tcpsock = -1;

void __attribute__((__noreturn__))
cleanup(int signum) {
    if (tcpsock >= 0) rump_sys_close(tcpsock);
    die(signum, NULL);
}

#define ERR(...) { \
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

    ERR("Fetching bus name\n");
    int unix_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (!unix_socket) {
        ERR("socket() failed");
        die(errno, "socket");
    }

    struct sockaddr_un sockaddr = {
        .sun_family = AF_UNIX,
        .sun_path = SOCK_FN,
    };
    if (connect(unix_socket,
                (struct sockaddr *)&sockaddr,
                sizeof(sockaddr))) {
        die(errno, "connect");
    }

    if (request_swarm_getshm(unix_socket)) {
        ERR("Could request SHM\n");
        die(errno, "payload");
    }

    if (rcv_message_type(unix_socket) != SWARM_GETSHM_REPLY) {
        ERR("Incompatible server\n");
        die(errno, "reply");
    }

    char *filename;
    in_addr_t ip_address;
    if (rcv_reply_swarm_getshm(unix_socket, &ip_address, &filename) < 0) {
        ERR("Could not read reply\n");
        die(errno, "read");
    }

    // bus file must be local and stat()-able
    struct stat statstruct = {};
    if (stat(filename, &statstruct) != 0) {
        free(filename);
        die(errno, "stat");
    }

    ERR("Creating Bus\n");
    rump_pub_shmif_create(filename, 0);
    free(filename);

    char const *ip_address_str = inet_ntoa(
            (struct in_addr) { .s_addr = ip_address } );

    ERR("Setting IP address %s\n", ip_address_str);
    rump_pub_netconfig_ipv4_ifaddr(
            "shmif0", ip_address_str, "255.255.255.0");
    rump_pub_netconfig_ifup("shmif0");

    ERR("Creating Socket\n");
    tcpsock = rump_sys_socket(PF_INET, SOCK_STREAM, 0);
    if (tcpsock <= 0) {
        die(errno, "socket");
    }

    short const portnum = 26420;
    ERR("Binding to port %d\n", portnum);
    struct sockaddr_in sin = {
        .sin_family = AF_INET,
        .sin_port = htons(portnum),
    };
    // listen from all addresses
    memset(&sin.sin_addr, 0, sizeof(sin.sin_addr));

    //TODO remove ASA implicit bind works
    int res;
    if ((res = request_hive_bind(unix_socket, PROTOCOL_TCP, portnum))) {
        die(-res, "explicit bind");
    }

    res = rump_sys_bind(tcpsock, (struct sockaddr*) &sin, sizeof(sin));
    if (res != 0) {
        die(errno, "bind");
    }

    ERR("Listening (Queue length 120)\n");
    res = rump_sys_listen(tcpsock, 120);
    if (res != 0) {
        die(errno, "listen");
    }

    for(;;) {
        ERR("Accepting...\n");
        int rcvsock = rump_sys_accept(tcpsock, NULL, 0);
        if (rcvsock <= 0) {
            die(errno, "accept");
        }

        int const bufsize = 50;
        char rbuf[bufsize + 1];
        rbuf[bufsize] = 0;
        //ERR("Reading at most %d bytes\n", bufsize);
        //int i;
        while((res = rump_sys_read(rcvsock, rbuf, bufsize)) > 0) {
            /*
            if (res <= 0) {
                die(errno, "read");
            }
            */
            ERR("rcvd %s\n", rbuf);
            sleep(1);
            char const wbuf[] = "Pong.\0";
            res = rump_sys_write(rcvsock, wbuf, sizeof(wbuf));
            if (res <= 0) {
                die(errno, "write");
            }
        }
        rump_sys_close(rcvsock);
    }

    ERR("Closing\n");
    rump_sys_close(tcpsock);

    close(unix_socket);

    die(0, NULL);
}
