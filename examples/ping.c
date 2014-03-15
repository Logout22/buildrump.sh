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
#include "swarm_client_ipc.h"

static void __attribute__((__noreturn__))
die(int e, const char *msg)
{

    if (msg)
        warnx("%s: %d", msg, e);
    rump_sys_reboot(0, NULL);
    exit(e);
}

int tcpsock = -1;
int unix_socket = -1;

void __attribute__((__noreturn__))
cleanup(int signum) {
	if (unix_socket >= 0) close(unix_socket);
    if (tcpsock >= 0) rump_sys_close(tcpsock);
    die(signum, NULL);
}

#define ERR(...) { \
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

    ERR("Fetching bus name\n");
    unix_socket = socket(AF_UNIX, SOCK_STREAM, 0);
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

    // initialise swarm_ipc
    sipc_client_set_socket(unix_socket);

    ERR("request SHM\n");
    if (request_swarm_getshm()) {
        ERR("Could request SHM\n");
        die(errno, "payload");
    }

    ERR("Fetching answer\n");
    if (rcv_message_type_sock() != SWARM_GETSHM_REPLY) {
        ERR("Incompatible server\n");
        die(errno, "reply");
    }

    char *filename;
    in_addr_t ip_address;
    uint8_t mac_address[MAC_ADDR_LEN];
    if (rcv_reply_swarm_getshm(&ip_address, mac_address, &filename) < 0) {
        ERR("Could not read reply\n");
        die(errno, "read");
    }

    // bus file must be local and stat()-able
    struct stat statstruct = {0};
    if (stat(filename, &statstruct) != 0) {
        free(filename);
        die(errno, "stat");
    }

    ERR("Creating Bus\n");
    rump_pub_shmif_create(filename, mac_address, 0);
    free(filename);

    char const *ip_address_str = inet_ntoa(
            (struct in_addr) { .s_addr = ip_address } );

    ERR("Setting IP address %s\n", ip_address_str);
    rump_pub_netconfig_ipv4_ifaddr(
            "shmif0", ip_address_str, "0.0.0.0");
    rump_pub_netconfig_ifup("shmif0");

    ERR("Creating Socket\n");
    tcpsock = rump_sys_socket(PF_INET, SOCK_STREAM, 0);
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
    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(portnum);
    // listen from all addresses
    memset(&sin.sin_addr, 0, sizeof(sin.sin_addr));

    int res = rump_sys_bind(tcpsock, (struct sockaddr*) &sin, sizeof(sin));
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

    die(0, NULL);
}
