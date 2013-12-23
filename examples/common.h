#define SOCK_FN "testsock"
#define SWARM_GETSHM 1
#define HIVE_BIND 2

#define USOCK_VERSION 1

#define IP_ADDRESS "10.93.48.100"

struct unxsock_msg {
    int um_ver;
    int um_msgid;
};

struct getshm_msg {
    struct unxsock_msg gs_header;
    int gs_pid;
};

//defining some BSD specific macros
#include <stddef.h>

#include <linux/if_ether.h>
#ifndef ETHER_HDR_LEN
    #define ETHER_HDR_LEN ETH_HLEN
#endif
#ifndef ETHERMTU
    #define ETHERMTU ETH_DATA_LEN
#endif
