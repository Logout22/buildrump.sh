#define SOCK_FN "testsock"
#define SWARM_GETSHM 1
#define HIVE_BIND 2

//defining some BSD specific macros
#include <stddef.h>

#include <linux/if_ether.h>
#ifndef ETHER_HDR_LEN
    #define ETHER_HDR_LEN ETH_HLEN
#endif
#ifndef ETHERMTU
    #define ETHERMTU ETH_DATA_LEN
#endif
