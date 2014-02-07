#ifndef __SWARM_IPC_H__
#define __SWARM_IPC_H__

#include <inttypes.h>
#include <arpa/inet.h>

#define USOCK_VERSION 1

#define SWARM_GETSHM 1
#define SWARM_GETSHM_REPLY 3
#define HIVE_BIND 2
#define HIVE_BIND_REPLY 4

#define PROTOCOL_TCP 0
#define PROTOCOL_UDP 1

#define HIVE_SUCCESS 0
#define HIVE_FAILURE -1

struct unxsock_msg {
    uint32_t um_ver;
    int32_t um_msgid;
};

struct getshm_msg {
    // nothing to send so far
};

struct getshm_rep {
    in_addr_t gr_ip_address;
    uint32_t gr_filename_len;
    /*
     * The protocol requires the sender to supply
     * gr_filename_len bytes of data for the client
     * following this structure (Version 1).
     */
};

struct bind_msg {
    uint32_t bm_protocol;
    uint32_t bm_resource;
};

struct bind_rep {
    int32_t br_result;
};

#endif //__SWARM_IPC_H__

