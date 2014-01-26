#include "swarm_ipc.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

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

#define DEFINE_STRUCT_OPERATION(OP, CONST) \
static bool OP##_struct(int fd, CONST void *structp, size_t structsize) { \
    size_t bytes_to_process = structsize; \
\
    /* proceed bytewise (int8_t*) */ \
    CONST int8_t *hdrp = structp; \
    while (bytes_to_process > 0) { \
        ssize_t this_run = OP(fd, hdrp, bytes_to_process); \
        if (this_run <= 0) { \
            return false; \
        } \
\
        bytes_to_process -= this_run; \
        hdrp += this_run; \
    } \
    /* no negative values (overreads) */ \
    assert(bytes_to_process == 0); \
\
    return true; \
}

DEFINE_STRUCT_OPERATION(read,);
DEFINE_STRUCT_OPERATION(write, const);

int32_t rcv_message_type(int sock) {
    struct unxsock_msg rcvd_hdr;
    if (!read_struct(sock, &rcvd_hdr, sizeof(rcvd_hdr)) ||
            rcvd_hdr.um_ver > USOCK_VERSION) {
        return -errno;
    }
    if (rcvd_hdr.um_msgid < 0) {
        return -EINVAL;
    }
    return rcvd_hdr.um_msgid;
}

static int send_message_type(int sock, int32_t msgid) {
    struct unxsock_msg send_hdr = {
        .um_ver = USOCK_VERSION,
        .um_msgid = msgid,
    };
    if (!write_struct(sock, &send_hdr, sizeof(send_hdr))) {
        return -errno;
    }
    return 0;
}

int request_swarm_getshm(int sock) {
    int res;
    if ((res = send_message_type(sock, SWARM_GETSHM))) {
        return res;
    }

    //NOTE: Enable as soon as there is something to send
    //struct getshm_msg to_send;

    return 0;
}

int reply_swarm_getshm(int sock, in_addr_t ip_addr, char *filename) {
    int res;
    if ((res = send_message_type(sock, SWARM_GETSHM_REPLY))) {
        return res;
    }

    assert(sizeof(size_t) >= sizeof(uint32_t));

    size_t retr_len = strlen(filename);
    if (retr_len >= UINT32_MAX) {
        return -EINVAL;
    }
    struct getshm_rep to_send = {
        .gr_ip_address = ip_addr,
        .gr_filename_len = (uint32_t) retr_len
    };

    if (!write_struct(sock, &to_send, sizeof(to_send))) {
        return -errno;
    }

    if (!write_struct(sock, filename, to_send.gr_filename_len)) {
        return -errno;
    }
    return 0;
}

int request_hive_bind(int sock, uint32_t protocol, uint32_t port) {
    int res;
    if ((res = send_message_type(sock, HIVE_BIND))) {
        return res;
    }

    struct bind_msg to_send = {
        .bm_protocol = protocol,
        .bm_resource = port,
    };
    if (!write_struct(sock, &to_send, sizeof(to_send))) {
        return -errno;
    }
    return 0;
}

int reply_hive_bind(int sock, int32_t result) {
    int res;
    if ((res = send_message_type(sock, HIVE_BIND_REPLY))) {
        return res;
    }

    struct bind_rep to_send = {
        .br_result = result,
    };
    if (!write_struct(sock, &to_send, sizeof(to_send))) {
        return -errno;
    }
    return 0;
}

int rcv_request_swarm_getshm(int sock) {
    /* fill in something as soon as required */
    return 0;
}

int rcv_reply_swarm_getshm(int sock, in_addr_t *ip_addr, char **filename) {
    struct getshm_rep to_rcv = {};
    if (!read_struct(sock, &to_rcv, sizeof(to_rcv))) {
        return -errno;
    }

    assert(sizeof(size_t) >= sizeof(uint32_t));
    size_t rcvd_filename_size = to_rcv.gr_filename_len + 1;
    char *rcvd_filename = malloc(rcvd_filename_size);
    if (!rcvd_filename) {
        // this error code means something like "computer on fire"
        return -1;
    }
    memset(rcvd_filename, 0, rcvd_filename_size);

    if (!read_struct(sock, rcvd_filename, to_rcv.gr_filename_len)) {
        return -errno;
    }

    *ip_addr = to_rcv.gr_ip_address;
    *filename = rcvd_filename;
    return 0;
}

int rcv_request_hive_bind(int sock, uint32_t *protocol, uint32_t *port) {
    struct bind_msg to_rcv = {};
    if (!read_struct(sock, &to_rcv, sizeof(to_rcv))) {
        return -errno;
    }

    *protocol = to_rcv.bm_protocol;
    *port = to_rcv.bm_resource;
    return 0;
}

int rcv_reply_hive_bind(int sock, int32_t *result) {
    struct bind_rep to_rcv = {};
    if (!read_struct(sock, &to_rcv, sizeof(to_rcv))) {
        return -errno;
    }

    *result = to_rcv.br_result;
    return 0;
}
