#include "swarm_client_ipc.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <stdio.h>

static int this_socket = -1;
static bool exit_handler_registered = false;

static void exit_handler() {
    close(this_socket);
}

void sipc_client_set_socket(int sock) {
    if (this_socket >= 0) {
        close(this_socket);
    }
    this_socket = sock;
    if (!exit_handler_registered) {
        atexit(exit_handler);
        exit_handler_registered = true;
    }
}

#define DEFINE_STRUCT_OPERATION(OP, CONST) \
static bool OP##_struct(CONST void *structp, size_t structsize) { \
    size_t bytes_to_process = structsize; \
\
    /* proceed bytewise (int8_t*) */ \
    CONST int8_t *hdrp = structp; \
    while (bytes_to_process > 0) { \
        ssize_t this_run = OP(this_socket, hdrp, bytes_to_process); \
        if (this_run <= 0) { \
            if (errno == EAGAIN || errno == EINTR) { \
                continue; \
            } \
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

int32_t rcv_message_type_sock() {
    struct unxsock_msg rcvd_hdr;
    if (!read_struct(&rcvd_hdr, sizeof(rcvd_hdr))) {
        return -errno;
    }
    if (rcvd_hdr.um_ver > USOCK_VERSION || rcvd_hdr.um_msgid < 0) {
        return -EINVAL;
    }
    return rcvd_hdr.um_msgid;
}

static int send_message_type_sock(int32_t msgid) {
    struct unxsock_msg send_hdr = {
        .um_ver = USOCK_VERSION,
        .um_msgid = msgid,
    };
    if (!write_struct(&send_hdr, sizeof(send_hdr))) {
        return -errno;
    }
    return 0;
}

int request_swarm_getshm() {
    int res;
    if ((res = send_message_type_sock(SWARM_GETSHM))) {
        return res;
    }

    //NOTE: Enable as soon as there is something to send
    //struct getshm_msg to_send;

    return 0;
}

int request_hive_bind_proc(uint32_t protocol, uint32_t port, uint8_t unbind) {
    int res;
    int32_t msg = unbind ? HIVE_UNBIND : HIVE_BIND;
    if ((res = send_message_type_sock(msg))) {
        return res;
    }

    struct bind_msg to_send = {
        .bm_protocol = protocol,
        .bm_resource = port,
    };
    if (!write_struct(&to_send, sizeof(to_send))) {
        return -errno;
    }
    return 0;
}

int rcv_reply_swarm_getshm(
        in_addr_t *ip_addr, uint8_t *mac_addr, char **filename) {
    struct getshm_rep to_rcv = {};
    if (!read_struct(&to_rcv, sizeof(to_rcv))) {
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

    if (!read_struct(rcvd_filename, to_rcv.gr_filename_len)) {
        return -errno;
    }

    *ip_addr = to_rcv.gr_ip_address;
    memcpy(mac_addr, to_rcv.gr_mac_address, MAC_ADDR_LEN);
    *filename = rcvd_filename;
    return 0;
}

int rcv_reply_hive_bind(int32_t *result) {
    struct bind_rep to_rcv = {};
    if (!read_struct(&to_rcv, sizeof(to_rcv))) {
        return -errno;
    }

    *result = to_rcv.br_result;
    return 0;
}

