#include "swarm_server_ipc.h"
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>

#include <stdio.h>

void __attribute__((__noreturn__))
die(int, const char*);

void errorcb(struct bufferevent *bev, short error, void *ctx) {
    bool finished = false;

    // XXX generalise printf to some in-program error string handler
    if (error & BEV_EVENT_EOF) {
        size_t len = evbuffer_get_length(bufferevent_get_input(bev));
        if (len > 0) {
            printf("Discarding %zu bytes on EOF.\n", len);
        }
    } else if (error & BEV_EVENT_ERROR) {
        printf("Got an error: %s\n",
            evutil_socket_error_to_string(EVUTIL_SOCKET_ERROR()));
        finished = true;
    } else if (error & BEV_EVENT_TIMEOUT) {
        // XXX a production version of swarm should handle
        // client timeouts
    }
    if (finished) {
        die(0, NULL);
    }
}

size_t sipc_struct_size(int32_t msgid) {
    switch (msgid) {
        case SWARM_GETSHM:
            return sizeof(struct getshm_msg);
        case SWARM_GETSHM_REPLY:
            return sizeof(struct getshm_rep);
        case HIVE_BIND:
            return sizeof(struct bind_msg);
        case HIVE_BIND_REPLY:
            return sizeof(struct bind_rep);
        default:
            return 0;
    }
}

void deallocate_bufferevent(struct bufferevent *oldstate) {
    bufferevent_free(oldstate);
}

static void reset_watermark(struct bufferevent *state) {
    // first receive a message header
    bufferevent_setwatermark(
            state, EV_READ, sizeof(struct unxsock_msg), 0);
}

static void set_watermark(struct bufferevent *state, int32_t msgid) {
    // now expect to read a whole struct of the requested type
    bufferevent_setwatermark(state, EV_READ,
            sipc_struct_size(msgid), 0);
}

struct bufferevent *initialise_bufferevent(
        struct event_base *ev_ba, int sock,
        bufferevent_data_cb readcb, void *context_object) {
    struct bufferevent *result = bufferevent_socket_new(
            ev_ba, sock, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(result, readcb, NULL, errorcb, context_object);
    reset_watermark(result);
    bufferevent_enable(result, EV_READ|EV_WRITE);
    return result;
}

static bool read_struct(
        struct bufferevent *state, void *structp, size_t structsize) {
    if (state == NULL) {
        errno = EINVAL;
        return false;
    }
    assert(structsize < SIZE_MAX / 2);

    size_t this_run = bufferevent_read(state, structp, structsize);
    return (this_run == structsize);
}

static bool write_struct(
        struct bufferevent *state, const void* data, size_t bytecount) {
    if (state == NULL) {
        errno = EINVAL;
        return -1;
    }
    assert(bytecount < SIZE_MAX / 2);
    int res = bufferevent_write(state, data, bytecount);
    return (res == 0);
}

int32_t rcv_message_type_evbuf(struct bufferevent *state) {
    struct unxsock_msg rcvd_hdr;
    if (!read_struct(state, &rcvd_hdr, sizeof(rcvd_hdr))) {
        return -errno;
    }
    if (rcvd_hdr.um_ver > USOCK_VERSION || rcvd_hdr.um_msgid < 0) {
        return -EINVAL;
    }
    // now expect to read a whole struct of the requested type
    set_watermark(state, rcvd_hdr.um_msgid);
    return rcvd_hdr.um_msgid;
}

static int send_message_type_evbuf(struct bufferevent *state, int32_t msgid) {
    struct unxsock_msg send_hdr = {
        .um_ver = USOCK_VERSION,
        .um_msgid = msgid,
    };
    if (!write_struct(state, &send_hdr, sizeof(send_hdr))) {
        return -errno;
    }
    return 0;
}

int reply_swarm_getshm(struct bufferevent *state,
        in_addr_t ip_addr, char *filename) {
    int res;
    if ((res = send_message_type_evbuf(state, SWARM_GETSHM_REPLY))) {
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

    if (!write_struct(state, &to_send, sizeof(to_send))) {
        return -errno;
    }

    if (!write_struct(state, filename, to_send.gr_filename_len)) {
        return -errno;
    }
    return 0;
}

int reply_hive_bind(struct bufferevent *state, int32_t result) {
    int res;
    if ((res = send_message_type_evbuf(state, HIVE_BIND_REPLY))) {
        return res;
    }

    struct bind_rep to_send = {
        .br_result = result,
    };
    if (!write_struct(state, &to_send, sizeof(to_send))) {
        return -errno;
    }
    return 0;
}

int rcv_request_swarm_getshm(struct bufferevent *state) {
    /* fill in something as soon as required */
    reset_watermark(state);
    return 0;
}

int rcv_request_hive_bind(struct bufferevent *state,
        uint32_t *protocol, uint32_t *port) {
    struct bind_msg to_rcv = {};
    if (!read_struct(state, &to_rcv, sizeof(to_rcv))) {
        return -errno;
    }
    reset_watermark(state);

    *protocol = to_rcv.bm_protocol;
    *port = to_rcv.bm_resource;
    return 0;
}

