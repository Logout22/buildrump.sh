#ifndef __SWARM_SERVER_IPC_H__
#define __SWARM_SERVER_IPC_H__

#include "swarm_ipc.h"

struct event_base;
struct bufferevent;

// NOTE: Do not instantiate directly, use allocators below:
struct sipc_state {
    struct event_base *ev_base = NULL;
    struct bufferevent *bufevent = NULL;
};

struct sipc_state *allocate_sipc_state(struct event_base *ev_ba, int sock);
void deallocate_sipc_state(struct sipc_state *oldstate);

/**
 * Send back information on the shared memory setup to the requester.
 * \param state the state structure describing the target channel
 * \param ip_addr the current IP address of the Swarm system
 * \param filename the file name for access to the shared memory area
 * \returns 0 on success, a negative error code otherwise
 */
int reply_swarm_getshm(
        struct sipc_state *state, in_addr_t ip_addr, char *filename);

/**
 * Send back information on the requested connection.
 * \param state the state structure describing the target channel
 * \param result the return code, indicating success or failure
 *        to reserve the connection
 * \returns 0 on success, a negative error code otherwise
 */
int reply_hive_bind(struct sipc_state *state, int32_t result);

/**
 * Receives the message header using \c state and returns the message type.
 * Always call this function before invoking
 * one of the other \c rcv_XYZ functions.
 * \returns the message type ID or a negative error code
 */
int32_t rcv_message_type_evbuf(struct sipc_state *state);

int rcv_request_swarm_getshm(struct sipc_state *state);

int rcv_request_hive_bind(
        struct sipc_state *state, uint32_t *protocol, uint32_t *port);

#endif //__SWARM_IPC_H__

