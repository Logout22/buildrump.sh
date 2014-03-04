#ifndef __SWARM_CLIENT_IPC_H__
#define __SWARM_CLIENT_IPC_H__

#include "swarm_ipc.h"

void sipc_client_set_socket(int sock);

/**
 * Request a shared memory area for packet transfer.
 * \returns 0 on success, a negative error code otherwise
 */
int request_swarm_getshm(void);

/**
 * Request or close a connection.
 * \param protocol the protocol for the port
 *  (see PROTOCOL_* macros in swarm_ipc.h)
 * \param port the resource (port) in question
 * \param unbind \c true for an unbind request, \c false for a bind request
 * \returns 0 on success, a negative error code otherwise
 */
int request_hive_bind_proc(uint32_t protocol, uint32_t port, bool unbind);

/**
 * Receives the message header and returns the message type.
 * Always call this function before invoking
 * one of the other \c rcv_XYZ functions.
 * \returns the message type ID or a negative error code
 */
int32_t rcv_message_type_sock(void);

int rcv_reply_swarm_getshm(in_addr_t *ip_addr, char **filename);

int rcv_reply_hive_bind(int32_t *result);

#endif //__SWARM_CLIENT_IPC_H__

