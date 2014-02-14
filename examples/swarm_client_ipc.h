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
 * Request a connection.
 * \param protocol the protocol for which to reserve the port
 * \param port the resource (port) to reserve for that protocol
 * \returns 0 on success, a negative error code otherwise
 */
int request_hive_bind(uint32_t protocol, uint32_t port);

/**
 * Receives the message header and returns the message type.
 * Always call this function before invoking
 * one of the other \c rcv_XYZ functions.
 * \returns the message type ID or a negative error code
 */
int32_t rcv_message_type_sock(void);

int rcv_reply_swarm_getshm(
        uint8_t **mac_addr, in_addr_t *ip_addr, char **filename);

int rcv_reply_hive_bind(int32_t *result);

#endif //__SWARM_CLIENT_IPC_H__

