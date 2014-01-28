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

/**
 * Request a shared memory area for packet transfer.
 * \param sock the UNIX socket to send the request to
 * \returns 0 on success, a negative error code otherwise
 */
int request_swarm_getshm(int sock);
/**
 * Send back information on the shared memory setup to the requester.
 * \param sock the UNIX socket to send the reply to
 * \param ip_addr the current IP address of the Swarm system
 * \param filename the file name for access to the shared memory area
 * \returns 0 on success, a negative error code otherwise
 */
int reply_swarm_getshm(int sock, in_addr_t ip_addr, char *filename);
/**
 * Request a connection.
 * \param sock the UNIX socket to send the request to
 * \param protocol the protocol for which to reserve the port
 * \param port the resource (port) to reserve for that protocol
 * \returns 0 on success, a negative error code otherwise
 */
int request_hive_bind(int sock, uint32_t protocol, uint32_t port);
/**
 * Send back information on the requested connection.
 * \param sock the UNIX socket to send the reply to
 * \param result the return code, indicating success or failure
 *        to reserve the connection
 * \returns 0 on success, a negative error code otherwise
 */
int reply_hive_bind(int sock, int32_t result);

/**
 * Receives the message header from \c sock and returns the message type.
 * Always call this function before invoking
 * one of the other \c rcv_XYZ functions.
 * \returns the message type ID or a negative error code
 */
int32_t rcv_message_type(int sock);
int rcv_request_swarm_getshm(int sock);
int rcv_reply_swarm_getshm(int sock, in_addr_t *ip_addr, char **filename);
int rcv_request_hive_bind(int sock, uint32_t *protocol, uint32_t *port);
int rcv_reply_hive_bind(int sock, int32_t *result);

#endif //__SWARM_IPC_H__

