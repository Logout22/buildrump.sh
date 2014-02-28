#ifndef __HIVE_H__
#define __HIVE_H__

#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>

// Pass constants
#define INVALID_BUS -4
#define DROP_FRAME -3
#define FRAME_TO_TAP -2
#define FRAME_TO_ALL -1

#define MAC_LEN 6
#define IP_LEN 4

#define CPYIP(A, B) memcpy((A), (B), 4)
#define CPYMAC(A, B) memcpy((A), (B), 6)
#define EQIP(A, B) (memcmp((A), (B), 4) == 0)
#define EQMAC(A, B) (memcmp((A), (B), 6) == 0)

struct bufferevent;

void init_hive(in_addr_t ip_address, uint8_t *cur_mac_address);
void shutdown_hive();
void register_connection(struct bufferevent*, int, uint32_t, uint32_t);
int pass_for_frame(void*,uint32_t,int,bool);
void remove_ports_for_watch(int);

#endif //__HIVE_H__
