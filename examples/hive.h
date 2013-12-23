#ifndef __HIVE_H__
#define __HIVE_H__

// Pass constants
#define DROP_FRAME -2
#define PACKET_TO_ALL -1

#include <stdbool.h>

void init_hive();
void shutdown_hive();
int pass_for_port(int,short,short,bool,bool);
int pass_for_frame(void*,int,bool);
void remove_ports_for_watch(int);

#endif //__HIVE_H__
