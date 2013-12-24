#ifndef __HIVE_H__
#define __HIVE_H__

// Pass constants
#define INVALID_BUS -4
#define DROP_FRAME -3
#define FRAME_TO_TAP -2
#define FRAME_TO_ALL -1

#include <stdbool.h>

void init_hive();
void shutdown_hive();
int pass_for_port(int,short,short,bool,bool);
int pass_for_frame(void*,int,bool);
void remove_ports_for_watch(int);

#endif //__HIVE_H__
