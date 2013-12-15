#ifndef __HIVE_H__
#define __HIVE_H__

// Pass constants
#define DROP_FRAME -2
#define PACKET_TO_TAP -1

#include <stdbool.h>

void init_hive();
int pass_for_port(int,short,short,bool);

#endif //__HIVE_H__
