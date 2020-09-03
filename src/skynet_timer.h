#ifndef SKYNET_TIMER_H
#define SKYNET_TIMER_H

#include <stdint.h>


void skynet_updatetime(void);
uint32_t skynet_starttime(void);
uint64_t skynet_thread_time(void);	// for profile, in micro second

void skynet_timer_init(void);

#endif
