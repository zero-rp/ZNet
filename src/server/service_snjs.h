#include"skynet.h"

#include<lua.h>
#include<lualib.h>
#include<lauxlib.h>

#include<assert.h>
#include<string.h>
#include<stdlib.h>
#include<stdio.h>

#define MEMORY_WARNING_REPORT 1024*1024*32

struct snjs;



int snjs_init(struct snjs *l, struct skynet_context *ctx, const char * args);
struct snjs *snjs_create(void);
void snjs_release(struct snjs *l);
void snjs_signal(struct snjs *l, int signal);



