#include"skynet.h"

#include<lua.h>
#include<lualib.h>
#include<lauxlib.h>

#include<assert.h>
#include<string.h>
#include<stdlib.h>
#include<stdio.h>

#define MEMORY_WARNING_REPORT 1024*1024*32

struct snlua{
    lua_State*L;
    struct skynet_context*ctx;
    size_t mem;
    size_t mem_report;
    size_t mem_limit;
};



int snlua_init(struct snlua *l, struct skynet_context *ctx, const char * args);
struct snlua *snlua_create(void);
void snlua_release(struct snlua *l);
void snlua_signal(struct snlua *l, int signal);



