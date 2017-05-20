#include "skynet.h"

#include "duktape.h"

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define MEMORY_WARNING_REPORT (1024 * 1024 * 32)

struct snjs {
    duk_context *ctx;
	struct skynet_context * context;
	size_t mem;
	size_t mem_report;
	size_t mem_limit;
};


static int
init_cb(struct snjs *l, struct skynet_context *context, const char * args, size_t sz) {
    duk_context *ctx = l->ctx;
    l->context = context;
	duk_gc(ctx, 0);

    //duk_push_pointer(ctx, context);
    //duk_put_prop_string(ctx, -1, "skynet_context");

    ////设置查找路径

    ////加载loader脚本

    ////调用loader
    //duk_push_lstring(ctx, args, sz);

    //加载完毕,回收内存
    duk_gc(ctx, 0);
	return 0;
}

static int
launch_cb(struct skynet_context * context, void *ud, int type, int session, uint32_t source , const void * msg, size_t sz) {
	assert(type == 0 && session == 0);
	struct snjs *l = ud;
	skynet_callback(context, NULL, NULL);
	int err = init_cb(l, context, msg, sz);
	if (err) {
		skynet_command(context, "EXIT", NULL);
	}

	return 0;
}

int
snjs_init(struct snjs *l, struct skynet_context *context, const char * args) {
	size_t sz = strlen(args);
	char * tmp = skynet_malloc(sz);
	memcpy(tmp, args, sz);
	skynet_callback(context, l , launch_cb);
	const char * self = skynet_command(context, "REG", NULL);
	uint32_t handle_id = strtoul(self+1, NULL, 16);
	// it must be first message
	skynet_send(context, 0, handle_id, PTYPE_TAG_DONTCOPY,0, tmp, sz);
	return 0;
}

struct snjs *
snjs_create(void) {
	struct snjs * l = skynet_malloc(sizeof(*l));
	memset(l,0,sizeof(*l));
	l->mem_report = MEMORY_WARNING_REPORT;
	l->mem_limit = 0;
	l->ctx = duk_create_heap_default();
	return l;
}

void
snjs_release(struct snjs *l) {
    duk_destroy_heap(l->ctx);
	skynet_free(l);
}

void
snjs_signal(struct snjs *l, int signal) {
	skynet_error(l->context, "recv a signal %d", signal);
	if (signal == 0) {

	} else if (signal == 1) {
		skynet_error(l->context, "Current Memory %.3fK", (float)l->mem / 1024);
	}
}
