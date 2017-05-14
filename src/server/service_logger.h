#include <skynet.h>
#include <stdio.h>

struct logger {
    FILE * handle;
    char * filename;
    int close;
};

struct logger *logger_create(void);
void logger_release(struct logger *inst);
static int logger_cb(struct znet_context * context, void *ud, int type, int session, uint32_t source, const void * msg, size_t sz);
int logger_init(struct logger * inst, struct znet_context *ctx, const char * parm);
