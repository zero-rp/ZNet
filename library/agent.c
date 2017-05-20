#include "skynet.h"
#include "skynet_socket.h"
#include <stdio.h>
struct agent {
    struct skynet_context * ctx;
    int watchdog;
    int fd;
    int gate;
};


static void
_ctrl(struct agent * g, const void * msg, int sz) {
    struct skynet_context * ctx = g->ctx;
    char *tmp = alloca(sz + 1);
    memcpy(tmp, msg, sz);
    tmp[sz] = '\0';
    char * command = tmp;
    int i;
    if (sz == 0)
        return;
    for (i = 0; i<sz; i++) {
        if (command[i] == ' ') {
            break;
        }
    }
    if (memcmp(command, "disconnect", i) == 0) {
        skynet_command(ctx, "EXIT", NULL);
        return;
    }
    skynet_error(ctx, "[agent] Unkown command : %s", command);
}

static int
_cb(struct skynet_context * ctx, void * ud, int type, int session, uint32_t source, const void * msg, size_t sz) {
    struct agent *g = ud;
    switch (type) {
    case PTYPE_TEXT:
        _ctrl(g, msg, (int)sz);
        break;
    case PTYPE_CLIENT: {
        //收到客户数据
        char *tmp = skynet_malloc(sz + 2);
        memcpy(tmp + 2, msg, sz);
        skynet_socket_send(ctx, g->fd, tmp, sz + 2);
        skynet_error(ctx, "[agent] recv len : %d", sz);
    }
    case PTYPE_SOCKET:
        // recv socket message from skynet_socket
        break;
    }
    return 0;
}

SKYNET_MODULE struct agent *agent_create(void){
    struct agent * g = skynet_malloc(sizeof(*g));
    memset(g, 0, sizeof(*g));
    g->watchdog = -1;
    g->fd = -1;
    g->gate = -1;
    return g;
}
SKYNET_MODULE void agent_release(struct agent *g){

    skynet_free(g);
}
SKYNET_MODULE int agent_init(struct agent *g, struct skynet_context * ctx, char * parm){
    if (parm == NULL)
        return 1;
    int sz = strlen(parm) + 1;
    char *watchdog = alloca(sz);
    char *gate = alloca(sz);
    int fd;
    //得到初始化参数,gate服务,socket句柄,watchdog服务
    int n = sscanf(parm, "%s %d %s", gate, &fd, watchdog);

    g->watchdog = skynet_queryname(ctx, watchdog);
    if (g->watchdog == 0) {
        skynet_error(ctx, "Invalid watchdog %s", watchdog);
        return 1;
    }

    g->gate = skynet_queryname(ctx, gate);
    if (g->gate == 0) {
        skynet_error(ctx, "Invalid gate %s", gate);
        return 1;
    }

    g->fd = fd;
    if (g->fd < 0) {
        skynet_error(ctx, "Invalid fd %s", fd);
        return 1;
    }
    
    //设置回调
    skynet_callback(ctx, g, _cb);

    g->ctx = ctx;

    //注册服务
    const char * self = skynet_command(ctx, "REG", NULL);
    uint32_t handle_id = strtoul(self + 1, NULL, 16);
    //
    char tmp[1024];
    n = snprintf(tmp, sizeof(tmp), "forward  %d %s :0", fd, self);
    skynet_send(ctx, 0, g->gate, PTYPE_TEXT, 0, tmp, n);
    //
    n = snprintf(tmp, sizeof(tmp), "start  %d", fd);
    skynet_send(ctx, 0, g->gate, PTYPE_TEXT, 0, tmp, n);
    return 0;
}