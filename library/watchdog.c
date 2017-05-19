#include "skynet.h"
#include "tree.h"
#include <stdio.h>
#include <stdlib.h>
struct watchdog {
    struct skynet_context * ctx;
    rb_root *agent;
    uint32_t gate;
    uint32_t self;

};

static void
_parm(char *msg, int sz, int command_sz) {
    while (command_sz < sz) {
        if (msg[command_sz] != ' ')
            break;
        ++command_sz;
    }
    int i;
    for (i = command_sz; i<sz; i++) {
        msg[i - command_sz] = msg[i];
    }
    msg[i - command_sz] = '\0';
}

static void
_ctrl(struct watchdog * g, const void * msg, int sz) {
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
    char * text = command;
    char * idstr = strsep(&text, " ");
    if (text == NULL) {
        skynet_error(ctx, "[gate] Unkown id");
        return;
    }
    int id = strtol(idstr, NULL, 10);

    if (memcmp(text, "disconnect", 10) == 0) {
        skynet_command(ctx, "EXIT", NULL);
        return;
    }
    if (memcmp(text, "open", 4) == 0) {
        char tmp[1024];
        int n = snprintf(tmp, sizeof(tmp), "agent :%x %d :%x", g->gate, id, g->self);

        //启动agent服务
        const char * gate_self = skynet_command(ctx, "LAUNCH", tmp);
        if (gate_self == NULL) {
            skynet_error(ctx, "Invalid LAUNCH agent");
            return 1;
        }
        uint32_t gate = skynet_queryname(ctx, gate_self);
        
        rb_insert(id, gate, g->agent);
        return;
    }
    if (memcmp(text, "close", 5) == 0) {
        rb_node * agent = rb_search(id, g->agent);
        if (agent) {
            //关闭agent服务
            char tmp[1024];
            int n = snprintf(tmp, sizeof(tmp), "disconnect");
            skynet_send(ctx, 0, agent->data, PTYPE_TEXT, 0, "disconnect", 10);
        }
        return;
    }
    skynet_error(ctx, "[watchdog] Unkown command : %s", text);
}

static int
_cb(struct skynet_context * ctx, void * ud, int type, int session, uint32_t source, const void * msg, size_t sz) {
    struct gate *g = ud;
    switch (type) {
    case PTYPE_TEXT:
        _ctrl(g, msg, (int)sz);
        break;
    case PTYPE_CLIENT: {
        if (sz <= 4) {
            //skynet_error(ctx, "Invalid client message from %x", source);
            break;
        }
        
    }
    case PTYPE_SOCKET:
        // recv socket message from skynet_socket
        break;
    }
    return 0;
}

SKYNET_MODULE struct watchdog *watchdog_create(void){
    struct watchdog * g = skynet_malloc(sizeof(*g));
    memset(g, 0, sizeof(*g));
    g->agent = rb_new();
    g->gate = -1;
    return g;
}
SKYNET_MODULE void watchdog_release(struct watchdog *g){
    rb_free(g->agent);
    skynet_free(g);
}
SKYNET_MODULE int watchdog_init(struct watchdog *g, struct skynet_context * ctx, char * parm){
    if (parm == NULL)
        return 1;
    int sz = strlen(parm) + 1;
    char *ip = alloca(sz);
    int port = 0;
    int max = 0;
    //得到初始化参数,监听ip,端口,最大连接数
    int n = sscanf(parm, "%s %d %d", ip, &port, &max);

    if (ip == 0) {
        skynet_error(ctx, "Invalid ip");
        return 1;
    }

    if (port <= 0) {
        skynet_error(ctx, "Invalid port %s");
        return 1;
    }

    if (max <= 0) {
        skynet_error(ctx, "Invalid max");
        return 1;
    }

    //设置回调地址
    skynet_callback(ctx, g, _cb);

    g->ctx = ctx;
    //注册服务
    const char * self = skynet_command(ctx, "REG", NULL);
    g->self = strtoul(self + 1, NULL, 16);

    //启动gate服务
    char tmp[1024];
    n = snprintf(tmp, sizeof(tmp), "gate S  %s %d 0 %d", self, port, max);
    const char * gate = skynet_command(ctx, "LAUNCH", tmp);
    if (gate == NULL) {
        skynet_error(ctx, "Invalid LAUNCH gate");
        return 1;
    }
    g->gate = skynet_queryname(ctx, gate);
    if (g->gate == 0) {
        skynet_error(ctx, "Invalid gate %s", gate);
        return 1;
    }
    return 0;
}