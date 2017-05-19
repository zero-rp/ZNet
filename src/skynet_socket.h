#ifndef _SKYNET_SOCKET_H_
#define _SKYNET_SOCKET_H_
#include "skynet.h"
struct skynet_context;

#define SKYNET_SOCKET_TYPE_DATA 1
#define SKYNET_SOCKET_TYPE_CONNECT 2
#define SKYNET_SOCKET_TYPE_CLOSE 3
#define SKYNET_SOCKET_TYPE_ACCEPT 4
#define SKYNET_SOCKET_TYPE_ERROR 5
#define SKYNET_SOCKET_TYPE_UDP 6
#define SKYNET_SOCKET_TYPE_WARNING 7

struct skynet_socket_message {
	int type;
	int id;
	int ud;
	char * buffer;
};

void skynet_socket_init();
void skynet_socket_exit();
void skynet_socket_free();
int skynet_socket_poll();

SKYNET_EXTERN int skynet_socket_send(struct skynet_context *ctx, int id, void *buffer, int sz);
SKYNET_EXTERN int skynet_socket_send_lowpriority(struct skynet_context *ctx, int id, void *buffer, int sz);
SKYNET_EXTERN int skynet_socket_listen(struct skynet_context *ctx, const char *host, int port, int backlog);
SKYNET_EXTERN int skynet_socket_connect(struct skynet_context *ctx, const char *host, int port);
SKYNET_EXTERN int skynet_socket_bind(struct skynet_context *ctx, int fd);
SKYNET_EXTERN void skynet_socket_close(struct skynet_context *ctx, int id);
SKYNET_EXTERN void skynet_socket_shutdown(struct skynet_context *ctx, int id);
SKYNET_EXTERN void skynet_socket_start(struct skynet_context *ctx, int id);
SKYNET_EXTERN void skynet_socket_nodelay(struct skynet_context *ctx, int id);

SKYNET_EXTERN int skynet_socket_udp(struct skynet_context *ctx, const char * addr, int port);
SKYNET_EXTERN int skynet_socket_udp_connect(struct skynet_context *ctx, int id, const char * addr, int port);
SKYNET_EXTERN int skynet_socket_udp_send(struct skynet_context *ctx, int id, const char * address, const void *buffer, int sz);
SKYNET_EXTERN const char * skynet_socket_udp_address(struct skynet_socket_message *, int *addrsz);

#endif
