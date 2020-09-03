#include "skynet.h"
#include "socket_server.h"
#include <uv.h>
#include <queue.h>
#include "skynet_mq.h"
#include "atomic.h"


#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>


#if defined(_WIN32) || defined(_WIN64)
#define close closesocket
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#endif

#define MAX_INFO 128
// MAX_SOCKET will be 2^MAX_SOCKET_P
#define MAX_SOCKET_P 16
#define MAX_EVENT 64
#define MIN_READ_BUFFER 64
#define SOCKET_TYPE_INVALID 0
#define SOCKET_TYPE_RESERVE 1
#define SOCKET_TYPE_PLISTEN 2
#define SOCKET_TYPE_LISTEN 3
#define SOCKET_TYPE_CONNECTING 4
#define SOCKET_TYPE_CONNECTED 5
#define SOCKET_TYPE_HALFCLOSE 6
#define SOCKET_TYPE_PACCEPT 7
#define SOCKET_TYPE_BIND 8

#define MAX_SOCKET (1<<MAX_SOCKET_P)

#define PRIORITY_HIGH 0
#define PRIORITY_LOW 1

#define HASH_ID(id) (((unsigned)id) % MAX_SOCKET)

#define PROTOCOL_TCP 0
#define PROTOCOL_UDP 1
#define PROTOCOL_UDPv6 2

#define UDP_ADDRESS_SIZE 19	// ipv6 128bit + port 16bit + 1 byte type

#define MAX_UDP_PACKAGE 65535

struct write_buffer {
	struct write_buffer * next;
	void *buffer;
	char *ptr;
	int sz;
	bool userobject;
	uint8_t udp_address[UDP_ADDRESS_SIZE];
};

#define SIZEOF_TCPBUFFER (offsetof(struct write_buffer, udp_address[0]))
#define SIZEOF_UDPBUFFER (sizeof(struct write_buffer))

struct wb_list {
	struct write_buffer * head;
	struct write_buffer * tail;
};

struct socket {
	uintptr_t opaque;
	struct wb_list high;
	struct wb_list low;
	int64_t wb_size;
	union {
		uv_tcp_t tcp;
		uv_udp_t udp;
        uv_tty_t tty;
	} s;
	uint16_t protocol;
	int id;
    uint16_t type;
	union {
		int size;
		uint8_t udp_address[UDP_ADDRESS_SIZE];
	} p;
	bool write;
};

struct socket_server {
	uv_loop_t *loop;
    int alloc_id;
	struct socket_object_interface soi;
	struct socket slot[MAX_SOCKET];
	char buffer[MAX_INFO];
	uint8_t udpbuffer[MAX_UDP_PACKAGE];
	uv_async_t cmd_req;//命令通知
    uv_mutex_t cmd_mutex;//命令互斥
    QUEUE cmd_queue;//命令队列
    uv_timer_t cmd_timer;//定时刷新命令
	void(*cb)(int code, struct socket_message *result);
};

struct skynet_message_cmd {
    void * data;
    size_t sz;
    QUEUE wq;
};

struct request_open {
	int id;
	int port;
	uintptr_t opaque;
	char host[1];
};

struct request_send {
	int id;
	int sz;
	char * buffer;
};

struct request_send_udp {
	struct request_send send;
	uint8_t address[UDP_ADDRESS_SIZE];
};

struct request_setudp {
	int id;
	uint8_t address[UDP_ADDRESS_SIZE];
};

struct request_close {
	int id;
	uintptr_t opaque;
};

struct request_listen {
	int id;
	int backlog;
	uintptr_t opaque;
	int family;
	struct sockaddr addr;
	char host[1];
};

struct request_bind {
	int id;
	int fd;
	uintptr_t opaque;
};

struct request_start {
	int id;
	uintptr_t opaque;
};

struct request_setopt {
	int id;
	int what;
	int value;
};

struct request_udp {
	int id;
	int fd;
	int family;
	uintptr_t opaque;
};

/*
	The first byte is TYPE

	S Start socket
	B Bind socket
	L Listen socket
	K Close socket
	O Connect to (Open)
	X Exit
	D Send package (high)
	P Send package (low)
	A Send UDP package
	T Set opt
	U Create UDP socket
	C set udp address
 */

struct request_package {
	uint8_t header[8];	// 6 bytes dummy
	union {
		char buffer[256];
		struct request_open open;
		struct request_send send;
		struct request_send_udp send_udp;
		struct request_close close;
		struct request_listen listen;
		struct request_bind bind;
		struct request_start start;
		struct request_setopt setopt;
		struct request_udp udp;
		struct request_setudp set_udp;
	} u;
	uint8_t dummy[256];
};

union sockaddr_all {
	struct sockaddr s;
	struct sockaddr_in v4;
	struct sockaddr_in6 v6;
};

struct send_object {
	void * buffer;
	int sz;
	void (*free_func)(void *);
};

#define MALLOC skynet_malloc
#define FREE skynet_free

static int ctrl_cmd(struct socket_server *ss, int type, int len, char *buffer, struct socket_message *result);
static void force_close(struct socket_server *ss, struct socket *s, struct socket_message *result);
static int send_list_tcp(struct socket_server *ss, struct socket *s, struct wb_list *list, struct socket_message *result);
static int send_list_udp(struct socket_server *ss, struct socket *s, struct wb_list *list, struct socket_message *result);
static int report_accept(struct socket_server *ss, struct socket *s, struct socket_message *result);

static inline struct socket *
socket_from_handle(uv_handle_t *h) {
	return ((struct socket *)((char *)(h)-(size_t)&(((struct socket *)0)->s)));
}

static inline bool
send_object_init(struct socket_server *ss, struct send_object *so, void *object, int sz) {
	if (sz < 0) {
		so->buffer = ss->soi.buffer(object);
		so->sz = ss->soi.size(object);
		so->free_func = ss->soi.free;
		return true;
	} else {
		so->buffer = object;
		so->sz = sz;
		so->free_func = FREE;
		return false;
	}
}

static inline void
write_buffer_free(struct socket_server *ss, struct write_buffer *wb) {
	if (wb->userobject) {
		ss->soi.free(wb->buffer);
	} else {
		FREE(wb->buffer);
	}
	FREE(wb);
}

static void
socket_keepalive(int fd) {
	int keepalive = 1;
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&keepalive , sizeof(keepalive));  
}

static int
reserve_id(struct socket_server *ss) {
    int i;
    for (i = 0; i<MAX_SOCKET; i++) {
        int id = ATOM_INC(&(ss->alloc_id));
        if (id < 0) {
            id = ATOM_AND(&(ss->alloc_id), 0x7fffffff);
        }
        struct socket *s = &ss->slot[HASH_ID(id)];
        if (s->type == SOCKET_TYPE_INVALID) {
            if (ATOM_CAS16(&s->type, SOCKET_TYPE_INVALID, SOCKET_TYPE_RESERVE)) {
                s->id = id;
                return id;
            }
            else {
                // retry
                --i;
            }
        }
    }
    return -1;
}


static inline void
close_cb(uv_handle_t *h) {
	if (h->type == UV_TCP || h->type == UV_UDP) {
		struct socket *s = socket_from_handle(h);
		s->type = SOCKET_TYPE_INVALID;
	}
}

static inline void
clear_wb_list(struct wb_list *list) {
	list->head = NULL;
	list->tail = NULL;
}

static inline void 
free_request_package(struct skynet_message_cmd *msg, void *u) {
	struct request_package *r = (struct request_package *)msg->data;
	FREE(r);
}


static inline void
cmd_cb(uv_async_t* handle) {
	struct socket_message result;
	struct skynet_message_cmd msg;
	struct socket_server *ss = (struct socket_server *)handle->data;
    while (true)
    {
        QUEUE* q;
        // 同步
        uv_mutex_lock(&ss->cmd_mutex);

        if (QUEUE_EMPTY(&ss->cmd_queue))
        {
            //空队列
            uv_mutex_unlock(&ss->cmd_mutex);
            break;
        }
        // 取出队列的头部节点（第一个task）
        q = QUEUE_HEAD(&ss->cmd_queue);

        // 从队列中移除这个task
        QUEUE_REMOVE(q);
        uv_mutex_unlock(&ss->cmd_mutex);

        // 取出task_client首地址
        struct skynet_message_cmd *w = QUEUE_DATA(q, struct skynet_message_cmd, wq);

        memcpy(&msg, w, sizeof(msg));

        struct request_package *r = (struct request_package *)msg.data;
        int ret = ctrl_cmd(ss, r->header[6], r->header[7], r->u.buffer, &result);
        free_request_package(&msg, NULL);
        if (ret != -1) {
            ss->cb(ret, &result);
            break;
        }



        FREE(w);
    }
}

static inline void
alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf){
	buf->base = (char *)MALLOC(suggested_size);
	buf->len = suggested_size;
}

static inline void
read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
	struct socket_server *ss = (struct socket_server *)stream->data;
	struct socket *s = socket_from_handle((uv_handle_t *)stream);
	struct socket_message result;

	if (nread > 0) {
		result.opaque = s->opaque;
		result.id = s->id;
		result.ud = nread;
		result.data = buf->base;
		ss->cb((stream->type != UV_UDP ? SOCKET_DATA : SOCKET_UDP), &result);
	}
	else {
		FREE(buf->base);
		if (nread < 0) {
			force_close(ss, s, &result);
			ss->cb(SOCKET_ERR, &result);
		}
	}
}

static void
connect_cb_(uv_connect_t* req, int status) {
	struct socket *s = (struct socket *)req->data;
	struct socket_server *ss = (struct socket_server *)s->s.tcp.data;
	struct socket_message result;

	if (status != 0 || uv_read_start((uv_stream_t *)&s->s, alloc_cb, read_cb) != 0) {
		force_close(ss, s, &result);
		ss->cb(SOCKET_ERR, &result);
	}
	else {
		uv_tcp_keepalive(&s->s.tcp, true, false);
		s->type = SOCKET_TYPE_CONNECTED;
		s->s.tcp.data = ss;
		result.opaque = s->opaque;
		result.id = s->id;
		result.ud = 0;
		result.data = NULL;
		union sockaddr_all u;
		socklen_t slen = sizeof(u);
		if (uv_tcp_getpeername(&s->s.tcp, &u.s, &slen) == 0) {
			void * sin_addr = (u.s.sa_family == AF_INET) ? (void*)&u.v4.sin_addr : (void *)&u.v6.sin6_addr;
			if (uv_inet_ntop(u.s.sa_family, sin_addr, ss->buffer, sizeof(ss->buffer))) {
				result.data = ss->buffer;
			}
		}
		ss->cb(SOCKET_OPEN, &result);
	}
	FREE(req);
}

static inline void 
write_cb_(uv_write_t* req, int status) {
	struct wb_list *list = (struct wb_list *)req->data;
	struct socket *s = socket_from_handle((uv_handle_t *)req->handle);
	struct socket_server *ss = (struct socket_server *)req->handle->data;
	struct socket_message result;
	s->write = false;
	FREE(req);
	
	if (status == 0) {
		struct write_buffer * tmp = list->head;
		list->head = tmp->next;
		write_buffer_free(ss, tmp);
		if (send_list_tcp(ss, s, list, &result) == -1) {
			return;
		}
	}
	ss->cb(SOCKET_CLOSE, &result);
}

static inline void 
udp_send_cb(uv_udp_send_t* req, int status) {
	struct wb_list *list = (struct wb_list *)req->data;
	struct socket *s = socket_from_handle((uv_handle_t *)req->handle);
	struct socket_server *ss = (struct socket_server *)req->handle->data;
	struct socket_message result;

	if (status == 0) {
		struct write_buffer * tmp = list->head;
		list->head = tmp->next;
		write_buffer_free(ss, tmp);
		if (send_list_udp(ss, s, list, &result) == -1) {
			return;
		}
	}
	// ignore udp sendto error
}

static inline void
connection_cb(uv_stream_t* server, int status) {
	struct socket_server *ss = (struct socket_server *)server->data;
	struct socket *s = socket_from_handle((uv_handle_t *)server);
	struct socket_message result;
	if (status == 0) {
		if (report_accept(ss, s, &result)) {
			ss->cb(SOCKET_ACCEPT, &result);
		}
	}
	else {
		force_close(ss, s, &result);
		ss->cb(SOCKET_ERR, &result);
	}
}

static inline void
cmd_timer_cb(uv_timer_t* handle) {
    struct socket_server *ss = (struct socket_server *)handle->data;
    uv_async_send(&ss->cmd_req);
}


struct socket_server * 
socket_server_create(void(*cb)(int code, struct socket_message *result)) {
	struct socket_server *ss = (struct socket_server *)MALLOC(sizeof(*ss));
	ss->loop = uv_loop_new();
	for (int i=0;i<MAX_SOCKET;i++) {
		struct socket *s = &ss->slot[i];
		s->type = SOCKET_TYPE_INVALID;
		clear_wb_list(&s->high);
		clear_wb_list(&s->low);
	}
	ss->alloc_id = 0;
	memset(&ss->soi, 0, sizeof(ss->soi));
	ss->cb = cb;
	uv_async_init(ss->loop, &ss->cmd_req, cmd_cb);
	ss->cmd_req.data = ss;

    uv_timer_init(ss->loop, &ss->cmd_timer);
    ss->cmd_timer.data = ss;
    //uv_timer_start(&ss->cmd_timer, cmd_cb, 10, 10);

    uv_mutex_init(&ss->cmd_mutex);
    QUEUE_INIT(&ss->cmd_queue);
	return ss;
}

static void
free_wb_list(struct socket_server *ss, struct wb_list *list) {
	struct write_buffer *wb = list->head;
	while (wb) {
		struct write_buffer *tmp = wb;
		wb = wb->next;
		write_buffer_free(ss, tmp);
	}
	list->head = NULL;
	list->tail = NULL;
}

static void
force_close(struct socket_server *ss, struct socket *s, struct socket_message *result) {
	result->id = s->id;
	result->ud = 0;
	result->data = NULL;
	result->opaque = s->opaque;
	if (s->type == SOCKET_TYPE_INVALID) {
		return;
	}
	assert(s->type != SOCKET_TYPE_RESERVE);
	free_wb_list(ss,&s->high);
	free_wb_list(ss,&s->low);
	uv_close((uv_handle_t *)&s->s, close_cb);
}

void 
socket_server_release(struct socket_server *ss) {
	int i;
	struct socket_message dummy;
	for (i=0;i<MAX_SOCKET;i++) {
		struct socket *s = &ss->slot[i];
		if (s->type != SOCKET_TYPE_RESERVE) {
			force_close(ss, s , &dummy);
		}
	}
	uv_close((uv_handle_t *)&ss->cmd_req, close_cb);
	uv_run(ss->loop, UV_RUN_DEFAULT); // 等待事件循环自己退出
	uv_loop_delete(ss->loop);
	//ss->cmd_queue->Release(free_request_package, NULL);
	//delete ss->cmd_queue;
	FREE(ss);
}

static inline void
check_wb_list(struct wb_list *s) {
	assert(s->head == NULL);
	assert(s->tail == NULL);
}
static inline void
udp_read_cb(uv_stream_t* stream, ssize_t nread, uv_buf_t *buf, struct sockaddr *addr, unsigned flags) {
    struct socket_server *ss = (struct socket_server *)stream->data;
    struct socket *s = socket_from_handle((uv_handle_t *)stream);
    struct socket_message result;

    if (nread > 0) {
        result.opaque = s->opaque;
        result.id = s->id;
        result.ud = nread;
        result.data = buf->base;
        //gen_udp_address(PROTOCOL_UDP, addr, );
        ss->cb((stream->type != UV_UDP ? SOCKET_DATA : SOCKET_UDP), &result);
    }
    else {
        FREE(buf->base);
        if (nread < 0) {
            force_close(ss, s, &result);
            ss->cb(SOCKET_ERR, &result);
        }
    }

}
static struct socket *
new_fd(struct socket_server *ss, int id, int fd, int protocol, uintptr_t opaque, bool add) {
	struct socket * s = &ss->slot[HASH_ID(id)];
	assert(s->type == SOCKET_TYPE_RESERVE);
	s->id = id;
	if (protocol == PROTOCOL_TCP) {
		if (fileno(stdin) == fd || fileno(stdout) == fd || fileno(stderr) == fd) {
			if (uv_tty_init(ss->loop, &s->s.tty, fd, (fileno(stdin) == fd)) != 0) {
				uv_close((uv_handle_t *)&s->s, close_cb);
				return NULL;
			}
		}
		else {
			uv_tcp_init(ss->loop, &s->s.tcp);
			if (fd != -1 && uv_tcp_open(&s->s.tcp, fd) != 0) {
				uv_close((uv_handle_t *)&s->s, close_cb);
				return NULL;
			}
		}
		s->s.tcp.data = ss;

		if (add) {
			if (uv_read_start((uv_stream_t *)&s->s, alloc_cb, read_cb) != 0) {
				uv_close((uv_handle_t *)&s->s, close_cb);;
				return NULL;
			}
		}
	}
    else if (protocol == PROTOCOL_UDP || protocol == PROTOCOL_UDPv6) {
        uv_udp_init(ss->loop, &s->s.udp);
        if (fd != -1) {
            uv_udp_open(&s->s.udp, fd);
        }
        s->s.udp.data = ss;
        if (add) {
            if (uv_udp_recv_start(&s->s.udp, alloc_cb, udp_read_cb) != 0) {
                s->type = SOCKET_TYPE_INVALID;
                return NULL;
            }
        }
    }
	s->protocol = protocol;
	s->p.size = MIN_READ_BUFFER;
	s->write = false;
	s->opaque = opaque;
	s->wb_size = 0;
	check_wb_list(&s->high);
	check_wb_list(&s->low);
	return s;
}

// return -1 when connecting
static int
open_socket(struct socket_server *ss, struct request_open * request, struct socket_message *result) {
	int id = request->id;
	result->opaque = request->opaque;
	result->id = id;
	result->ud = 0;
	result->data = NULL;

	struct sockaddr_in addr;
	int err = uv_ip4_addr(request->host, request->port, &addr);
	if (err != 0) {
		goto _failed;
	}

	struct socket *ns = new_fd(ss, id, -1, PROTOCOL_TCP, request->opaque, false);
	if (ns == NULL) {
		goto _failed;
	}

	ns->type = SOCKET_TYPE_CONNECTING;
	uv_connect_t *req = (uv_connect_t *)MALLOC(sizeof(uv_connect_t));
	req->data = ns;
	int status = uv_tcp_connect(req, &ns->s.tcp, (struct sockaddr *)&addr, connect_cb_);
	if(status != 0) {
		FREE(req);
		goto _failed;
	}
	return -1;
_failed:
	ss->slot[HASH_ID(id)].type = SOCKET_TYPE_INVALID;
	return SOCKET_ERR;
}

#define MAX_SEND_BUF 1 // 这里暂时只设置为1，因为write_cb_里不知道该怎么得到这一次发送的总buf数
static int
send_list_tcp(struct socket_server *ss, struct socket *s, struct wb_list *list, struct socket_message *result) {
	if (s->write) return -1;

	if (list->head != NULL) {
		uv_buf_t buf[MAX_SEND_BUF];
		struct write_buffer * tmp = list->head;
		int i = 0;
		for (; tmp != NULL && i < MAX_SEND_BUF; ++i, tmp = tmp->next) {
			buf[i] = uv_buf_init(tmp->ptr, tmp->sz);
		}
		uv_write_t *req = (uv_write_t *)MALLOC(sizeof(uv_write_t));
		req->data = list;
		if (uv_write(req, (uv_stream_t *)&s->s.tcp, buf, i, &write_cb_) != 0) {
			FREE(req);
			return SOCKET_CLOSE;
		}
		s->write = true;
	}
	return -1;
}

static socklen_t
udp_socket_address(struct socket *s, const uint8_t udp_address[UDP_ADDRESS_SIZE], union sockaddr_all *sa) {
	int type = (uint8_t)udp_address[0];
	if (type != s->protocol)
		return 0;
	uint16_t port = 0;
	memcpy(&port, udp_address+1, sizeof(uint16_t));
	switch (s->protocol) {
	case PROTOCOL_UDP:
		memset(&sa->v4, 0, sizeof(sa->v4));
		sa->s.sa_family = AF_INET;
		sa->v4.sin_port = port;
		memcpy(&sa->v4.sin_addr, udp_address + 1 + sizeof(uint16_t), sizeof(sa->v4.sin_addr));	// ipv4 address is 32 bits
		return sizeof(sa->v4);
	case PROTOCOL_UDPv6:
		memset(&sa->v6, 0, sizeof(sa->v6));
		sa->s.sa_family = AF_INET6;
		sa->v6.sin6_port = port;
		memcpy(&sa->v6.sin6_addr, udp_address + 1 + sizeof(uint16_t), sizeof(sa->v6.sin6_addr));	// ipv4 address is 128 bits
		return sizeof(sa->v6);
	}
	return 0;
}

static int
send_list_udp(struct socket_server *ss, struct socket *s, struct wb_list *list, struct socket_message *result) {
	if (list->head != NULL) {
		struct write_buffer * tmp = list->head;
		uv_buf_t buf = uv_buf_init(tmp->ptr, tmp->sz);
		uv_udp_send_t *req = (uv_udp_send_t *)MALLOC(sizeof(uv_udp_send_t));
		req->data = list;
		union sockaddr_all sa;
		socklen_t sasz = udp_socket_address(s, tmp->udp_address, &sa);
		if (uv_udp_send(req, &s->s.udp, &buf, 1, &sa.s, &udp_send_cb) != 0) {
			FREE(req);
			return SOCKET_CLOSE;
		}
	}
	return -1;
}

static int
send_list(struct socket_server *ss, struct socket *s, struct wb_list *list, struct socket_message *result) {
	if (s->protocol == PROTOCOL_TCP) {
		return send_list_tcp(ss, s, list, result);
	} else {
		return send_list_udp(ss, s, list, result);
	}
}

static inline int
list_uncomplete(struct wb_list *s) {
	struct write_buffer *wb = s->head;
	if (wb == NULL)
		return 0;
	
	return (void *)wb->ptr != wb->buffer;
}

static void
raise_uncomplete(struct socket * s) {
	struct wb_list *low = &s->low;
	struct write_buffer *tmp = low->head;
	low->head = tmp->next;
	if (low->head == NULL) {
		low->tail = NULL;
	}

	// move head of low list (tmp) to the empty high list
	struct wb_list *high = &s->high;
	assert(high->head == NULL);

	tmp->next = NULL;
	high->head = high->tail = tmp;
}

/*
	Each socket has two write buffer list, high priority and low priority.

	1. send high list as far as possible.
	2. If high list is empty, try to send low list.
	3. If low list head is uncomplete (send a part before), move the head of low list to empty high list (call raise_uncomplete) .
	4. If two lists are both empty, turn off the event. (call check_close)
 */
static int
send_buffer(struct socket_server *ss, struct socket *s, struct socket_message *result) {
	if (send_list(ss,s,&s->high,result) == SOCKET_CLOSE) {
		return SOCKET_CLOSE;
	}
	if (s->high.head == NULL) {
		if (s->low.head != NULL) {
			if (send_list(ss,s,&s->low,result) == SOCKET_CLOSE) {
				return SOCKET_CLOSE;
			}
		}
	}
	return -1;
}

static struct write_buffer *
append_sendbuffer_(struct socket_server *ss, struct wb_list *s, struct request_send * request, int size, int n) {
	struct write_buffer * buf = (struct write_buffer *)MALLOC(size);
	struct send_object so;
	buf->userobject = send_object_init(ss, &so, request->buffer, request->sz);
	buf->ptr = (char*)so.buffer+n;
	buf->sz = so.sz - n;
	buf->buffer = request->buffer;
	buf->next = NULL;
	if (s->head == NULL) {
		s->head = s->tail = buf;
	} else {
		assert(s->tail != NULL);
		assert(s->tail->next == NULL);
		s->tail->next = buf;
		s->tail = buf;
	}
	return buf;
}

static inline void
append_sendbuffer_udp(struct socket_server *ss, struct socket *s, int priority, struct request_send * request, const uint8_t udp_address[UDP_ADDRESS_SIZE]) {
	struct wb_list *wl = (priority == PRIORITY_HIGH) ? &s->high : &s->low;
	struct write_buffer *buf = append_sendbuffer_(ss, wl, request, SIZEOF_UDPBUFFER, 0);
	memcpy(buf->udp_address, udp_address, UDP_ADDRESS_SIZE);
	s->wb_size += buf->sz;
}

static inline void
append_sendbuffer(struct socket_server *ss, struct socket *s, struct request_send * request, int n) {
	struct write_buffer *buf = append_sendbuffer_(ss, &s->high, request, SIZEOF_TCPBUFFER, n);
	s->wb_size += buf->sz;

	struct socket_message msg;
	if (!s->write && send_buffer(ss, s, &msg) == SOCKET_CLOSE) {
		ss->cb(SOCKET_CLOSE, &msg);
	}
}

static inline void
append_sendbuffer_low(struct socket_server *ss,struct socket *s, struct request_send * request) {
	struct write_buffer *buf = append_sendbuffer_(ss, &s->low, request, SIZEOF_TCPBUFFER, 0);
	s->wb_size += buf->sz;
}

static inline int
send_buffer_empty(struct socket *s) {
	return (s->high.head == NULL && s->low.head == NULL);
}

/*
	When send a package , we can assign the priority : PRIORITY_HIGH or PRIORITY_LOW

	If socket buffer is empty, write to fd directly.
		If write a part, append the rest part to high list. (Even priority is PRIORITY_LOW)
	Else append package to high (PRIORITY_HIGH) or low (PRIORITY_LOW) list.
 */
static int
send_socket(struct socket_server *ss, struct request_send * request, struct socket_message *result, int priority, const uint8_t *udp_address) {
	int id = request->id;
	struct socket * s = &ss->slot[HASH_ID(id)];
	struct send_object so;
	send_object_init(ss, &so, request->buffer, request->sz);
	if (s->type == SOCKET_TYPE_INVALID || s->id != id 
		|| s->type == SOCKET_TYPE_HALFCLOSE) {
		so.free_func(request->buffer);
		return -1;
	}
	assert(s->type != SOCKET_TYPE_PLISTEN && s->type != SOCKET_TYPE_LISTEN);
	if (send_buffer_empty(s) && s->type == SOCKET_TYPE_CONNECTED) {
		if (s->protocol == PROTOCOL_TCP) {
			append_sendbuffer(ss, s, request, 0);	// add to high priority list, even priority == PRIORITY_LOW
		} else {
			// udp
			if (udp_address == NULL) {
				udp_address = s->p.udp_address;
			}
			append_sendbuffer_udp(ss, s, priority, request, udp_address);
		}
	} else {
		if (s->protocol == PROTOCOL_TCP) {
			if (priority == PRIORITY_LOW) {
				append_sendbuffer_low(ss, s, request);
			} else {
				append_sendbuffer(ss, s, request, 0);
			}
		} else {
			if (udp_address == NULL) {
				udp_address = s->p.udp_address;
			}
			append_sendbuffer_udp(ss,s,priority,request,udp_address);
		}
	}
	return -1;
}

static int
listen_socket(struct socket_server *ss, struct request_listen * request, struct socket_message *result) {
	int id = request->id;
	struct socket *s = new_fd(ss, id, -1, PROTOCOL_TCP, request->opaque, false);
	if (s == NULL) {
		goto _failed;
	}

	if (uv_tcp_bind(&s->s.tcp, &request->addr, 0) != 0) {
		uv_close((uv_handle_t *)&s->s.tcp, close_cb);
		return -1;
	}
	s->s.tcp.data = (void *)request->backlog; // 把backlog存在data里面
	s->type = SOCKET_TYPE_PLISTEN;
	return -1;
_failed:
	result->opaque = request->opaque;
	result->id = id;
	result->ud = 0;
	result->data = NULL;
	ss->slot[HASH_ID(id)].type = SOCKET_TYPE_INVALID;

	return -1;
}

static int
close_socket(struct socket_server *ss, struct request_close *request, struct socket_message *result) {
	int id = request->id;
	struct socket * s = &ss->slot[HASH_ID(id)];
	if (s->type == SOCKET_TYPE_INVALID || s->id != id) {
		result->id = id;
		result->opaque = request->opaque;
		result->ud = 0;
		result->data = NULL;
		return SOCKET_CLOSE;
	}
	if (!send_buffer_empty(s)) { 
		int type = send_buffer(ss,s,result);
		if (type != -1)
			return type;
	}
	if (send_buffer_empty(s)) {
		force_close(ss,s,result);
		result->id = id;
		result->opaque = request->opaque;
		return SOCKET_CLOSE;
	}
	s->type = SOCKET_TYPE_HALFCLOSE;

	return -1;
}

static int
bind_socket(struct socket_server *ss, struct request_bind *request, struct socket_message *result) {
	int id = request->id;
	result->id = id;
	result->opaque = request->opaque;
	result->ud = 0;
	struct socket *s = new_fd(ss, id, request->fd, PROTOCOL_TCP, request->opaque, true);
	if (s == NULL) {
		result->data = NULL;
		return SOCKET_ERR;
	}
	s->type = SOCKET_TYPE_BIND;
	result->data = "binding";
	return SOCKET_OPEN;
}

static int
start_socket(struct socket_server *ss, struct request_start *request, struct socket_message *result) {
	int id = request->id;
	result->id = id;
	result->opaque = request->opaque;
	result->ud = 0;
	result->data = NULL;
	struct socket *s = &ss->slot[HASH_ID(id)];
	if (s->type == SOCKET_TYPE_INVALID || s->id !=id) {
		return SOCKET_ERR;
	}
	if (s->type == SOCKET_TYPE_PACCEPT) {
		if (uv_read_start((uv_stream_t *)&s->s, alloc_cb, read_cb) != 0) {
			force_close(ss, s, result);
			return SOCKET_ERR;
		}
		s->s.tcp.data = ss;
		s->type = SOCKET_TYPE_CONNECTED;
		s->opaque = request->opaque;
		result->data = "start";
		return SOCKET_OPEN;
	} else if (s->type == SOCKET_TYPE_CONNECTED) {
		s->opaque = request->opaque;
		result->data = "transfer";
		return SOCKET_OPEN;
	}
	else if (s->type == SOCKET_TYPE_PLISTEN) {
		int backlog = (int)s->s.tcp.data;
		if (uv_listen((uv_stream_t *)&s->s, backlog, connection_cb) != 0) {
			force_close(ss, s, result);
			return SOCKET_ERR;
		}
		s->s.tcp.data = ss;
		s->type = SOCKET_TYPE_LISTEN;
		s->opaque = request->opaque;
		result->data = "start";
		return SOCKET_OPEN;
	}
	return -1;
}

static void
setopt_socket(struct socket_server *ss, struct request_setopt *request) {
	int id = request->id;
	struct socket *s = &ss->slot[HASH_ID(id)];
	if (s->type == SOCKET_TYPE_INVALID || s->id !=id) {
		return;
	}
	int v = request->value;
#if defined(_WIN32) || defined(_WIN64)
	setsockopt(s->s.tcp.socket, IPPROTO_TCP, request->what, (char *)&v, sizeof(v));
#else
    setsockopt(s->s.tcp.io_watcher.fd, IPPROTO_TCP, request->what, (char *)&v, sizeof(v));
#endif
}

static void
add_udp_socket(struct socket_server *ss, struct request_udp *udp) {
	int id = udp->id;
	int protocol;
	if (udp->family == AF_INET6) {
		protocol = PROTOCOL_UDPv6;
	} else {
		protocol = PROTOCOL_UDP;
	}
	struct socket *ns = new_fd(ss, id, udp->fd, protocol, udp->opaque, true);
	if (ns == NULL) {
		ss->slot[HASH_ID(id)].type = SOCKET_TYPE_INVALID;
	}
	ns->type = SOCKET_TYPE_CONNECTED;
	memset(ns->p.udp_address, 0, sizeof(ns->p.udp_address));
}

static int
set_udp_address(struct socket_server *ss, struct request_setudp *request, struct socket_message *result) {
	int id = request->id;
	struct socket *s = &ss->slot[HASH_ID(id)];
	if (s->type == SOCKET_TYPE_INVALID || s->id !=id) {
		return -1;
	}
	int type = request->address[0];
	if (type != s->protocol) {
		// protocol mismatch
		result->opaque = s->opaque;
		result->id = s->id;
		result->ud = 0;
		result->data = NULL;

		return SOCKET_ERR;
	}
	if (type == PROTOCOL_UDP) {
		memcpy(s->p.udp_address, request->address, 1+2+4);	// 1 type, 2 port, 4 ipv4
	} else {
		memcpy(s->p.udp_address, request->address, 1+2+16);	// 1 type, 2 port, 16 ipv6
	}
	return -1;
}

// return type
static int
ctrl_cmd(struct socket_server *ss, int type, int len, char *buffer, struct socket_message *result) {
	switch (type) {
	case 'S':
		return start_socket(ss,(struct request_start *)buffer, result);
	case 'B':
		return bind_socket(ss,(struct request_bind *)buffer, result);
	case 'L':
		return listen_socket(ss,(struct request_listen *)buffer, result);
	case 'K':
		return close_socket(ss,(struct request_close *)buffer, result);
	case 'O':
		return open_socket(ss, (struct request_open *)buffer, result);
	case 'X':
		result->opaque = 0;
		result->id = 0;
		result->ud = 0;
		result->data = NULL;
		return SOCKET_EXIT;
	case 'D':
		return send_socket(ss, (struct request_send *)buffer, result, PRIORITY_HIGH, NULL);
	case 'P':
		return send_socket(ss, (struct request_send *)buffer, result, PRIORITY_LOW, NULL);
	case 'A': {
		struct request_send_udp * rsu = (struct request_send_udp *)buffer;
		return send_socket(ss, &rsu->send, result, PRIORITY_HIGH, rsu->address);
	}
	case 'C':
		return set_udp_address(ss, (struct request_setudp *)buffer, result);
	case 'T':
		setopt_socket(ss, (struct request_setopt *)buffer);
		return -1;
	case 'U':
		add_udp_socket(ss, (struct request_udp *)buffer);
		return -1;
	default:
		fprintf(stderr, "socket-server: Unknown ctrl %c.\n",type);
		return -1;
	};

	return -1;
}

static int
gen_udp_address(int protocol, union sockaddr_all *sa, uint8_t * udp_address) {
	int addrsz = 1;
	udp_address[0] = (uint8_t)protocol;
	if (protocol == PROTOCOL_UDP) {
		memcpy(udp_address+addrsz, &sa->v4.sin_port, sizeof(sa->v4.sin_port));
		addrsz += sizeof(sa->v4.sin_port);
		memcpy(udp_address+addrsz, &sa->v4.sin_addr, sizeof(sa->v4.sin_addr));
		addrsz += sizeof(sa->v4.sin_addr);
	} else {
		memcpy(udp_address+addrsz, &sa->v6.sin6_port, sizeof(sa->v6.sin6_port));
		addrsz += sizeof(sa->v6.sin6_port);
		memcpy(udp_address+addrsz, &sa->v6.sin6_addr, sizeof(sa->v6.sin6_addr));
		addrsz += sizeof(sa->v6.sin6_addr);
	}
	return addrsz;
}

// return 0 when failed
static int
report_accept(struct socket_server *ss, struct socket *s, struct socket_message *result) {
	union sockaddr_all u;
	socklen_t len = sizeof(u);

	int id = reserve_id(ss);
	if (id < 0) {
		return 0;
	}
	struct socket *ns = new_fd(ss, id, -1, PROTOCOL_TCP, s->opaque, false);
	if (ns == NULL) {
		return 0;
	}

	if (uv_accept((uv_stream_t *)&s->s.tcp, (uv_stream_t *)&ns->s.tcp) != 0) {
		uv_close((uv_handle_t *)&ns->s.tcp, close_cb);
		return 0;
	}

	ns->type = SOCKET_TYPE_PACCEPT;
	result->opaque = s->opaque;
	result->id = s->id;
	result->ud = id;
	result->data = NULL;

	uv_tcp_getpeername(&ns->s.tcp, &u.s, &len);
	void * sin_addr = (u.s.sa_family == AF_INET) ? (void*)&u.v4.sin_addr : (void *)&u.v6.sin6_addr;
	int sin_port = ntohs((u.s.sa_family == AF_INET) ? u.v4.sin_port : u.v6.sin6_port);
	char tmp[INET6_ADDRSTRLEN];
	if (uv_inet_ntop(u.s.sa_family, sin_addr, tmp, sizeof(tmp)) == 0) {
		sprintf(ss->buffer, "%s:%d", tmp, sin_port);
		result->data = ss->buffer;
	}
    skynet_error(NULL, "accept %d", id);
	return 1;
}

// return type
int 
socket_server_poll(struct socket_server *ss) {
	return uv_run(ss->loop, UV_RUN_ONCE);
}

static void
send_request(struct socket_server *ss, struct request_package *request, char type, int len) {
	request->header[6] = (uint8_t)type;
	request->header[7] = (uint8_t)len;
	
    struct skynet_message_cmd *msg=MALLOC(sizeof(*msg));
	msg->data = MALLOC(sizeof(*request));
	memcpy(msg->data, request, sizeof(*request));
	msg->sz = sizeof(*request);
    // 同步
    uv_mutex_lock(&ss->cmd_mutex);
    // 将task插入队列尾部
    QUEUE_INSERT_TAIL(&ss->cmd_queue, &msg->wq);
    uv_mutex_unlock(&ss->cmd_mutex);
	uv_async_send(&ss->cmd_req);
}

static int
open_request(struct socket_server *ss, struct request_package *req, uintptr_t opaque, const char *addr, int port) {
	int len = strlen(addr);
	if (len + sizeof(req->u.open) > 256) {
		fprintf(stderr, "socket-server : Invalid addr %s.\n",addr);
		return -1;
	}
	int id = reserve_id(ss);
	if (id < 0)
		return -1;
	req->u.open.opaque = opaque;
	req->u.open.id = id;
	req->u.open.port = port;
	memcpy(req->u.open.host, addr, len);
	req->u.open.host[len] = '\0';

	return len;
}

int 
socket_server_connect(struct socket_server *ss, uintptr_t opaque, const char * addr, int port) {
	struct request_package request;
	int len = open_request(ss, &request, opaque, addr, port);
	if (len < 0)
		return -1;
	send_request(ss, &request, 'O', sizeof(request.u.open) + len);
	return request.u.open.id;
}

// return -1 when error
int64_t 
socket_server_send(struct socket_server *ss, int id, const void * buffer, int sz) {
	struct socket * s = &ss->slot[HASH_ID(id)];
	if (s->id != id || s->type == SOCKET_TYPE_INVALID) {
		return -1;
	}

	struct request_package request;
	request.u.send.id = id;
	request.u.send.sz = sz;
	request.u.send.buffer = (char *)buffer;

	send_request(ss, &request, 'D', sizeof(request.u.send));
	return s->wb_size;
}

int 
socket_server_send_lowpriority(struct socket_server *ss, int id, const void * buffer, int sz) {
	struct socket * s = &ss->slot[HASH_ID(id)];
	if (s->id != id || s->type == SOCKET_TYPE_INVALID) {
		return -1;
	}

	struct request_package request;
	request.u.send.id = id;
	request.u.send.sz = sz;
	request.u.send.buffer = (char *)buffer;

	send_request(ss, &request, 'P', sizeof(request.u.send));
    return 0;
}

void
socket_server_exit(struct socket_server *ss) {
	struct request_package request;
	send_request(ss, &request, 'X', 0);
}

void
socket_server_close(struct socket_server *ss, uintptr_t opaque, int id) {
	struct request_package request;
	request.u.close.id = id;
	request.u.close.opaque = opaque;
	send_request(ss, &request, 'K', sizeof(request.u.close));
}

void
socket_server_shutdown(struct socket_server *ss, uintptr_t opaque, int id) {
    struct request_package request;
    request.u.close.id = id;
    //request.u.close.shutdown = 1;
    request.u.close.opaque = opaque;
    send_request(ss, &request, 'K', sizeof(request.u.close));
}

static int
do_getaddr(const char *host, int port, int protocol, int *family, struct sockaddr *addr) {
	int status;
	struct addrinfo ai_hints;
	struct addrinfo *ai_list = NULL;
	char portstr[16];
	if (host == NULL || host[0] == 0) {
		host = "0.0.0.0";	// INADDR_ANY
	}
	sprintf(portstr, "%d", port);
	memset(&ai_hints, 0, sizeof(ai_hints));
	ai_hints.ai_family = AF_UNSPEC;
	if (protocol == IPPROTO_TCP) {
		ai_hints.ai_socktype = SOCK_STREAM;
	}
	else {
		assert(protocol == IPPROTO_UDP);
		ai_hints.ai_socktype = SOCK_DGRAM;
	}
	ai_hints.ai_protocol = protocol;

	status = getaddrinfo(host, portstr, &ai_hints, &ai_list);
	if (status != 0) {
		return -1;
	}
	*addr = *ai_list->ai_addr;
	freeaddrinfo(ai_list);
	return 0;
}

int 
socket_server_listen(struct socket_server *ss, uintptr_t opaque, const char * addr, int port, int backlog) {
	struct request_package request;
	if (do_getaddr(addr, port, IPPROTO_TCP, &request.u.listen.family, &request.u.listen.addr) != 0) {
		return -1;
	}

	int id = reserve_id(ss);
	if (id < 0) {
		return id;
	}
	request.u.listen.opaque = opaque;
	request.u.listen.id = id;
	request.u.listen.backlog = backlog;
	send_request(ss, &request, 'L', sizeof(request.u.listen));
	return id;
}

int
socket_server_bind(struct socket_server *ss, uintptr_t opaque, int fd) {
	struct request_package request;
	int id = reserve_id(ss);
	if (id < 0)
		return -1;
	request.u.bind.opaque = opaque;
	request.u.bind.id = id;
	request.u.bind.fd = fd;
	send_request(ss, &request, 'B', sizeof(request.u.bind));
	return id;
}

void 
socket_server_start(struct socket_server *ss, uintptr_t opaque, int id) {
	struct request_package request;
	request.u.start.id = id;
	request.u.start.opaque = opaque;
	send_request(ss, &request, 'S', sizeof(request.u.start));
}

void
socket_server_nodelay(struct socket_server *ss, int id) {
	struct request_package request;
	request.u.setopt.id = id;
	request.u.setopt.what = TCP_NODELAY;
	request.u.setopt.value = 1;
	send_request(ss, &request, 'T', sizeof(request.u.setopt));
}

void 
socket_server_userobject(struct socket_server *ss, struct socket_object_interface *soi) {
	ss->soi = *soi;
}

// UDP

int 
socket_server_udp(struct socket_server *ss, uintptr_t opaque, const char * addr, int port) {
    int fd = 0;
	int family;
	if (port != 0 || addr != NULL) {
		// bind
        family = AF_INET;
        fd = socket(family, SOCK_DGRAM, 0);
        struct sockaddr_in local_addr;
        memset(&local_addr, 0, sizeof(struct sockaddr_in));
        local_addr.sin_family = AF_INET;
        local_addr.sin_port = (uint16_t)((((uint16_t)(port) & 0xff00) >> 8) | (((uint16_t)(port) & 0x00ff) << 8));
        if (addr != NULL)
            local_addr.sin_addr.S_un.S_addr = inet_addr(addr);
        bind(fd, (struct sockaddr *)(&local_addr), sizeof(struct sockaddr_in));
		
        //fd = -1;// do_bind(addr, port, IPPROTO_UDP, &family);
		if (fd < 0) {
			return -1;
		}
	} else {
		family = AF_INET;
		fd = socket(family, SOCK_DGRAM, 0);
		if (fd < 0) {
			return -1;
		}
	}

	int id = reserve_id(ss);
	if (id < 0) {
		close(fd);
		return -1;
	}
	struct request_package request;
	request.u.udp.id = id;
	request.u.udp.fd = fd;
	request.u.udp.opaque = opaque;
	request.u.udp.family = family;

	send_request(ss, &request, 'U', sizeof(request.u.udp));	
	return id;
}

int64_t 
socket_server_udp_send(struct socket_server *ss, int id, const struct socket_udp_address *addr, const void *buffer, int sz) {
	struct socket * s = &ss->slot[HASH_ID(id)];
	if (s->id != id || s->type == SOCKET_TYPE_INVALID) {
		return -1;
	}

	struct request_package request;
	request.u.send_udp.send.id = id;
	request.u.send_udp.send.sz = sz;
	request.u.send_udp.send.buffer = (char *)buffer;

	const uint8_t *udp_address = (const uint8_t *)addr;
	int addrsz;
	switch (udp_address[0]) {
	case PROTOCOL_UDP:
		addrsz = 1+2+4;		// 1 type, 2 port, 4 ipv4
		break;
	case PROTOCOL_UDPv6:
		addrsz = 1+2+16;	// 1 type, 2 port, 16 ipv6
		break;
	default:
		return -1;
	}

	memcpy(request.u.send_udp.address, udp_address, addrsz);	

	send_request(ss, &request, 'A', sizeof(request.u.send_udp.send)+addrsz);
	return s->wb_size;
}

int
socket_server_udp_connect(struct socket_server *ss, int id, const char * addr, int port) {
	int status;
	struct addrinfo ai_hints;
	struct addrinfo *ai_list = NULL;
	char portstr[16];
    sprintf(portstr, "%d", port);
	memset( &ai_hints, 0, sizeof( ai_hints ) );
	ai_hints.ai_family = AF_UNSPEC;
	ai_hints.ai_socktype = SOCK_DGRAM;
	ai_hints.ai_protocol = IPPROTO_UDP;

	status = getaddrinfo(addr, portstr, &ai_hints, &ai_list );
	if ( status != 0 ) {
		return -1;
	}
	struct request_package request;
	request.u.set_udp.id = id;
	int protocol;

	if (ai_list->ai_family == AF_INET) {
		protocol = PROTOCOL_UDP;
	} else if (ai_list->ai_family == AF_INET6) {
		protocol = PROTOCOL_UDPv6;
	} else {
		freeaddrinfo( ai_list );
		return -1;
	}

	int addrsz = gen_udp_address(protocol, (union sockaddr_all *)ai_list->ai_addr, request.u.set_udp.address);

	freeaddrinfo( ai_list );

	send_request(ss, &request, 'C', sizeof(request.u.set_udp) - sizeof(request.u.set_udp.address) +addrsz);

	return 0;
}

const struct socket_udp_address *
socket_server_udp_address(struct socket_server *ss, struct socket_message *msg, int *addrsz) {
	uint8_t * address = (uint8_t *)(msg->data + msg->ud);
	int type = address[0];
	switch(type) {
	case PROTOCOL_UDP:
		*addrsz = 1+2+4;
		break;
	case PROTOCOL_UDPv6:
		*addrsz = 1+2+16;
		break;
	default:
		return NULL;
	}
	return (const struct socket_udp_address *)address;
}
