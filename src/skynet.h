#ifndef SKYNET_H
#define SKYNET_H

#include <stddef.h>
#include <stdint.h>

#if defined(WIN32) || defined(WIN64)
# if defined(BUILDING)
/* Building shared library. */
#   define SKYNET_EXTERN __declspec(dllexport)
# elif defined(USING)
/* Using shared library. */
#   define SKYNET_EXTERN __declspec(dllimport)
# else
/* Building static library. */
#   define SKYNET_EXTERN /* nothing */
# endif
#elif __GNUC__ >= 4
# define SKYNET_EXTERN __attribute__((visibility("default")))
#else
# define SKYNET_EXTERN /* nothing */
#endif

#define PTYPE_TEXT 0
#define PTYPE_RESPONSE 1
#define PTYPE_MULTICAST 2
#define PTYPE_CLIENT 3
#define PTYPE_SYSTEM 4
#define PTYPE_HARBOR 5
#define PTYPE_SOCKET 6
// read lualib/skynet.lua examples/simplemonitor.lua
#define PTYPE_ERROR 7	
// read lualib/skynet.lua lualib/mqueue.lua lualib/snax.lua
#define PTYPE_RESERVED_QUEUE 8
#define PTYPE_RESERVED_DEBUG 9
#define PTYPE_RESERVED_LUA 10
#define PTYPE_RESERVED_SNAX 11

#define PTYPE_TAG_DONTCOPY 0x10000
#define PTYPE_TAG_ALLOCSESSION 0x20000

struct skynet_context;

SKYNET_EXTERN void skynet_error(struct skynet_context * context, const char *msg, ...);
SKYNET_EXTERN const char * skynet_command(struct skynet_context * context, const char * cmd , const char * parm);
SKYNET_EXTERN uint32_t skynet_queryname(struct skynet_context * context, const char * name);
SKYNET_EXTERN int skynet_send(struct skynet_context * context, uint32_t source, uint32_t destination , int type, int session, void * msg, size_t sz);
SKYNET_EXTERN int skynet_sendname(struct skynet_context * context, uint32_t source, const char * destination , int type, int session, void * msg, size_t sz);

SKYNET_EXTERN int skynet_isremote(struct skynet_context *, uint32_t handle, int * harbor);

SKYNET_EXTERN typedef int (*skynet_cb)(struct skynet_context * context, void *ud, int type, int session, uint32_t source , const void * msg, size_t sz);
SKYNET_EXTERN void skynet_callback(struct skynet_context * context, void *ud, skynet_cb cb);

SKYNET_EXTERN uint32_t skynet_current_handle(void);
SKYNET_EXTERN uint64_t skynet_now(void);
SKYNET_EXTERN void skynet_debug_memory(const char *info);	// for debug use, output current service memory to stderr
#if defined(WIN32) || defined(WIN64)
SKYNET_EXTERN void usleep(uint32_t us);
SKYNET_EXTERN char *strsep(char **s, const char *ct);
#endif


#include <stddef.h>
#include <malloc.h>
#ifdef NOUSE_JEMALLOC
#define skynet_malloc malloc
#define skynet_calloc calloc
#define skynet_realloc realloc
#define skynet_free free
#else
SKYNET_EXTERN void * skynet_malloc(size_t sz);
SKYNET_EXTERN void * skynet_calloc(size_t nmemb, size_t size);
SKYNET_EXTERN void * skynet_realloc(void *ptr, size_t size);
SKYNET_EXTERN void skynet_free(void *ptr);
#endif
SKYNET_EXTERN char * skynet_strdup(const char *str);
SKYNET_EXTERN void * skynet_lalloc(void *ptr, size_t osize, size_t nsize);	// use for lua

#endif
