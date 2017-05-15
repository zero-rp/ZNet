#include "skynet.h"

struct gate;

struct gate *gate_create(void);
void gate_release(struct gate *g);
int gate_init(struct gate *g, struct skynet_context * ctx, char * parm);
