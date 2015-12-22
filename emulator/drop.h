#ifndef DIVERT_DROP_H
#define DIVERT_DROP_H

#include "emulator.h"

typedef struct {
    pipe_node_t node;
    float *t;
    float *drop_rate;
} drop_pipe_t;


#endif //DIVERT_DROP_H
