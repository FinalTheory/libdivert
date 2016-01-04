#ifndef DIVERT_DROP_H
#define DIVERT_DROP_H


#include "emulator.h"

typedef struct {
    pipe_node_t node;
    float *t;
    float *drop_rate;
} drop_pipe_t;

pipe_node_t *
drop_pipe_create(size_t num, float *t,
                 float *drop_rate,
                 int direction);

#endif //DIVERT_DROP_H
