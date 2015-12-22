#ifndef DIVERT_BITERR_H
#define DIVERT_BITERR_H

#include "emulator.h"

typedef struct {
    pipe_node_t node;
    float *t;
    float *err_exp;
} biterr_pipe_t;


#endif //DIVERT_BITERR_H
