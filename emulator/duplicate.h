#ifndef DIVERT_DUPLICATE_H
#define DIVERT_DUPLICATE_H

#include "emulator.h"

typedef struct {
    pipe_node_t node;
    float *t;
    float *dup_rate;

    size_t max_duplicate;
} duplicate_pipe_t;


#endif //DIVERT_DUPLICATE_H
