//
// Created by baidu on 15/12/20.
//

#ifndef DIVERT_BANDWIDTH_H
#define DIVERT_BANDWIDTH_H

#include "emulator.h"

typedef struct {
    pipe_node_t node;

    float *t;
    float *bandwidth;
    circ_buf_t *buffer;
} limit_pipe_t;

#endif //DIVERT_BANDWIDTH_H
