#ifndef DIVERT_REINJECT_H
#define DIVERT_REINJECT_H

#include "emulator.h"
#include <stdlib.h>


typedef struct {
    pipe_node_t node;
    divert_t *handle;
} reinject_pipe_t;

pipe_node_t *reinject_pipe_create(divert_t *handle);

#endif //DIVERT_REINJECT_H
