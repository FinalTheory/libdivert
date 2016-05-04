#ifndef DIVERT_DUPLICATE_H
#define DIVERT_DUPLICATE_H

#include "emulator.h"


typedef struct {
    pipe_node_t node;
    float *t;
    float *dup_rate;

    size_t max_duplicate;
} duplicate_pipe_t;

pipe_node_t *
duplicate_pipe_create(packet_ip_filter *ip_filter,
                      packet_size_filter *size_filter,
                      size_t num, float *t,
                      float *dup_rate,
                      size_t max_duplicate);

#endif //DIVERT_DUPLICATE_H
