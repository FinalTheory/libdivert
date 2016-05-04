#ifndef DIVERT_BITERR_H
#define DIVERT_BITERR_H

#include "emulator.h"

typedef struct {
    pipe_node_t node;
    float *t;
    float *biterr_rate;
    int max_flip;
} biterr_pipe_t;

pipe_node_t *
biterr_pipe_create(packet_ip_filter *ip_filter,
                   packet_size_filter *size_filter,
                   size_t num, float *t,
                   float *biterr_rate,
                   int max_flip);

#endif //DIVERT_BITERR_H
