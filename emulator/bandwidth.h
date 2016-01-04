#ifndef DIVERT_BANDWIDTH_H
#define DIVERT_BANDWIDTH_H

#include "emulator.h"
#include "delay.h"

typedef struct {
    pipe_node_t node;
    float *t;
    float *bandwidth;
    struct timeval prev_send;
    circ_buf_t *buffer;
} bandwidth_pipe_t;

typedef delay_packet_t bandwidth_packet_t;

pipe_node_t *
bandwidth_pipe_create(size_t num, float *t,
                      float *bandwidth,
                      int direction,
                      size_t queue_size);

#endif //DIVERT_BANDWIDTH_H
