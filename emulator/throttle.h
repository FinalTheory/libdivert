#ifndef DIVERT_THROTTLE_H
#define DIVERT_THROTTLE_H

#include "emulator.h"
#include "delay.h"

typedef delay_packet_t throttle_packet_t;

typedef struct {
    pipe_node_t node;
    float *t_start;
    float *t_end;
    circ_buf_t *throttle_queue;
} throttle_pipe_t;

#endif //DIVERT_THROTTLE_H
