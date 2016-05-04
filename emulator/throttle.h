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

pipe_node_t *
throttle_pipe_create(packet_ip_filter *ip_filter,
                     packet_size_filter *size_filter,
                     size_t num,
                     float *t_start,
                     float *t_end,
                     size_t queue_size);

#endif //DIVERT_THROTTLE_H
