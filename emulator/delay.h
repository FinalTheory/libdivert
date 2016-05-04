#ifndef DIVERT_DELAY_H
#define DIVERT_DELAY_H

#include "emulator.h"

typedef struct {
    pipe_node_t node;
    float *t;
    float *delay_time;
    pqueue *delay_queue;
} delay_pipe_t;

typedef struct {
    emulator_packet_t *packet;
    struct timeval time_send;
    u_char is_registered;
} delay_packet_t;

pipe_node_t *delay_pipe_create(packet_ip_filter *ip_filter,
                               packet_size_filter *size_filter,
                               size_t num, float *t,
                               float *delay_time,
                               size_t queue_size);

#endif //DIVERT_DELAY_H
