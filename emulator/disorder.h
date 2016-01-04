#ifndef DIVERT_DISORDER_H
#define DIVERT_DISORDER_H

#include "emulator.h"


typedef struct {
    emulator_packet_t *packet;
    uint64_t time_send;
} disorder_packet_t;

typedef struct {
    pipe_node_t node;
    float *t;
    float *disorder_rate;
    int max_disorder;
    uint64_t packet_cnt[2];
    PQueue *disorder_queue[2];
} disorder_pipe_t;

pipe_node_t *
disorder_pipe_create(size_t num, float *t,
                     float *disorder_rate,
                     int direction,
                     size_t queue_size,
                     int max_disorder);

#endif //DIVERT_DISORDER_H
