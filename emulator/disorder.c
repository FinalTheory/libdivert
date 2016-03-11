#include "disorder.h"
#include <string.h>


static int
cmp_disorder_packet(const void *x, const void *y) {
    const disorder_packet_t *a = x;
    const disorder_packet_t *b = y;
    if (a->time_send > b->time_send) {
        return -1;
    } else if (a->time_send < b->time_send) {
        return 1;
    } else {
        return 0;
    }
}

static void
disorder_pipe_insert(pipe_node_t *node,
                          emulator_packet_t *packet) {
    emulator_config_t *config = node->config;
    disorder_pipe_t *pipe = container_of(node, disorder_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    do {
        // do not process this packet if this is a timeout signal
        if (packet->label != NEW_PACKET) { break; }
        // update packet counter
        pipe->packet_cnt[packet->direction]++;
        // then check packet size
        if (!is_effect_applied(node->size_filter,
                               packet->headers.size_payload)) { break; }
        // calculate rate
        if (calc_val_by_time(pipe->t,
                             pipe->disorder_rate,
                             node->num, &node->p,
                             &node->tv_start) < rand_double()) { break; }
        // get the corresponding packet queue
        pqueue *disorder_queue = pipe->disorder_queue[packet->direction];
        // check if there is empty slot in queue
        if (pqueue_is_full(disorder_queue)) { break; }

        disorder_packet_t *ptr =
                divert_mem_alloc(config->pool,
                                 sizeof(disorder_packet_t));
        ptr->packet = packet;
        ptr->time_send = (rand() % pipe->max_disorder + 1) +
                         pipe->packet_cnt[packet->direction];

        // insert packet into disorder queue and finish processing
        pqueue_enqueue(disorder_queue, ptr);
        return;
    } while (0);
    next_pipe_insert(node->next, packet);
}

static void
disorder_pipe_process(pipe_node_t *node) {
    emulator_config_t *config = node->config;
    disorder_pipe_t *pipe = container_of(node, disorder_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    // move inbound/outbound disorder packets into next pipe
    for (int q = 0; q < 2; q++) {
        pqueue *disorder_queue =
                pipe->disorder_queue[q];
        while (pqueue_size(disorder_queue) > 0) {
            disorder_packet_t *ptr = pqueue_head(disorder_queue);
            int direction = ptr->packet->direction;
            if (ptr->time_send > pipe->packet_cnt[direction]) {
                break;
            }
            ptr = pqueue_dequeue(disorder_queue);
            next_pipe_insert(node->next, ptr->packet);
            divert_mem_free(config->pool, ptr);
        }
    }
}

static void
disorder_pipe_clear(pipe_node_t *node) {
    emulator_config_t *config = node->config;
    disorder_pipe_t *pipe = container_of(node, disorder_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    for (int q = 0; q < 2; q++) {
        pqueue *disorder_queue =
                pipe->disorder_queue[q];
        while (pqueue_size(disorder_queue) > 0) {
            disorder_packet_t *ptr = pqueue_dequeue(disorder_queue);
            next_pipe_insert(node->next, ptr->packet);
            divert_mem_free(config->pool, ptr);
        }
    }
}

static void
disorder_pipe_free(pipe_node_t *node) {
    emulator_free_size_filter(node->size_filter);
    disorder_pipe_t *pipe = container_of(node, disorder_pipe_t, node);
    CHECK_AND_FREE(pipe->t)
    CHECK_AND_FREE(pipe->disorder_rate)
    pqueue_destroy(pipe->disorder_queue[0]);
    pqueue_destroy(pipe->disorder_queue[1]);
    CHECK_AND_FREE(pipe)
}

pipe_node_t *
disorder_pipe_create(packet_size_filter *filter,
                     size_t num, float *t,
                     float *disorder_rate,
                     size_t queue_size,
                     int max_disorder) {
    disorder_pipe_t *pipe = calloc(1, sizeof(disorder_pipe_t));
    pipe_node_t *node = &pipe->node;

    MALLOC_AND_COPY(pipe->t, t, num, float)
    MALLOC_AND_COPY(pipe->disorder_rate, disorder_rate, num, float)
    pipe->disorder_queue[0] = pqueue_new(cmp_disorder_packet, queue_size);
    pipe->disorder_queue[1] = pqueue_new(cmp_disorder_packet, queue_size);
    pipe->packet_cnt[0] = 0;
    pipe->packet_cnt[1] = 0;
    pipe->max_disorder = max_disorder;

    node->pipe_type = PIPE_DISORDER;
    node->process = disorder_pipe_process;
    node->insert = disorder_pipe_insert;
    node->clear = disorder_pipe_clear;
    node->free = disorder_pipe_free;

    node->p = 0;
    node->num = num;
    node->size_filter = filter;

    return node;
}
