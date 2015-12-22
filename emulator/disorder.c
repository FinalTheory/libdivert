#include "disorder.h"

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

void disorder_pipe_insert(pipe_node_t *node,
                          emulator_packet_t *packet) {
    disorder_pipe_t *pipe = container_of(node, disorder_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    /*
     * packet disorder stage
     */
    do {
        // do not process this packet if this is a signal
        if (packet->label != NEW_PACKET) { break; }

        // first update packet counter
        pipe->packet_cnt[packet->direction]++;
        PQueue *disorder_queue = pipe->disorder_queue[packet->direction];

        if (!check_direction(node->direction,
                             packet->direction)) { break; }
        if (calc_val_by_time(pipe->t,
                             pipe->disorder_rate,
                             node->num, &node->p,
                             &node->tv_start) < rand_double()) {
            break;
        }
        // check if there is empty slot in queue
        if (pqueue_is_full(disorder_queue)) { break; }
        // check if this is a known direction
        if (packet->direction == DIRECTION_UNKNOWN) { break; }

        disorder_packet_t *ptr =
                malloc(sizeof(disorder_packet_t));
        ptr->packet = packet;
        ptr->time_send = rand() % pipe->max_disorder +
                         pipe->packet_cnt[packet->direction];

        // insert packet into disorder queue and finish processing
        pqueue_enqueue(disorder_queue, ptr);
        return;
    } while (0);
    next_pipe_insert(node->next, packet);
}

void disorder_pipe_process(pipe_node_t *node) {
    disorder_pipe_t *pipe = container_of(node, disorder_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    // move inbound/outbound disorder packets into next pipe
    for (int q = 0; q < 2; q++) {
        PQueue *disorder_queue =
                pipe->disorder_queue[q];
        while (pqueue_size(disorder_queue) > 0) {
            disorder_packet_t *ptr = pqueue_head(disorder_queue);
            int direction = ptr->packet->direction;
            if (ptr->time_send > pipe->packet_cnt[direction]) {
                break;
            }
            ptr = pqueue_dequeue(disorder_queue);
            next_pipe_insert(node->next, ptr->packet);
            CHECK_AND_FREE(ptr)
        }
    }
}