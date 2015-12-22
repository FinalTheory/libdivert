#include "delay.h"

static int
cmp_delay_packet(const void *x, const void *y) {
    if (x == NULL) { return 1; }
    if (y == NULL) { return -1; }
    const delay_packet_t *a = x;
    const delay_packet_t *b = y;
    uint64_t val_a = a->time_send.tv_sec *
                     (uint64_t)1000000 +
                     a->time_send.tv_usec;
    uint64_t val_b = b->time_send.tv_sec *
                     (uint64_t)1000000 +
                     b->time_send.tv_usec;
    if (val_a > val_b) {
        return -1;
    } else if (val_a < val_b) {
        return 1;
    } else {
        return 0;
    }
}

static void
delay_pipe_insert(pipe_node_t *node,
                       emulator_packet_t *packet) {
    delay_pipe_t *pipe = container_of(node, delay_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;
    /*
     * packet delay stage
     */
    do {
        if (packet->label != NEW_PACKET) { break; }

        if (!check_direction(node->direction,
                             packet->direction)) { break; }
        if (pqueue_is_full(pipe->delay_queue)) { break; }
        // break if the delay time is too short
        double delay_time = calc_val_by_time(pipe->t,
                                             pipe->delay_time,
                                             node->num, &node->p,
                                             &node->tv_start);
        if (delay_time < FLOAT_EPS) { break; }

        // calculate send time
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        time_add(&tv, delay_time);
        delay_packet_t *ptr = malloc(sizeof(delay_packet_t));
        ptr->packet = packet;
        ptr->time_send = tv;
        ptr->is_registered = 0;

        // insert packet into delay queue and finish processing
        pqueue_enqueue(pipe->delay_queue, ptr);
        return;
    } while (0);
    next_pipe_insert(node->next, packet);
}

static void
delay_pipe_process(pipe_node_t *node) {
    delay_pipe_t *pipe = container_of(node, delay_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    struct timeval time_now;
    struct timezone tz;
    delay_packet_t *ptr = NULL;

    // try to deliver all timeout packets to next pipe
    gettimeofday(&time_now, &tz);
    while (pqueue_size(pipe->delay_queue) > 0) {
        // check if there are timeout packets
        ptr = pqueue_head(pipe->delay_queue);
        if (time_greater_than(&ptr->time_send, &time_now)) {
            if (!ptr->is_registered) {
                // register timeout event
                register_timer(node, &ptr->time_send, TIMEOUT_EVENT);
                ptr->is_registered = 1;
            }
            break;
        }
        // then send them to next pipe
        ptr = pqueue_dequeue(pipe->delay_queue);
        next_pipe_insert(node->next, ptr->packet);
        CHECK_AND_FREE(ptr)
    }
}

static void
delay_pipe_clear(pipe_node_t *node) {
    delay_pipe_t *pipe = container_of(node, delay_pipe_t, node);
    delay_packet_t *ptr = NULL;
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    while (pqueue_size(pipe->delay_queue) > 0) {
        ptr = pqueue_dequeue(pipe->delay_queue);
        // send all packets into next pipe
        next_pipe_insert(node->next, ptr->packet);
        CHECK_AND_FREE(ptr)
    }
}

pipe_node_t *delay_pipe_create(size_t num, float *t,
                               float *delay_time,
                               int direction,
                               size_t queue_size) {
    delay_pipe_t *pipe = calloc(1, sizeof(delay_pipe_t));
    pipe_node_t *node = &pipe->node;

    pipe->t = t;
    pipe->delay_time = delay_time;
    pipe->delay_queue = pqueue_new(cmp_delay_packet, queue_size);

    node->pipe_type = PIPE_REINJECT;
    node->process = delay_pipe_process;
    node->insert = delay_pipe_insert;
    node->clear = delay_pipe_clear;

    node->p = 0;
    node->num = num;
    node->direction = direction;

    return node;
}
