#include "emulator.h"
#include "bandwidth.h"


static void
bandwidth_pipe_insert(pipe_node_t *node,
                      emulator_packet_t *packet) {
    struct timezone tz;
    bandwidth_pipe_t *pipe = container_of(node, bandwidth_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    do {
        if (packet->label != NEW_PACKET) { break; }
        if (!check_direction(node->direction,
                             packet->direction)) { break; }
        // if buffer is full, just drop this packet
        if (circ_buf_is_full(pipe->buffer)) {
            CHECK_AND_FREE(packet->ip_data)
            CHECK_AND_FREE(packet)
            return;
        }
        // calculate current bandwidth (KB/s to Byte/s)
        double bandwidth = calc_val_by_time(pipe->t,
                                            pipe->bandwidth,
                                            node->num, &node->p,
                                            &node->tv_start) * 1024.;

        // calculate the desired send time
        size_t size_payload = packet->headers.size_payload;
        double time_delta = (double)size_payload / bandwidth;
        struct timeval time_send = pipe->prev_send;
        time_add(&time_send, time_delta);

        // see if we should send this packet right now
        struct timeval time_now;
        gettimeofday(&time_now, &tz);
        if (time_greater_than(&time_now, &time_send)) { break; }

        // if not, insert it into buffer
        bandwidth_packet_t *ptr =
                malloc(sizeof(bandwidth_packet_t));
        ptr->packet = packet;
        ptr->time_send = time_send;
        ptr->is_registered = 0;

        // insert packet into delay queue and finish processing
        circ_buf_insert(pipe->buffer, ptr);
        // update time stamp to the calculated send time
        pipe->prev_send = time_send;
        return;
    } while (0);
    // update time stamp of previous sent packet
    next_pipe_insert(node->next, packet);
    gettimeofday(&pipe->prev_send, &tz);
}

static void
bandwidth_pipe_process(pipe_node_t *node) {
    bandwidth_pipe_t *pipe = container_of(node, bandwidth_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    while (circ_buf_size(pipe->buffer) > 0) {
        bandwidth_packet_t *ptr = circ_buf_head(pipe->buffer);
        if (!ptr->is_registered) {
            // register timeout event
            register_timer(node, &ptr->time_send,
                           TIMEOUT_EVENT);
            ptr->is_registered = 1;
        }
        // then send them to next pipe
        ptr = circ_buf_remove(pipe->buffer);
        // do not update the previous send time here
        next_pipe_insert(node->next, ptr->packet);
        CHECK_AND_FREE(ptr)
    }
}

static void
bandwidth_pipe_clear(pipe_node_t *node) {
    bandwidth_pipe_t *pipe = container_of(node, bandwidth_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    while (circ_buf_size(pipe->buffer) > 0) {
        bandwidth_packet_t *ptr = circ_buf_head(pipe->buffer);
        next_pipe_insert(node->next, ptr->packet);
        CHECK_AND_FREE(ptr)
    }
}

pipe_node_t *bandwidth_pipe_create(size_t num, float *t,
                                   float *bandwidth,
                                   int direction,
                                   size_t queue_size) {
    bandwidth_pipe_t *pipe = calloc(1, sizeof(bandwidth_pipe_t));
    pipe_node_t *node = &pipe->node;

    struct timezone tz;
    gettimeofday(&pipe->prev_send, &tz);

    pipe->t = t;
    pipe->bandwidth = bandwidth;
    pipe->buffer = circ_buf_create(queue_size);

    node->pipe_type = PIPE_REINJECT;
    node->process = bandwidth_pipe_process;
    node->insert = bandwidth_pipe_insert;
    node->clear = bandwidth_pipe_clear;

    node->p = 0;
    node->num = num;
    node->direction = direction;

    return node;
}
