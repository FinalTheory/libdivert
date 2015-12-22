#include "throttle.h"

static double
calc_do_throttle(float *t1, float *t2,
                 ssize_t n, ssize_t *p,
                 struct timeval *tv_start) {

    // guard here to avoid invalid memory access
    if (t1 == NULL || t2 == NULL) {
        return -1.;
    }

    struct timeval tv;
    struct timezone tz;
    double ret_val = -1.;
    gettimeofday(&tv, &tz);

    double end_time = t2[n - 1];
    double t_now = time_minus(&tv, tv_start);
    if (t_now >= end_time) {
        long k = (long)(t_now / end_time);
        // then reset it to beginning
        time_add(tv_start, end_time * k);
        t_now -= end_time * k;
        *p = 0;
    }

    while (*p < n) {
        if (t_now < t1[*p]) {
            break;
        } else if (t1[*p] <= t_now && t_now <= t2[*p]) {
            ret_val = t2[*p];
            break;
        } else {
            (*p)++;
        }
    }

    return ret_val;
}

void throttle_pipe_insert(pipe_node_t *node,
                          emulator_packet_t *packet) {
    /*
     * packet throttle stage
     */
    throttle_pipe_t *pipe = container_of(node, throttle_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;
    do {
        if (packet->label != NEW_PACKET) { break; }
        double delay_time;
        if (!check_direction(node->direction,
                             packet->direction)) { break; }
        if ((delay_time = calc_do_throttle(pipe->t_start,
                                           pipe->t_end,
                                           node->num, &node->p,
                                           &node->tv_start)) < 0.) { break; }
        // if buffer full, also quit
        if (circ_buf_is_full(pipe->throttle_queue)) { break; }

        throttle_packet_t *ptr = malloc(sizeof(throttle_packet_t));
        ptr->is_registered = 0;
        ptr->packet = packet;
        ptr->time_send = node->tv_start;
        time_add(&ptr->time_send, delay_time);
        circ_buf_insert(pipe->throttle_queue, ptr);
        return;
    } while (0);
    next_pipe_insert(node->next, packet);
}

void throttle_pipe_process(pipe_node_t *node) {
    throttle_pipe_t *pipe = container_of(node, throttle_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    struct timeval time_now;
    struct timezone tz;

    throttle_packet_t *ptr = NULL;

    gettimeofday(&time_now, &tz);
    // send out all timeout packets
    while (circ_buf_size(pipe->throttle_queue) > 0) {
        ptr = circ_buf_head(pipe->throttle_queue);
        if (time_greater_than(&ptr->time_send, &time_now)) {
            if (!ptr->is_registered) {
                register_timer(node, &ptr->time_send, TIMEOUT_EVENT);
                ptr->is_registered = 1;
            }
            break;
        }
        // then send them to next pipe
        ptr = circ_buf_remove(pipe->throttle_queue);
        next_pipe_insert(node->next, ptr->packet);
        CHECK_AND_FREE(ptr)
    }
}
