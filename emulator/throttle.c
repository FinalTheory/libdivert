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

static void
throttle_pipe_insert(pipe_node_t *node,
                     emulator_packet_t *packet) {
    emulator_config_t *config = node->config;
    throttle_pipe_t *pipe = container_of(node, throttle_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    do {
        double delay_time;
        if (packet->label != NEW_PACKET) { break; }

        if (!apply_ip_filter(node->ip_filter, &packet->headers)) { break; }

        if (!apply_size_filter(node->size_filter,
                               packet->headers.size_payload)) { break; }

        if ((delay_time = calc_do_throttle(pipe->t_start,
                                           pipe->t_end,
                                           node->num, &node->p,
                                           &node->tv_start)) < 0.) { break; }
        // if buffer full, also quit
        if (circ_buf_is_full(pipe->throttle_queue)) { break; }

        throttle_packet_t *ptr =
                divert_mem_alloc(config->pool,
                                 sizeof(throttle_packet_t));
        ptr->is_registered = 0;
        ptr->packet = packet;
        ptr->time_send = node->tv_start;
        time_add(&ptr->time_send, delay_time);
        circ_buf_insert(pipe->throttle_queue, ptr);
        return;
    } while (0);
    next_pipe_insert(node->next, packet);
}

static void
throttle_pipe_process(pipe_node_t *node) {
    emulator_config_t *config = node->config;
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
                register_timer(node, &ptr->time_send,
                               ptr->packet->direction);
                ptr->is_registered = 1;
            }
            break;
        }
        // then send them to next pipe
        ptr = circ_buf_remove(pipe->throttle_queue);
        next_pipe_insert(node->next, ptr->packet);
        divert_mem_free(config->pool, ptr);
    }
}

static void
throttle_pipe_clear(pipe_node_t *node) {
    emulator_config_t *config = node->config;
    throttle_pipe_t *pipe = container_of(node, throttle_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    // send out all timeout packets
    while (circ_buf_size(pipe->throttle_queue) > 0) {
        throttle_packet_t *ptr = circ_buf_remove(pipe->throttle_queue);
        next_pipe_insert(node->next, ptr->packet);
        divert_mem_free(config->pool, ptr);
    }
}

static void
throttle_pipe_free(pipe_node_t *node) {
    emulator_free_ip_filter(node->ip_filter);
    emulator_free_size_filter(node->size_filter);
    throttle_pipe_t *pipe = container_of(node, throttle_pipe_t, node);
    circ_buf_destroy(pipe->throttle_queue);
    CHECK_AND_FREE(pipe->t_start)
    CHECK_AND_FREE(pipe->t_end)
    CHECK_AND_FREE(pipe)
}

pipe_node_t *
throttle_pipe_create(packet_ip_filter *ip_filter,
                     packet_size_filter *size_filter,
                     size_t num,
                     float *t_start,
                     float *t_end,
                     size_t queue_size) {
    throttle_pipe_t *pipe = calloc(1, sizeof(throttle_pipe_t));
    pipe_node_t *node = &pipe->node;

    MALLOC_AND_COPY(pipe->t_start, t_start, num, float)
    MALLOC_AND_COPY(pipe->t_end, t_end, num, float)
    pipe->throttle_queue = circ_buf_create(queue_size);

    node->pipe_type = PIPE_THROTTLE;
    node->insert = throttle_pipe_insert;
    node->process = throttle_pipe_process;
    node->clear = throttle_pipe_clear;
    node->free = throttle_pipe_free;

    node->p = 0;
    node->num = num;
    node->ip_filter = ip_filter;
    node->size_filter = size_filter;

    return node;
}
