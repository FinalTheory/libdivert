#include "drop.h"


static void
drop_pipe_insert(pipe_node_t *node,
                      emulator_packet_t *packet) {
    emulator_config_t *config = node->config;
    drop_pipe_t *pipe = container_of(node, drop_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    do {
        if (packet->label != NEW_PACKET) { break; }

        if (!apply_ip_filter(node->ip_filter, &packet->headers)) { break; }

        if (!apply_size_filter(node->size_filter,
                               packet->headers.size_payload)) { break; }

        double drop_rate;
        if (pipe->t != NULL) {
            // time driven mode:
            // drop rate is calculated by a function
            drop_rate = calc_val_by_time(pipe->t,
                                         pipe->drop_rate,
                                         node->num, &node->p,
                                         &node->tv_start);
        } else {
            // event driven mode:
            // drop rate is specified for each packet
            drop_rate = pipe->drop_rate[node->p];
            node->p = (node->p + 1) % node->num;
        }
        if (drop_rate < rand_double()) { break; }
        // just drop this packet, free the memory
        // as if we did not receive this packet
        divert_mem_free(config->pool, packet->ip_data);
        divert_mem_free(config->pool, packet);
        return;
    } while (0);
    next_pipe_insert(node->next, packet);
}

static void
drop_pipe_free(pipe_node_t *node) {
    emulator_free_ip_filter(node->ip_filter);
    emulator_free_size_filter(node->size_filter);
    drop_pipe_t *pipe = container_of(node, drop_pipe_t, node);
    CHECK_AND_FREE(pipe->t)
    CHECK_AND_FREE(pipe->drop_rate)
    CHECK_AND_FREE(pipe)
}

pipe_node_t *
drop_pipe_create(packet_ip_filter *ip_filter,
                 packet_size_filter *size_filter,
                 size_t num, float *t,
                 float *drop_rate) {
    drop_pipe_t *pipe = calloc(1, sizeof(drop_pipe_t));
    pipe_node_t *node = &pipe->node;

    if (t != NULL) {
        MALLOC_AND_COPY(pipe->t, t, num, float)
    } else {
        pipe->t = NULL;
    }
    MALLOC_AND_COPY(pipe->drop_rate, drop_rate, num, float)

    node->pipe_type = PIPE_DROP;
    node->insert = drop_pipe_insert;
    node->free = drop_pipe_free;
    node->process = NULL;
    node->clear = NULL;

    node->p = 0;
    node->num = num;
    node->ip_filter = ip_filter;
    node->size_filter = size_filter;

    return node;
}
