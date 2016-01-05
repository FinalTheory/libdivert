#include "drop.h"


static void
drop_pipe_insert(pipe_node_t *node,
                      emulator_packet_t *packet) {
    drop_pipe_t *pipe = container_of(node, drop_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    do {
        if (packet->label != NEW_PACKET) { break; }
        if (!is_effect_applied(node->size_filter,
                               packet->headers.size_payload)) { break; }
        if (calc_val_by_time(pipe->t,
                             pipe->drop_rate,
                             node->num, &node->p,
                             &node->tv_start) < rand_double()) { break; }
        // just drop this packet, free the memory
        // as if we did not receive this packet
        CHECK_AND_FREE(packet->ip_data)
        CHECK_AND_FREE(packet)
        return;
    } while (0);
    next_pipe_insert(node->next, packet);
}

pipe_node_t *
drop_pipe_create(packet_size_filter *filter,
                 size_t num, float *t,
                 float *drop_rate) {
    drop_pipe_t *pipe = calloc(1, sizeof(drop_pipe_t));
    pipe_node_t *node = &pipe->node;

    pipe->t = t;
    pipe->drop_rate = drop_rate;

    node->pipe_type = PIPE_DROP;
    node->insert = drop_pipe_insert;
    node->process = NULL;
    node->clear = NULL;

    node->p = 0;
    node->num = num;
    node->size_filter = filter;

    return node;
}
