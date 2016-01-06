#include "duplicate.h"
#include <string.h>


static void
duplicate_pipe_insert(pipe_node_t *node,
                      emulator_packet_t *packet) {
    duplicate_pipe_t *pipe = container_of(node, duplicate_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    /*
     * packet duplicate stage
     */
    do {
        if (packet->label != NEW_PACKET) { break; }
        if (!is_effect_applied(node->size_filter,
                               packet->headers.size_payload)) { break; }
        if (calc_val_by_time(pipe->t,
                             pipe->dup_rate,
                             node->num, &node->p,
                             &node->tv_start) < rand_double()) { break; }
        // random repeat times, could be zero
        size_t times = rand() % pipe->max_duplicate;
        for (size_t i = 0; i < times; i++) {
            emulator_packet_t *new_packet = calloc(1, sizeof(emulator_packet_t));
            *new_packet = *packet;
            MALLOC_AND_COPY(new_packet->ip_data, packet->ip_data,
                            ntohs(packet->ip_data->ip_len), u_char)
            // just insert the packet into next pipe is OK
            next_pipe_insert(node->next, new_packet);
        }
    } while (0);
    next_pipe_insert(node->next, packet);
}

static void
duplicate_pipe_free(pipe_node_t *node) {
    duplicate_pipe_t *pipe = container_of(node, duplicate_pipe_t, node);
    CHECK_AND_FREE(pipe->t)
    CHECK_AND_FREE(pipe->dup_rate)
    CHECK_AND_FREE(pipe)
}

pipe_node_t *
duplicate_pipe_create(packet_size_filter *filter,
                      size_t num, float *t,
                      float *dup_rate,
                      size_t max_duplicate) {
    duplicate_pipe_t *pipe = calloc(1, sizeof(duplicate_pipe_t));
    pipe_node_t *node = &pipe->node;

    MALLOC_AND_COPY(pipe->t, t, num, float)
    MALLOC_AND_COPY(pipe->dup_rate, dup_rate, num, float)
    pipe->max_duplicate = max_duplicate;

    node->pipe_type = PIPE_DUPLICATE;
    node->insert = duplicate_pipe_insert;
    node->free = duplicate_pipe_free;
    node->process = NULL;
    node->clear = NULL;

    node->p = 0;
    node->num = num;
    node->size_filter = filter;

    return node;
}
