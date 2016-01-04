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
        if (!check_direction(node->direction,
                             packet->direction)) { break; }
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

pipe_node_t *
duplicate_pipe_create(size_t num, float *t,
                      float *dup_rate,
                      int direction,
                      size_t max_duplicate) {
    duplicate_pipe_t *pipe = calloc(1, sizeof(duplicate_pipe_t));
    pipe_node_t *node = &pipe->node;

    pipe->t = t;
    pipe->dup_rate = dup_rate;
    pipe->max_duplicate = max_duplicate;

    node->pipe_type = PIPE_DUPLICATE;
    node->insert = duplicate_pipe_insert;
    node->process = NULL;
    node->clear = NULL;

    node->p = 0;
    node->num = num;
    node->direction = direction;

    return node;
}
