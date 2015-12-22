#include "duplicate.h"


void duplicate_pipe_insert(pipe_node_t *node,
                           emulator_packet_t *packet) {
    duplicate_pipe_t *pipe = container_of(node, duplicate_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    /*
     * packet duplicate stage
     */
    do {
        if (packet->label != NEW_PACKET) { break; }
        if (!check_direction(node->direction, packet->direction)) { break; }
        if (calc_val_by_time(pipe->t,
                             pipe->dup_rate,
                             node->num, &node->p,
                             &node->tv_start) < rand_double()) { break; }
        size_t times = rand() % pipe->max_duplicate;
        for (size_t i = 0; i < times; i++) {
            // just insert the packet into next pipe is OK
            next_pipe_insert(node->next, packet);
        }
    } while (0);
    next_pipe_insert(node->next, packet);
}

void duplicate_pipe_process(pipe_node_t *node) {
    // do nothing here
}
