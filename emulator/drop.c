#include "drop.h"


void drop_pipe_insert(pipe_node_t *node,
                      emulator_packet_t *packet) {
    /*
     * packet drop stage
    */
    drop_pipe_t *pipe = container_of(node, drop_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    do {
        if (packet->label != NEW_PACKET) { break; }
        if (!check_direction(node->direction,
                             packet->direction)) { break; }
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

void drop_pipe_process(pipe_node_t *node) {
    // do nothing here
}
