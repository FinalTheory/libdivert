#include "biterr.h"
#include "emulator.h"


void biterr_pipe_insert(pipe_node_t *node,
                        emulator_packet_t *packet) {
    biterr_pipe_t *pipe = container_of(node, biterr_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    /*
                 * packet tamper stage
                 */
    do {
        if (packet->label != NEW_PACKET) { break; }
        emulator_config_t *config = node->config;
        int num_flip = 0;
        if (!check_direction(node->direction,
                             packet->direction)) { break; }
        // only apply for packets with payload
        if (packet->headers.size_payload <= 0) { break; }
        if ((num_flip = (int)
                calc_val_by_time(pipe->t,
                                 pipe->err_exp,
                                 node->num, &node->p,
                                 &node->tv_start)) < 1) { break; }
        // randomly flip some bits of payload data
        for (int i = 0; i < num_flip; i++) {
            size_t idx = rand() %
                         (packet->headers.size_payload * BITS_PER_BYTE);
            packet->headers.payload[idx / BITS_PER_BYTE]
                    ^= (u_char)(1u << (BITS_PER_BYTE - idx % BITS_PER_BYTE - 1));
        }
        // if this is a TCP or UDP packet
        // we should re-calculate the checksum
        if (config->flags & EMULATOR_RECHECKSUM) {
            divert_checksum(packet->ip_data);
        }
        next_pipe_insert(node->next, packet);
    } while (0);

    next_pipe_insert(node->next, packet);
}

void biterr_pipe_process(pipe_node_t *node) {
    // still do nothing here
}
