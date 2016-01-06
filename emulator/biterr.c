#include "biterr.h"
#include <string.h>

static void
biterr_pipe_insert(pipe_node_t *node,
                   emulator_packet_t *packet) {
    biterr_pipe_t *pipe = container_of(node, biterr_pipe_t, node);
    pipe_insert_func_t next_pipe_insert = node->next->insert;

    /*
     * packet bit error pipe
     */
    do {
        if (packet->label != NEW_PACKET) { break; }
        emulator_config_t *config = node->config;

        if (!is_effect_applied(node->size_filter,
                               packet->headers.size_payload)) { break; }
        // only apply for packets with payload
        if (packet->headers.size_payload <= 0) { break; }
        if (calc_val_by_time(pipe->t,
                             pipe->biterr_rate,
                             node->num, &node->p,
                             &node->tv_start) < rand_double()) { break; }

        int num_flip = rand() % pipe->max_flip + 1;
        // randomly flip some bits of payload data
        for (int i = 0; i < num_flip; i++) {
            // is this implement correct?
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
        return;
    } while (0);

    next_pipe_insert(node->next, packet);
}

static void
biterr_pipe_free(pipe_node_t *node) {
    biterr_pipe_t *pipe = container_of(node, biterr_pipe_t, node);
    CHECK_AND_FREE(pipe->t)
    CHECK_AND_FREE(pipe->biterr_rate)
    CHECK_AND_FREE(pipe)
}

pipe_node_t *biterr_pipe_create(packet_size_filter *filter,
                                size_t num, float *t,
                                float *biterr_rate,
                                int max_flip) {
    biterr_pipe_t *pipe = calloc(1, sizeof(biterr_pipe_t));
    pipe_node_t *node = &pipe->node;

    MALLOC_AND_COPY(pipe->t, t, num, float)
    MALLOC_AND_COPY(pipe->biterr_rate, biterr_rate, num, float)
    pipe->max_flip = max_flip;

    node->pipe_type = PIPE_BITERR;
    node->insert = biterr_pipe_insert;
    node->free = biterr_pipe_free;
    node->process = NULL;
    node->clear = NULL;

    node->p = 0;
    node->num = num;
    node->size_filter = filter;

    return node;
}
