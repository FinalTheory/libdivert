#include "reinject.h"
#include "emulator.h"


static void
reinject_pipe_insert(pipe_node_t *node,
                     emulator_packet_t *packet) {

    // if this is an event, just return
    if (packet->label != NEW_PACKET) { return; }

    // or, we re-inject this packet into IP stack
    reinject_pipe_t *pipe = container_of(node, reinject_pipe_t, node);
    emulator_config_t *config = node->config;
    divert_reinject(pipe->handle, packet->ip_data, -1, &packet->sin);
    // update size counter of diverted packet
    config->dsize[packet->direction] += packet->headers.size_payload;
    // dump this packet if needed
    if (config->flags & EMULATOR_DUMP_PCAP) {
        divert_dump_pcap(packet->ip_data,
                         config->dump_affected);
    }
    // and free this memory
    divert_mem_free(config->pool, packet->ip_data);
    divert_mem_free(config->pool, packet);
}

pipe_node_t *reinject_pipe_create(divert_t *handle) {
    reinject_pipe_t *pipe = calloc(1, sizeof(reinject_pipe_t));
    pipe_node_t *node = &pipe->node;

    pipe->handle = handle;

    node->pipe_type = PIPE_REINJECT;
    node->insert = reinject_pipe_insert;
    node->process = NULL;
    node->clear = NULL;
    node->free = NULL;

    node->size_filter = NULL;

    return node;
}
