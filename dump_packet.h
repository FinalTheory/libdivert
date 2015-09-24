//
// Created by baidu on 15/9/2.
//

#ifndef DIVERT_DUMP_PACKET_H
#define DIVERT_DUMP_PACKET_H

#include "divert.h"
#include <sys/types.h>

#define DIVERT_DUMP_BPF_HERDER      (1u)
#define DIVERT_DUMP_PKTAP_HERDER    (1u << 1)
#define DIVERT_DUMP_ETHER_HERDER    (1u << 2)
#define DIVERT_DUMP_IP_HEADER       (1u << 3)

#define MIN_IP_HEADER_SIZE  20u
#define MIN_TCP_HEADER_SIZE 20u

u_char *divert_dump_packet(u_char *packet, packet_hdrs_t *result,
                           u_int32_t flags, char *errmsg);

#endif //DIVERT_DUMP_PACKET_H
