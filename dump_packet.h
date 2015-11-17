#ifndef DIVERT_DUMP_PACKET_H
#define DIVERT_DUMP_PACKET_H

#include "divert.h"
#include <sys/types.h>

#define MIN_IP_HEADER_SIZE  20u
#define MIN_TCP_HEADER_SIZE 20u

u_char *divert_dump_packet(u_char *packet,
                           packet_hdrs_t *result,
                           char *errmsg);

#endif //DIVERT_DUMP_PACKET_H
