//
// Created by baidu on 15/9/2.
//

#ifndef DIVERT_DUMP_PACKET_H
#define DIVERT_DUMP_PACKET_H

#include "divert.h"
#include <sys/types.h>

u_char *divert_dump_bpf_raw_data(u_char *packet, char *errmsg, packet_hdrs_t *result);

u_char *divert_dump_ethernet_data(u_char *packet, char *errmsg, packet_hdrs_t *result);

u_char *divert_dump_ip_data(u_char *packet, char *errmsg, packet_hdrs_t *result);

#endif //DIVERT_DUMP_PACKET_H
