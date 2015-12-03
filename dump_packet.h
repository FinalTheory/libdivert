#ifndef DIVERT_DUMP_PACKET_H
#define DIVERT_DUMP_PACKET_H

#include "divert.h"
#include <sys/types.h>

#define MIN_IP_HEADER_SIZE  20u
#define MIN_TCP_HEADER_SIZE 20u

u_char *divert_dump_packet(u_char *packet,
                           packet_hdrs_t *result,
                           char *errmsg);

uint16_t ip_checksum(const void *buf, size_t hdr_len);

uint16_t tcp_checksum(const void *buff, size_t len,
                      in_addr_t src_addr, in_addr_t dest_addr);

uint16_t udp_checksum(const void *buff, size_t len,
                      in_addr_t src_addr, in_addr_t dest_addr);

#endif //DIVERT_DUMP_PACKET_H
