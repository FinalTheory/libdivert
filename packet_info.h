#ifndef DIVERT_PACKET_INFO_H
#define DIVERT_PACKET_INFO_H

#include <sys/types.h>
#include "net/bpf.h"
#include "net/pktap.h"
#include <pthread.h>

#ifdef  __cplusplus
extern "C" {
#endif


struct packet_map_t;

struct packet_map_t *packet_map_create();

void packet_map_insert(struct packet_map_t *mp,
                       in_addr_t _ip_src,
                       in_addr_t _ip_dst,
                       u_short _port_src,
                       u_short _port_dst,
                       struct pktap_header *ptr);
void packet_map_insert(struct packet_map_t *mp,
                       in_addr_t _ip_src,
                       in_addr_t _ip_dst,
                       u_short _port_src,
                       u_short _port_dst,
                       struct pktap_header *ptr);

struct pktap_header *packet_map_query(struct packet_map_t *mp,
                                      in_addr_t _ip_src,
                                      in_addr_t _ip_dst,
                                      u_short _port_src,
                                      u_short _port_dst);

size_t packet_map_get_size(struct packet_map_t *mp);

void packet_map_clean(struct packet_map_t *mp);

void packet_map_free(struct packet_map_t *mp);

#ifdef  __cplusplus
}
#endif

#endif //DIVERT_PACKET_INFO_H
