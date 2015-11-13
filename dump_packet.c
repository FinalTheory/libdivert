#include "dump_packet.h"
#include "divert.h"
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/*
 * The DLT_NULL packet header is 4 bytes long. It contains a host-byte-order
 * 32-bit integer that specifies the family, e.g. AF_INET.
 *
 * Note here that "host" refers to the host on which the packets were
 * captured; that isn't necessarily *this* host.
 *
 * The OpenBSD DLT_LOOP packet header is the same, except that the integer
 * is in network byte order.
 */

/*
 * Packet structure captured by BPF device
 * Please refer to:
 * 1. https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man4/bpf.4.html
 * 2. http://www.tcpdump.org/linktypes/LINKTYPE_PKTAP.html
 *
    +---------------------------+
    |  BPF header extended [1]  |
    |    (apple modification)   |
    +---------------------------+
    |    Header for DLT_PKTAP   |
    |       See also: [2]       |
    +---------------------------+
    |      ETHERNET header      |
    |             or            |
    |       DLT_NULL header     |
    +---------------------------+
    |         IP header         |
    |                           |
    +---------------------------+
    |       TCP/UDP header      |
    |                           |
    +---------------------------+
    |        Data payload       |
    .                           .
    .                           .
 */

u_char *divert_dump_packet(u_char *packet, packet_hdrs_t *result,
                           u_int32_t flags, char *errmsg) {
    errmsg[0] = 0;
    memset(result, 0, sizeof(packet_hdrs_t));
    u_char *entry = packet;

    if (flags & DIVERT_DUMP_IP_HEADER) {
        struct ip *ip_hdr = (struct ip *)entry;          /* define/compute ip header offset */
        size_t size_ip = ip_hdr->ip_hl * 4u; /* size of IP header */

        struct tcphdr *tcp_hdr = NULL;                   /* The TCP header */
        struct udphdr *udp_hdr = NULL;                   /* The packet payload */
        u_char *payload = NULL;                          /* Packet payload */
        size_t size_tcp = 0;
        size_t size_udp = 0;
        size_t size_payload = 0;

        if (size_ip < MIN_IP_HEADER_SIZE) {
            sprintf(errmsg, "Invalid IP header size: %zu", size_ip);
            memset(result, 0, sizeof(packet_hdrs_t));
            return NULL;
        }

        result->ip_hdr = ip_hdr;
        result->size_ip = size_ip;

        /*
         * Determine protocol
         * But we only handle TCP and UDP here
         */
        switch (ip_hdr->ip_p) {
            case IPPROTO_TCP:
                tcp_hdr = (struct tcphdr *)(entry + size_ip);
                break;
            case IPPROTO_UDP:
                udp_hdr = (struct udphdr *)(entry + size_ip);
                break;
            default:
                return NULL;
        }

        result->tcp_hdr = tcp_hdr;
        result->udp_hdr = udp_hdr;

        if (tcp_hdr != NULL) {
            /*
             *  OK, this packet is TCP.
             *  Define/compute tcp header offset
             */
            size_tcp = tcp_hdr->th_off * 4;
            if (size_tcp < MIN_TCP_HEADER_SIZE) {
                sprintf(errmsg, "Invalid TCP header length: %zu bytes", size_tcp);
                memset(result, 0, sizeof(packet_hdrs_t));
                return NULL;
            }
            result->size_tcp = size_tcp;
            /* define/compute tcp payload (segment) offset */
            payload = entry + size_ip + size_tcp;
            /* compute tcp payload (segment) size */
            size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_tcp);
        } else if (udp_hdr != NULL) {
            /*
             *  Oh, this packet is UDP.
             */
            size_udp = sizeof(struct udphdr);
            result->size_udp = size_udp;
            payload = entry + size_ip + size_udp;
            size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_udp);
        }

        if (size_payload == 0) {
            return NULL;
        } else if ((int)size_payload < 0) {
            sprintf(errmsg, "Error: payload size is negative");
            memset(result, 0, sizeof(packet_hdrs_t));
            return NULL;
        } else {
            result->payload = payload;
            result->size_payload = size_payload;
            return payload;
        }
    }
    return NULL;
}
