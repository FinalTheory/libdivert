#include "dump_packet.h"
#include <string.h>
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
 * # this is deprecated in libdivert
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

u_char *divert_dump_packet(u_char *packet,
                           packet_hdrs_t *result,
                           char *errmsg) {
    errmsg[0] = 0;
    memset(result, 0, sizeof(packet_hdrs_t));
    u_char *entry = packet;

    struct ip *ip_hdr = (struct ip *)entry;          /* define/compute ip header offset */
    size_t size_ip = ip_hdr->ip_hl * 4u;             /* size of IP header */

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
    return NULL;
}

//! \brief Calculate the IP header checksum.
//! \param buf The IP header content.
//! \param hdr_len The IP header length.
//! \return The result of the checksum.
uint16_t ip_checksum(const void *buf, size_t hdr_len)
{
    unsigned long sum = 0;
    const uint16_t *ip1;

    ip1 = buf;
    while (hdr_len > 1)
    {
        sum += *ip1++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        hdr_len -= 2;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (uint16_t)(~sum);
}

//! \brief Calculate the TCP checksum.
//! \param buff The TCP packet.
//! \param len The size of the TCP packet.
//! \param src_addr The IP source address (in network format).
//! \param dest_addr The IP destination address (in network format).
//! \return The result of the checksum.
uint16_t tcp_checksum(const void *buff, size_t len,
                      in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;

    // Calculate the sum						//
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if ( len & 1 )
        // Add the padding if the packet lenght is odd		//
        sum += *((uint8_t *)buf);

    // Add the pseudo-header					//
    sum += *(ip_src++);
    sum += *ip_src;
    sum += *(ip_dst++);
    sum += *ip_dst;
    sum += htons(IPPROTO_TCP);
    sum += htons(length);

    // Add the carries						//
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum				//
    return ( (uint16_t)(~sum)  );
}

//! \brief
//!	Calculate the UDP checksum (calculated with the whole
//!	packet).
//! \param buff The UDP packet.
//! \param len The UDP packet length.
//! \param src_addr The IP source address (in network format).
//! \param dest_addr The IP destination address (in network format).
//! \return The result of the checksum.
uint16_t udp_checksum(const void *buff, size_t len,
                      in_addr_t src_addr, in_addr_t dest_addr)
{
    const uint16_t *buf=buff;
    uint16_t *ip_src=(void *)&src_addr, *ip_dst=(void *)&dest_addr;
    uint32_t sum;
    size_t length=len;

    // Calculate the sum						//
    sum = 0;
    while (len > 1)
    {
        sum += *buf++;
        if (sum & 0x80000000)
            sum = (sum & 0xFFFF) + (sum >> 16);
        len -= 2;
    }

    if ( len & 1 )
        // Add the padding if the packet lenght is odd		//
        sum += *((uint8_t *)buf);

    // Add the pseudo-header					//
    sum += *(ip_src++);
    sum += *ip_src;

    sum += *(ip_dst++);
    sum += *ip_dst;

    sum += htons(IPPROTO_UDP);
    sum += htons(length);

    // Add the carries						//
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    // Return the one's complement of sum				//
    return ( (uint16_t)(~sum)  );
}
