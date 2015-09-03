#include "dump_packet.h"
#include <string.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

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
    |       (DLT_EN10MB)        |
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


u_char *divert_dump_bpf_raw_data(u_char *packet, char *errmsg, packet_hdrs_t *result) {
    errmsg[0] = 0;
    // extract the BPF header
    struct bpf_hdr_ext *bhephdr = (struct bpf_hdr_ext *)packet;
    if (bhephdr->bh_hdrlen < sizeof(struct bpf_hdr_ext)) {
        sprintf(errmsg, "Invalid BPF header length: %hu bytes", bhephdr->bh_hdrlen);
        memset(result, 0, sizeof(packet_hdrs_t));
        return NULL;
    }
    result->bhep_hdr = bhephdr;

    // extract the PKTAP header
    struct pktap_header *pktap_hdr = (struct pktap_header *)(packet + bhephdr->bh_hdrlen);
    if (pktap_hdr->pth_length < sizeof(struct pktap_header)) {
        sprintf(errmsg, "Invalid PKTAP header length: %u bytes", pktap_hdr->pth_length);
        memset(result, 0, sizeof(packet_hdrs_t));
        return NULL;
    }
    result->pktap_hdr = pktap_hdr;

    return divert_dump_ethernet_data((u_char *)pktap_hdr + pktap_hdr->pth_length, errmsg, result);
}

u_char *divert_dump_ethernet_data(u_char *packet, char *errmsg, packet_hdrs_t *result) {
    errmsg[0] = 0;
    /* The Ethernet Data Link header */
    struct ether_header *ethernet_hdr = (struct ether_header *)(packet);
    result->ether_hdr = ethernet_hdr;

    return divert_dump_ip_data(packet + ETHER_HDR_LEN, errmsg, result);
}

u_char *divert_dump_ip_data(u_char *packet, char *errmsg, packet_hdrs_t *result) {
    errmsg[0] = 0;

    struct ip *ip_hdr = (struct ip *)packet;         /* define/compute ip header offset */
    struct tcphdr *tcp_hdr = NULL;                   /* The TCP header */
    struct udphdr *udp_hdr = NULL;                   /* The packet payload */
    u_char *payload = NULL;                          /* Packet payload */

    size_t size_ip = 0;
    size_t size_tcp = 0;
    size_t size_udp = 0;
    size_t size_payload = 0;

    result->ip_hdr = ip_hdr;

    size_ip = IP_VHL_HL(ip_hdr->ip_vhl) * 4u;
    if (size_ip < 20) {
        sprintf(errmsg, "Invalid IP header length: %zu bytes", size_ip);
        memset(result, 0, sizeof(packet_hdrs_t));
        return NULL;
    }
    result->size_ip = size_ip;

    /*
     * Determine protocol
     * But we only handle TCP and UDP here
     */
    switch (ip_hdr->ip_p) {
        case IPPROTO_TCP:
            tcp_hdr = (struct tcphdr *)(packet + size_ip);
            break;
        case IPPROTO_UDP:
            udp_hdr = (struct udphdr *)(packet + size_ip);
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
        if (size_tcp < 20) {
            sprintf(errmsg, "Invalid TCP header length: %zu bytes", size_tcp);
            memset(result, 0, sizeof(packet_hdrs_t));
            return NULL;
        }
        result->size_tcp = size_tcp;
        /* define/compute tcp payload (segment) offset */
        payload = packet + size_ip + size_tcp;
        /* compute tcp payload (segment) size */
        size_payload = ntohs(ip_hdr->ip_len) - (size_ip + size_tcp);
    } else if (udp_hdr != NULL) {
        /*
         *  Oh, this packet is UDP.
         */
        size_udp = sizeof(struct udphdr);
        result->size_udp = size_udp;
        payload = packet + size_ip + size_udp;
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
