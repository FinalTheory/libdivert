#include "divert.h"
#include "print_data.h"
#include "print_packet.h"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void print_pktap_header(struct pktap_header *pktp_hdr) {
    printf("pth_length %u (sizeof(struct pktap_header)  %lu)\n",
           pktp_hdr->pth_length, sizeof(struct pktap_header));
    printf("pth_type_next %u\n", pktp_hdr->pth_type_next);
    printf("pth_dlt %u\n", pktp_hdr->pth_dlt);
    printf("pth_ifname %s\n", pktp_hdr->pth_ifname);
    printf("pth_flags 0x%x\n", pktp_hdr->pth_flags);
    printf("pth_protocol_family %u\n", pktp_hdr->pth_protocol_family);
    printf("pth_frame_pre_length %u\n", pktp_hdr->pth_frame_pre_length);
    printf("pth_frame_post_length %u\n", pktp_hdr->pth_frame_post_length);
    printf("pth_pid %d\n", pktp_hdr->pth_pid);
    printf("pth_comm %s\n", pktp_hdr->pth_comm);
    printf("pth_svc %u\n", pktp_hdr->pth_svc);
    printf("pth_epid %d\n", pktp_hdr->pth_epid);
    printf("pth_ecomm %s\n", pktp_hdr->pth_ecomm);
}

void divert_print_packet(FILE *fp, u_int32_t flags,
                         packet_hdrs_t *packet_headers,
                         struct pktap_header *pktap_hdr) {
    static u_int32_t count = 1;
    if (flags & PRINT_NEWLINE) {
        puts("");
    }
    if (flags & PRINT_INDEX) {
        fprintf(fp, "Packet index %u:\n", count++);
    }
    if ((flags & PRINT_PROC) && pktap_hdr != NULL) {
        fprintf(fp, "\tProcess information: %s:%d\n",
                pktap_hdr->pth_comm, pktap_hdr->pth_pid);
    }
    if ((flags & PRINT_DATA_LINK) && pktap_hdr != NULL) {
        fprintf(fp, "\tData Link Type: %s, on %s\n",
                pcap_datalink_val_to_name(pktap_hdr->pth_dlt), pktap_hdr->pth_ifname);
    }

    /* print source and destination IP addresses */
    if (flags & PRINT_ADDR) {
        fprintf(fp, "\tFrom: %s\n", inet_ntoa(packet_headers->ip_hdr->ip_src));
        fprintf(fp, "\t  To: %s\n", inet_ntoa(packet_headers->ip_hdr->ip_dst));
    }
    if (flags & PRINT_PROT) {
        switch (packet_headers->ip_hdr->ip_p) {
            case IPPROTO_TCP:
                fprintf(fp, "\tProtocol: TCP\n");
                if (flags & PRINT_PORT) {
                    fprintf(fp, "\tSrc port: %d\n", ntohs(packet_headers->tcp_hdr->th_sport));
                    fprintf(fp, "\tDst port: %d\n", ntohs(packet_headers->tcp_hdr->th_dport));
                }
                break;
            case IPPROTO_UDP:
                fprintf(fp, "\tProtocol: UDP\n");
                if (flags & PRINT_PORT) {
                    fprintf(fp, "\tSrc port: %d\n", ntohs(packet_headers->udp_hdr->uh_sport));
                    fprintf(fp, "\tDst port: %d\n", ntohs(packet_headers->udp_hdr->uh_dport));
                }
                break;
            case IPPROTO_ICMP:
                fprintf(fp, "\tProtocol: ICMP\n");
                return;
            case IPPROTO_IP:
                fprintf(fp, "\tProtocol: IP\n");
                return;
            default:
                fprintf(fp, "\tProtocol: unknown\n");
                return;
        }
    }
    if (flags & PRINT_PAYLOAD) {
        fprintf(fp, "\tPayload (%zu bytes):\n", packet_headers->size_payload);
        if (packet_headers->payload != NULL) {
            print_payload(fp, packet_headers->payload, (int)packet_headers->size_payload);
        }
    }
}
