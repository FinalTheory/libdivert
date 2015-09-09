#include "divert.h"
#include "print_data.h"
#include "print_packet.h"
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>


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
        fprintf(fp, "\tData Link Type: %s\n",
                pcap_datalink_val_to_name(pktap_hdr->pth_dlt));
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
