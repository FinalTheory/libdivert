#include "divert.h"
#include "dump_packet.h"
#include "print_packet.h"
#include "net/pktap.h"
#include "print_data.h"
#include "queue.h"
#include <stdlib.h>


divert_t *handle;

void intHandler(int signal) {
    handle->is_looping = 0;
}

void callback(void *args, struct pktap_header *pktap_hdr, struct ip *packet, struct sockaddr *sin) {
    char errmsg[256];
    packet_hdrs_t packet_hdrs;
    socklen_t sin_len = sizeof(struct sockaddr_in);
    divert_t *handle = (divert_t *)args;
    sendto(handle->divert_fd, packet,
           ntohs(packet->ip_len), 0, sin, sin_len);
    if (pktap_hdr != NULL) {

//        divert_dump_ip_data((u_char *)packet, errmsg, &packet_hdrs);
//        divert_print_packet(stderr, ~(PRINT_DATA_LINK | PRINT_PROC), &packet_hdrs);
    } else {
//        divert_dump_ip_data((u_char *)packet, errmsg, &packet_hdrs);
//        divert_print_packet(stderr, ~(PRINT_DATA_LINK | PRINT_PROC), &packet_hdrs);
    }
}

int main() {
    char errmsg[PCAP_ERRBUF_SIZE];
    handle = divert_create(1234, DIVERT_FLAG_WITH_APPLE_EXTHDR, errmsg);
    divert_activate(handle, errmsg);
    if (errmsg[0]) {
        puts(errmsg);
        exit(EXIT_FAILURE);
    }
    signal(SIGINT, intHandler);
    divert_loop(handle, -1, callback, handle);
    printf("Capture rate: %f\n", handle->num_diverted / (double)(handle->num_captured));
    printf("Accuracy: %f\n", handle->num_diverted /
                                 (double)(handle->num_missed + handle->num_diverted));
    if (divert_clean(handle, errmsg) == 0) {
        puts("Successfully cleaned.");
    }
    return 0;
}
