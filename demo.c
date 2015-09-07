#include "divert.h"
#include "dump_packet.h"
#include "print_packet.h"
#include <stdlib.h>


divert_t *handle;

void intHandler(int signal) {
    handle->is_looping = 0;
}

void callback(void *args, u_char *packet, u_int64_t flags, struct sockaddr *sin) {
    socklen_t sin_len = sizeof(struct sockaddr_in);
    packet_hdrs_t hdrs;
    char errmsg[PCAP_ERRBUF_SIZE];
    divert_t *handle = (divert_t *)args;

    if (flags & DIVERT_RAW_BPF_PACKET) {
        divert_dump_bpf_raw_data(packet, errmsg, &hdrs);
        if (errmsg[0]) {
            puts(errmsg);
        } else {
            divert_print_packet(stderr, PRINT_PROC, &hdrs);
        }
        sendto(handle->divert_fd, hdrs.ip_hdr,
               ntohs(hdrs.ip_hdr->ip_len), 0, sin, sin_len);
    } else {
        puts("Unknown packet!");
        printf("flags = %lld\n", flags);
        exit(EXIT_FAILURE);
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
    divert_loop(handle, 1000, callback, handle);
    printf("Capture rate: %f\n", handle->num_diverted /
                              (double)(handle->num_diverted + handle->num_missed));
    if (divert_clean(handle, errmsg) == 0) {
        puts("Successfully cleaned.");
    }
    return 0;
}
