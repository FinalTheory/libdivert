#include "divert.h"
#include "dump_packet.h"
#include "print_packet.h"
#include <stdlib.h>

#define MAX_PACKET_SIZE 65535


u_char packet_buf[MAX_PACKET_SIZE];
u_char sin_buf[2 * sizeof(struct sockaddr)];
u_char pktap_hdr_buf[2 * sizeof(struct pktap_header)];
divert_t *handle;


void intHandler(int signal) {
    divert_loop_stop(handle);
    puts("Loop stop by SIGINT.");
}


void error_handler(u_int64_t flags) {
    if (flags & DIVERT_ERROR_BPF_INVALID) {
        puts("Invalid BPF packet.");
    }
    if (flags & DIVERT_ERROR_BPF_NODATA) {
        puts("Didn't read data from BPF device.");
    }
    if (flags & DIVERT_ERROR_DIVERT_NODATA) {
        puts("Didn't read data from divert socket or data error.");
    }
    if (flags & DIVERT_ERROR_KQUEUE) {
        puts("kqueue error.");
    }
}


int main() {
    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];

    // pointer to buffer of pktap header
    struct pktap_header *pktap_hdr =
            (struct pktap_header *)pktap_hdr_buf;
    packet_hdrs_t packet_hdrs;

    // create a handle for divert object
    handle = divert_create(0, DIVERT_FLAG_WITH_PKTAP |
                              DIVERT_FLAG_BLOCK_IO, errmsg);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle, errmsg);
    if (errmsg[0]) {
        puts(errmsg);
        exit(EXIT_FAILURE);
    }

    // register signal handler to exit process gracefully
    signal(SIGINT, intHandler);

    printf("BPF buffer size: %zu\n", handle->bufsize);

    // call the non-blocking main loop
    divert_loop(handle, -1);

    while (divert_is_looping(handle)) {
        // read data from the divert handle
        ssize_t status = divert_read(handle, pktap_hdr_buf,
                                     packet_buf, sin_buf);

        // the handle is closed, then just break the loop
        if (status == DIVERT_READ_EOF) {
            break;
        }

        // re-inject packets into TCP/IP stack
        divert_reinject(handle, (struct ip *)packet_buf, -1, (struct sockaddr *)sin_buf);

        // dump the data of IP packet
        divert_dump_packet(packet_buf, &packet_hdrs,
                           DIVERT_DUMP_IP_HEADER, errmsg);

        // output the error message
        if (errmsg[0]) {
            puts(errmsg);
        }

        if (pktap_hdr->pth_length > 0) {
            // if the packet has process information, only print its information
            printf("\nSend by %s: %d on device: %s\n", pktap_hdr->pth_comm,
                   pktap_hdr->pth_pid, pktap_hdr->pth_ifname);
        } else {
            // else we print detail of that packet
            divert_print_packet(stderr, ~0u, &packet_hdrs, pktap_hdr);
        }
    }

    // output statics information
    printf("\nCaptured by BPF device: %llu\n", handle->num_captured);
    printf("Packets without process info: %llu\n", handle->num_missed);
    printf("Diverted by divert socket with process info: %llu\n", handle->num_diverted);
    printf("Accuracy: %f\n", (double)handle->num_diverted /
                             (handle->num_diverted + handle->num_missed));

    /*
     * output the statics information of libpcap
     * the dropped packets means that your network is busy
     * and some packets are dropped without processing
     * because the processing speed is not fast enough
     */
    struct pcap_stat stats;
    divert_bpf_stats(handle, &stats);
    printf("BPF device received: %d, dropped: %d, dropped by driver: %d\n",
           stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);

    // clean the handle to release resources
    if (divert_close(handle, errmsg) == 0) {
        puts("Successfully cleaned.");
    }

    return 0;
}
