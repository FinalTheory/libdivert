#include "divert.h"
#include "dump_packet.h"
#include "print_packet.h"
#include <stdlib.h>


divert_t *handle;

void intHandler(int signal) {
    puts("Loop stop by SIGINT.");
    divert_loop_stop(handle);
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

void callback(void *args, struct pktap_header *pktap_hdr, struct ip *packet, struct sockaddr *sin) {
    char errmsg[256];
    packet_hdrs_t packet_hdrs;

    // re-inject packets into TCP/IP stack
    divert_reinject(handle, packet, -1, sin);

    // dump the data of IP packet
    divert_dump_packet((u_char *)packet, &packet_hdrs,
                       DIVERT_DUMP_IP_HEADER, errmsg);

    // if the packet has process information
    if (pktap_hdr != NULL) {
        printf("\nSend by %s: %d on device: %s\n", pktap_hdr->pth_comm,
               pktap_hdr->pth_pid, pktap_hdr->pth_ifname);
    } else {
        divert_print_packet(stderr, ~0u, &packet_hdrs, pktap_hdr);
    }
}

int main() {
    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];
    // create a handle for divert object
    handle = divert_create(1234, DIVERT_FLAG_WITH_PKTAP, errmsg);

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

    // call the main loop
    divert_loop(handle, -1, callback, handle);

    // output statics information
    printf("Captured by BPF device: %llu\n", handle->num_captured);
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
    pcap_stats(handle->pcap_handle, &stats);
    printf("BPF device received: %d, dropped: %d, dropped by driver: %d\n",
           stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);

    // clean the handle to release resources
    if (divert_clean(handle, errmsg) == 0) {
        puts("Successfully cleaned.");
    }

    return 0;
}
