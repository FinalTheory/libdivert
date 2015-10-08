#include "divert.h"
#include "string.h"
#include "nids.h"
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>


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

#define int_ntoa(x)    inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *adres(struct tuple4 addr) {
    static char buf[256];
    strcpy (buf, int_ntoa(addr.saddr));
    sprintf (buf + strlen(buf), ",%i,", addr.source);
    strcat (buf, int_ntoa(addr.daddr));
    sprintf (buf + strlen(buf), ",%i", addr.dest);
    return buf;
}


void tcp_callback(struct tcp_stream *a_tcp, void **this_time_not_needed) {
    char buf[1024];
    strcpy (buf, adres(a_tcp->addr)); // we put conn params into buf
    if (a_tcp->nids_state == NIDS_JUST_EST) {
        // connection described by a_tcp is established
        // here we decide, if we wish to follow this stream
        // sample condition: if (a_tcp->addr.dest!=23) return;
        // in this simple app we follow each stream, so..
        a_tcp->client.collect++; // we want data received by a client
        a_tcp->server.collect++; // and by a server, too
        a_tcp->server.collect_urg++; // we want urgent data received by a
        // server
#ifdef WE_WANT_URGENT_DATA_RECEIVED_BY_A_CLIENT
        a_tcp->client.collect_urg++; // if we don't increase this value,
                                   // we won't be notified of urgent data
                                   // arrival
#endif
        fprintf(stderr, "%s established\n", buf);
        return;
    }
    if (a_tcp->nids_state == NIDS_CLOSE) {
        // connection has been closed normally
        fprintf(stderr, "%s closing\n", buf);
        return;
    }
    if (a_tcp->nids_state == NIDS_RESET) {
        // connection has been closed by RST
        fprintf(stderr, "%s reset\n", buf);
        return;
    }

    if (a_tcp->nids_state == NIDS_DATA) {
        // new data has arrived; gotta determine in what direction
        // and if it's urgent or not

        struct half_stream *hlf;

        if (a_tcp->server.count_new_urg) {
            // new byte of urgent data has arrived
            strcat(buf, "(urgent->)");
            buf[strlen(buf) + 1] = 0;
            buf[strlen(buf)] = a_tcp->server.urgdata;
            write(1, buf, strlen(buf));
            return;
        }
        // We don't have to check if urgent data to client has arrived,
        // because we haven't increased a_tcp->client.collect_urg variable.
        // So, we have some normal data to take care of.
        if (a_tcp->client.count_new) {
            // new data for client
            hlf = &a_tcp->client; // from now on, we will deal with hlf var,
            // which will point to client side of conn
            strcat (buf, "(<-)"); // symbolic direction of data
        }
        else {
            hlf = &a_tcp->server; // analogical
            strcat (buf, "(->)");
        }
        fprintf(stderr, "%s", buf); // we print the connection parameters
        // (saddr, daddr, sport, dport) accompanied
        // by data flow direction (-> or <-)

        write(2, hlf->data, (size_t)hlf->count_new); // we print the newly arrived data
    }
    return;
}

#define MAX_PACKET_SIZE 65535

u_char packet_buf[MAX_PACKET_SIZE];
u_char sin_buf[2 * sizeof(struct sockaddr)];
u_char pktap_hdr_buf[2 * sizeof(struct pktap_header)];
divert_t *handle;

int main() {
    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];

    // create a handle for divert object
    handle = divert_create(0, DIVERT_FLAG_USE_PKTAP |
                              DIVERT_FLAG_BLOCK_IO |
                              DIVERT_FLAG_TCP_REASSEM, errmsg);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle, errmsg);
    if (errmsg[0]) {
        puts(errmsg);
        exit(EXIT_FAILURE);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    printf("BPF buffer size: %zu\n", handle->bufsize);

    // call the non-blocking main loop
    divert_loop(handle, -1);

    nids_register_tcp(tcp_callback);

    while (divert_is_looping(handle)) {
        // read data from the divert handle
        divert_read(handle, pktap_hdr_buf,
                    packet_buf, sin_buf);
        // re-inject packets into TCP/IP stack
        divert_reinject(handle, (struct ip *)packet_buf,
                        -1, (struct sockaddr *)sin_buf);
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
