#include "divert.h"
#include "nids.h"
#include <stdlib.h>
#include <dump_packet.h>

void tcp_callback(struct tcp_stream *a_tcp, void **this_time_not_needed) {
    if (a_tcp->nids_state == NIDS_JUST_EST) {
        a_tcp->client.collect++;
        a_tcp->server.collect++;
    }
}

#define MAX_PACKET_SIZE 65535

u_char packet_buf[MAX_PACKET_SIZE + 10];
u_char sin_buf[2 * sizeof(struct sockaddr)];
u_char proc_info_buf[2 * sizeof(struct pktap_header)];
divert_t *handle;

inline double rand_double() {
    return (double)rand() / (double)RAND_MAX;
}

pid_t pid;
double rate;

int main(int argc, char *argv[]) {
    // set random seed
    srand((u_int)time(NULL));

    // extract process PID
    if (argc == 3) {
        pid = atoi(argv[1]);
        sscanf(argv[2], "%lf", &rate);
    } else {
        puts("Usage: ./gfw_simulator <PID> <reset_rate>");
        exit(EXIT_FAILURE);
    }

    // statistics
    int diverted = 0, missed = 0;

    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];

    // create a handle for divert object
    handle = divert_create(0, DIVERT_FLAG_BLOCK_IO |
                              DIVERT_FLAG_TCP_REASSEM, errmsg);

    // activate the divert handler
    divert_activate(handle, errmsg);
    if (errmsg[0]) {
        puts(errmsg);
        exit(EXIT_FAILURE);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    printf("Divert socket buffer size: %zu\n", handle->bufsize);

    // call the non-blocking main loop
    divert_loop(handle, -1);

    nids_register_tcp(tcp_callback);

    proc_info_t *proc = (proc_info_t *)proc_info_buf;

    while (divert_is_looping(handle)) {
        // read data from the divert handle
        divert_read(handle, proc_info_buf,
                    packet_buf, sin_buf);

        diverted++;
        if (proc->pid == -1 && proc->epid == -1) {
            missed++;
        } else if (proc->pid == pid) {
            packet_hdrs_t headers;
            divert_dump_packet(packet_buf, &headers,
                               DIVERT_DUMP_IP_HEADER, errmsg);

            if (headers.tcp_hdr != NULL) {
                if (headers.tcp_hdr->th_flags & TH_RST) {
                    puts("TCP RST packet");
                } else {
                    struct tcp_stream *tcp =
                            divert_find_tcp_stream((struct ip *)packet_buf);
                    if (tcp != NULL && tcp->nids_state == NIDS_DATA) {
                        if (rand_double() < rate) {
                            nids_killtcp(tcp);
                        }
                    }
                }
            }
        }

        // re-inject packets into TCP/IP stack
        divert_reinject(handle, (struct ip *)packet_buf,
                        -1, (struct sockaddr *)sin_buf);
    }

    printf("Process information accuracy: %f\n", (diverted - missed) / (double)diverted);

    // clean the handle to release resources
    if (divert_close(handle, errmsg) == 0) {
        puts("Successfully cleaned.");
    }

    return 0;
}
