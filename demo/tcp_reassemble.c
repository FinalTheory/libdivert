#include "divert.h"
#include "string.h"
#include "nids.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <libproc.h>
#include <divert.h>


static pid_t pid;
static char proc_name_buf[128];


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
    sprintf (buf + strlen(buf), "(%i)-", addr.source);
    strcat (buf, int_ntoa(addr.daddr));
    sprintf (buf + strlen(buf), "(%i)", addr.dest);
    return buf;
}


void tcp_callback(struct tcp_stream *a_tcp, void **this_time_not_needed) {
    char addr_buf[1024];
    strcpy (addr_buf, adres(a_tcp->addr)); // we put conn params into buf
    if (a_tcp->nids_state == NIDS_JUST_EST) {
        a_tcp->client.collect++; // we want data received by a client
        a_tcp->server.collect++; // and by a server, too
        fprintf(stderr, "%s established\n", addr_buf);
        // clean the data file
        FILE *fp = fopen(addr_buf, "wb");
        fclose(fp);
        return;
    }
    if (a_tcp->nids_state == NIDS_CLOSE) {
        // connection has been closed normally
        fprintf(stderr, "%s closing\n", addr_buf);
        return;
    }
    if (a_tcp->nids_state == NIDS_RESET) {
        // connection has been closed by RST
        fprintf(stderr, "%s reset\n", addr_buf);
        return;
    }

    if (a_tcp->nids_state == NIDS_DATA) {
        //fprintf(stderr, "Data of connection: %s\n", addr_buf);
        // new data has arrived
        // gotta determine in what direction
        struct half_stream *hlf;

        if (a_tcp->client.count_new) {
            // new data for client
            hlf = &a_tcp->client; // from now on, we will deal with hlf var,
        } else {
            hlf = &a_tcp->server; // analogical
        }
        FILE *fp = fopen(addr_buf, "a");
        fwrite(hlf->data, 1, (size_t)hlf->count_new, fp);
        fclose(fp);
    }
    return;
}

#define MAX_PACKET_SIZE 65535

u_char packet_buf[MAX_PACKET_SIZE];
u_char sin_buf[2 * sizeof(struct sockaddr)];
u_char proc_info_buf[2 * sizeof(struct pktap_header)];
divert_t *handle;

int main(int argc, char *argv[]) {
    if (argc == 2) {
        pid = atoi(argv[1]);
    } else {
        puts("Usage: ./tcp_reassemble <PID>");
        exit(EXIT_FAILURE);
    }

    proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("Watching packets of %s: %d\n", proc_name_buf, pid);

    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];

    // create a handle for divert object
    handle = divert_create(0, DIVERT_FLAG_BLOCK_IO |
                              DIVERT_FLAG_TCP_REASSEM, errmsg);

    FILE *fp1 = fopen("data.pcap", "w");
    FILE *fp2 = fopen("data_all.pcap", "w");
    FILE *fp3 = fopen("data_unknown.pcap", "w");
    divert_init_pcap(fp1, errmsg);
    divert_init_pcap(fp2, errmsg);
    divert_init_pcap(fp3, errmsg);

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

    printf("Packet buffer size: %zu\n", handle->bufsize);

    // call the non-blocking main loop
    divert_loop(handle, -1);

    nids_register_tcp(tcp_callback);

    while (divert_is_looping(handle)) {
        // read data from the divert handle
        divert_read(handle, proc_info_buf,
                    packet_buf, sin_buf);

        pid_t cur_pid = ((proc_info_t *)proc_info_buf)->pid == -1 ?
                        ((proc_info_t *)proc_info_buf)->epid :
                        ((proc_info_t *)proc_info_buf)->pid;
        if (cur_pid == pid) {
            divert_dump_pcap((struct ip *)packet_buf, fp1, errmsg);
            divert_dump_pcap((struct ip *)packet_buf, fp2, errmsg);
        } else if (cur_pid == -1) {
            divert_dump_pcap((struct ip *)packet_buf, fp2, errmsg);
            divert_dump_pcap((struct ip *)packet_buf, fp3, errmsg);
        }

        // re-inject packets into TCP/IP stack
        divert_reinject(handle, (struct ip *)packet_buf,
                        -1, (struct sockaddr *)sin_buf);
    }

    // clean the handle to release resources
    if (divert_close(handle, errmsg) == 0) {
        puts("Successfully cleaned.");
    }
    fclose(fp1);
    fclose(fp2);
    fclose(fp3);

    return 0;
}
