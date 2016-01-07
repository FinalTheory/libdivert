#include "divert.h"
#include "string.h"
#include "nids.h"
#include <stdlib.h>
#include <arpa/inet.h>
#include <libproc.h>


static pid_t pid;
static char proc_name_buf[128];


void error_handler(u_int64_t flags) {
    if (flags & DIVERT_ERROR_DIVERT_NODATA) {
        puts("Didn't read data from divert socket or data error.");
    }
    if (flags & DIVERT_ERROR_KQUEUE) {
        puts("kqueue error.");
    }
    if (flags & DIVERT_ERROR_INVALID_IP) {
        puts("Invalid IP packet.");
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

u_char packet_buf[MAX_PACKET_SIZE + 10];
u_char sin_buf[sizeof(struct sockaddr) + 10];
u_char proc_info_buf[sizeof(proc_info_t) + 10];
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

    // create a handle for divert object
    handle = divert_create(0, DIVERT_FLAG_BLOCK_IO |
                              DIVERT_FLAG_TCP_REASSEM);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle);
    if (handle->errmsg[0]) {
        puts(handle->errmsg);
        exit(EXIT_FAILURE);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    printf("Packet buffer size: %zu\n", handle->bufsize);

    // call the non-blocking main loop
    printf("Divert Loop Start Status: %d\n", divert_loop(handle, -1));

    // register callback function
    nids_register_tcp(tcp_callback);

    while (divert_is_looping(handle)) {
        // read data from the divert handle
        divert_read(handle,
                    (proc_info_t *)proc_info_buf,
                    (struct ip *)packet_buf,
                    (struct sockaddr_in *)sin_buf);

        // re-inject packets into TCP/IP stack
        divert_reinject(handle, (struct ip *)packet_buf,
                        -1, (struct sockaddr *)sin_buf);
    }

    // clean the handle to release resources
    if (divert_close(handle) == 0) {
        puts("Successfully cleaned.");
    }
    return 0;
}
