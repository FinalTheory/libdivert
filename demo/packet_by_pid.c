#include "divert.h"
#include "dump_packet.h"
#include "print_packet.h"
#include <stdlib.h>
#include <libproc.h>

#define MAX_PACKET_SIZE 65535


u_char packet_buf[MAX_PACKET_SIZE];
u_char sin_buf[2 * sizeof(struct sockaddr)];
u_char proc_info_buf[2 * sizeof(proc_info_t)];


void error_handler(u_int64_t flags) {
    if (flags & DIVERT_ERROR_DIVERT_NODATA) {
        puts("Didn't read data from divert socket or data error.");
    }
    if (flags & DIVERT_ERROR_KQUEUE) {
        puts("kqueue error.");
    }
}


static pid_t pid;
static char proc_name_buf[128];


int main(int argc, char *argv[]) {
    if (argc == 2) {
        pid = atoi(argv[1]);
    } else {
        puts("Usage: ./packet_by_pid <PID>");
        exit(EXIT_FAILURE);
    }
    proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("Watching packets of %s: %d\n", proc_name_buf, pid);

    // buffer for error information
    char errmsg[DIVERT_ERRBUF_SIZE];

    // pointer to buffer of pktap header
    proc_info_t *proc = (proc_info_t *)proc_info_buf;
    packet_hdrs_t packet_hdrs;

    // create a handle for divert object
    divert_t *handle = divert_create(0, DIVERT_FLAG_BLOCK_IO, errmsg);

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

    divert_set_filter(handle, "ip from any to not 0.0.0.255:24 via en0", errmsg);

    // call the non-blocking main loop
    divert_loop(handle, -1);

    while (divert_is_looping(handle)) {
        // read data from the divert handle
        ssize_t status = divert_read(handle, proc_info_buf,
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

        // get actual pid of this packet
        pid_t cur_pid = proc->pid == -1 ? proc->epid : proc->pid;
        if (cur_pid == pid) {
            // print detail of that packet
            divert_print_packet(stderr, ~0u, &packet_hdrs, NULL);
        }
    }

    // clean the handle to release resources
    if (divert_close(handle, errmsg) == 0) {
        puts("Successfully cleaned.");
    }

    return 0;
}
