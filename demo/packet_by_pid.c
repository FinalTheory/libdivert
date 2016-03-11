#include "divert.h"
#include "dump_packet.h"
#include "print_packet.h"
#include <stdlib.h>
#include <libproc.h>

#define MAX_PACKET_SIZE 65535


void error_handler(u_int64_t flags) {
    if (flags & DIVERT_ERROR_NODATA) {
        puts("Didn't read data from divert socket or data error.");
    }
    if (flags & DIVERT_ERROR_KQUEUE) {
        puts("kqueue error.");
    }
    if (flags & DIVERT_ERROR_INVALID_IP) {
        puts("Invalid IP packet.");
    }
}

static pid_t pid;
static char proc_name_buf[128];

void callback(void *args, void *proc_info_p,
              struct ip *packet, struct sockaddr *sin) {
    proc_info_t *proc = proc_info_p;
    packet_hdrs_t packet_hdrs;
    divert_t *handle = args;
    // re-inject packets into TCP/IP stack
    divert_reinject(handle, packet, -1, sin);
    // dump the data of IP packet
    divert_dump_packet((u_char *)packet,
                       &packet_hdrs,
                       handle->errmsg);
    // output the error message
    if (handle->errmsg[0]) {
        puts(handle->errmsg);
    }
    // get actual pid of this packet
    pid_t cur_pid = proc->pid == -1 ? proc->epid : proc->pid;
    if (cur_pid == pid) {
        // print detail of that packet
        divert_print_packet(stderr, ~0u, &packet_hdrs, NULL);
    }
}


int main(int argc, char *argv[]) {
    if (argc == 2) {
        pid = atoi(argv[1]);
    } else {
        puts("Usage: ./packet_by_pid <PID>");
        exit(EXIT_FAILURE);
    }
    proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("Watching packets of %s: %d\n", proc_name_buf, pid);

    // create a handle for divert object
    divert_t *handle = divert_create(0, 0);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // set callback function for divert handle
    divert_set_callback(handle, callback, handle);

    // activate the divert handler
    divert_activate(handle);
    if (handle->errmsg[0]) {
        puts(handle->errmsg);
        exit(EXIT_FAILURE);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    divert_update_ipfw(handle, "ip from any to not 0.0.0.255:24 via en0");

    // call the non-blocking main loop
    divert_loop(handle, -1);

    printf("Num reused: %zu, num new allocated: %zu, num large: %zu\n",
           handle->pool->num_reuse,
           handle->pool->num_alloc,
           handle->pool->num_large);

    // clean the handle to release resources
    if (divert_close(handle) == 0) {
        puts("Successfully cleaned.");
    }

    return 0;
}
