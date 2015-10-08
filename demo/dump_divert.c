#include "divert.h"
#include <stdlib.h>
#include <divert.h>


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

inline double rand_double() {
    return (double)rand() / (double)RAND_MAX;
}

FILE *fp1, *fp2;
pid_t pid;
double rate = 0.1;

void callback(void *args, void *proc_info_p, struct ip *packet, struct sockaddr *sin) {
    proc_info_t *proc = proc_info_p;
    char errmsg[256];
    divert_t *handle = (divert_t *)args;
    if (pid == proc->pid) {
        if (divert_is_inbound(sin, NULL)) {
            if (rand_double() < 1 - rate) {
                divert_reinject(handle, packet, -1, sin);
                divert_dump_pcap(packet, fp1, errmsg);
            }
            divert_dump_pcap(packet, fp2, errmsg);
        } else {
            divert_reinject(handle, packet, -1, sin);
            divert_dump_pcap(packet, fp1, errmsg);
            divert_dump_pcap(packet, fp2, errmsg);
        }
    } else {
        divert_reinject(handle, packet, -1, sin);
    }
}

int main(int argc, char *argv[]) {
    // set random seed
    srand((u_int)time(NULL));

    // extract process PID
    if (argc == 3) {
        pid = atoi(argv[1]);
        sscanf(argv[2], "%lf", &rate);
    } else {
        puts("Usage: ./dump_divert <PID> <drop_rate>");
        exit(EXIT_FAILURE);
    }

    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];

    // open file for pcap
    fp1 = fopen("data1.pcap", "w");
    fp2 = fopen("data2.pcap", "w");
    divert_init_pcap(fp1, errmsg);
    divert_init_pcap(fp2, errmsg);

    // create a handle for divert object
    // not using any flag, just divert all packets
    divert_t *handle = divert_create(0, 0u, errmsg);

    // set the callback function to handle packets
    divert_set_callback(handle, callback, handle);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle, errmsg);

    char rule[] = "ip from any to any via en0";
    divert_set_filter(handle, rule, errmsg);

    if (errmsg[0]) {
        puts(errmsg);
        exit(EXIT_FAILURE);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    printf("Divert socket buffer size: %zu\n", handle->bufsize);

    // call the main loop
    divert_loop(handle, -1);

    // output statics information
    printf("Diverted packets: %llu\n", handle->num_diverted);

    // clean the handle to release resources
    if (divert_close(handle, errmsg) == 0) {
        puts("Successfully cleaned, exit.");
    }
    fclose(fp1);
    fclose(fp2);
    return 0;
}
