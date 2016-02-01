#include "divert.h"

#define MAX_PACKET_SIZE 65535


u_char packet_buf[MAX_PACKET_SIZE];
u_char sin_buf[2 * sizeof(struct sockaddr)];
u_char proc_info_buf[2 * sizeof(proc_info_t)];


// generate random float number from 0 to 1
inline double rand_double() {
    return (double)rand() / (double)RAND_MAX;
}

int main(int argc, char *argv[]) {
    double rate;
    char *dev_str;
    if (argc == 3) {
        dev_str = argv[1];
        sscanf(argv[2], "%lf", &rate);
    } else {
        puts("Usage: ./violated_wifi <dev_name> <drop_rate>");
        exit(EXIT_FAILURE);
    }

    // create a handle for divert object
    divert_t *handle = divert_create(0, DIVERT_FLAG_BLOCK_IO);

    // activate the divert handler
    divert_activate(handle);

    divert_set_device(handle, dev_str);

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    divert_update_ipfw(handle, "ip from any to any");

    // check error message
    if (handle->errmsg[0]) {
        puts(handle->errmsg);
        exit(EXIT_FAILURE);
    }

    // call the non-blocking main loop
    divert_loop(handle, -1);

    size_t idx = 0;

    while (divert_is_looping(handle)) {
        // read data from the divert handle
        ssize_t status = divert_read(handle,
                                     (proc_info_t *)proc_info_buf,
                                     (struct ip *)packet_buf,
                                     (struct sockaddr_in *)sin_buf);
        idx++;
        // the handle is closed, then just break the loop
        if (status == DIVERT_READ_EOF) { break; }
        // drop inbound packets
        if (divert_device_inbound(handle, (struct ip *)packet_buf)) {
            if (rand_double() < rate) {
                printf("Dropped packet %zu\n", idx);
                continue;
            }
        }
        // re-inject packets into TCP/IP stack
        divert_reinject(handle, (struct ip *)packet_buf, -1, (struct sockaddr *)sin_buf);
    }

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
