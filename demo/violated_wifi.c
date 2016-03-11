#include "divert.h"


// generate random float number from 0 to 1
inline double rand_double() {
    return (double)rand() / (double)RAND_MAX;
}

double rate;

void ip_callback(void *args, void *proc_info_p,
                 struct ip *packet, struct sockaddr *sin) {
    static size_t idx = 0;
    divert_t *handle = args;
    idx++;
    // drop some inbound packets
    if (divert_device_inbound(handle, packet)) {
        if (rand_double() < rate) {
            printf("Dropped packet %zu\n", idx);
            return;
        }
    }
    // re-inject packets into TCP/IP stack
    divert_reinject(handle, packet, -1, sin);
}

int main(int argc, char *argv[]) {
    char *dev_str;
    if (argc == 3) {
        dev_str = argv[1];
        sscanf(argv[2], "%lf", &rate);
    } else {
        puts("Usage: ./violated_wifi <dev_name> <drop_rate>");
        exit(EXIT_FAILURE);
    }

    // create a handle for divert object
    divert_t *handle = divert_create(0, 0);

    divert_set_device(handle, dev_str);

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    divert_set_callback(handle, ip_callback, handle);

    divert_update_ipfw(handle, "ip from any to any");

    // activate the divert handler
    divert_activate(handle);

    // check error message
    if (handle->errmsg[0]) {
        puts(handle->errmsg);
        exit(EXIT_FAILURE);
    }

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
