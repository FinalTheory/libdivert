#include "emulator_config.h"
#include "emulator_callback.h"
#include <stdlib.h>
#include <libproc.h>
#include <divert.h>


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

pid_t pid;

static char proc_name_buf[128];

float t[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
float delay[] = {0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2};
float rate[] = {0, 0.02, 0.04, 0.06, 0.08, 0.1, 0.12, 0.14, 0.16, 0.18, 0.2};

int main(int argc, char *argv[]) {
    // set random seed
    srand((u_int)time(NULL));

    // extract process PID
    if (argc == 2) {
        pid = atoi(argv[1]);
    } else {
        puts("Usage: ./dump_divert <PID>");
        exit(EXIT_FAILURE);
    }

    proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("Watching packets of %s: %d\n", proc_name_buf, pid);

    pid_t pids[1];
    pids[0] = pid;

    // create a handle for divert object
    // not using any flag, just divert all packets
    divert_t *handle = divert_create(0, 0u);

    emulator_config_t *config = emulator_create_config();

    emulator_add_flag(config, EMULATOR_DISORDER);

    emulator_set_disorder(config, 11, t, rate);

    emulator_set_pid(config, pids, 1);

    emulator_set_handle(config, handle);

    emulator_set_direction(config, OFFSET_DISORDER, DIRECTION_OUT);

    if (handle->errmsg[0]) {
        puts(handle->errmsg);
        exit(EXIT_FAILURE);
    }

    // set the callback function to handle packets
    divert_set_callback(handle, emulator_callback, config);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle);

    divert_update_ipfw(handle, "udp from any to any via lo0");

    if (handle->errmsg[0]) {
        puts(handle->errmsg);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    printf("Divert socket buffer size: %zu\n", handle->bufsize);

    // call the main loop
    divert_loop(handle, -1);

    // clear the emulator config
    emulator_destroy_config(config);

    // output statics information
    printf("Diverted packets: %llu\n", handle->num_diverted);

    // clean the handle to release resources
    if (divert_close(handle) == 0) {
        puts("Successfully cleaned, exit.");
    }
    return 0;
}
