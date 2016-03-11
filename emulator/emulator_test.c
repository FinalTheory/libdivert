#include "emulator.h"
#include "delay.h"
#include "bandwidth.h"
#include "biterr.h"
#include "disorder.h"
#include "duplicate.h"
#include "throttle.h"
#include "drop.h"
#include <libproc.h>
#include "divert_ipfw.h"

#define DATA_LEN 200


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

pid_t pid;

static char proc_name_buf[128];


float t[DATA_LEN] = {0.000, 0.063, 0.126, 0.189, 0.253, 0.316, 0.379, 0.442, 0.505, 0.568, 0.631, 0.695, 0.758, 0.821, 0.884, 0.947, 1.010, 1.074, 1.137, 1.200, 1.263, 1.326, 1.389, 1.452, 1.516, 1.579, 1.642, 1.705, 1.768, 1.831, 1.894, 1.958, 2.021, 2.084, 2.147, 2.210, 2.273, 2.336, 2.400, 2.463, 2.526, 2.589, 2.652, 2.715, 2.778, 2.842, 2.905, 2.968, 3.031, 3.094, 3.157, 3.221, 3.284, 3.347, 3.410, 3.473, 3.536, 3.599, 3.663, 3.726, 3.789, 3.852, 3.915, 3.978, 4.041, 4.105, 4.168, 4.231, 4.294, 4.357, 4.420, 4.483, 4.547, 4.610, 4.673, 4.736, 4.799, 4.862, 4.926, 4.989, 5.052, 5.115, 5.178, 5.241, 5.304, 5.368, 5.431, 5.494, 5.557, 5.620, 5.683, 5.746, 5.810, 5.873, 5.936, 5.999, 6.062, 6.125, 6.188, 6.252, 6.315, 6.378, 6.441, 6.504, 6.567, 6.630, 6.694, 6.757, 6.820, 6.883, 6.946, 7.009, 7.073, 7.136, 7.199, 7.262, 7.325, 7.388, 7.451, 7.515, 7.578, 7.641, 7.704, 7.767, 7.830, 7.893, 7.957, 8.020, 8.083, 8.146, 8.209, 8.272, 8.335, 8.399, 8.462, 8.525, 8.588, 8.651, 8.714, 8.778, 8.841, 8.904, 8.967, 9.030, 9.093, 9.156, 9.220, 9.283, 9.346, 9.409, 9.472, 9.535, 9.598, 9.662, 9.725, 9.788, 9.851, 9.914, 9.977, 10.040, 10.104, 10.167, 10.230, 10.293, 10.356, 10.419, 10.483, 10.546, 10.609, 10.672, 10.735, 10.798, 10.861, 10.925, 10.988, 11.051, 11.114, 11.177, 11.240, 11.303, 11.367, 11.430, 11.493, 11.556, 11.619, 11.682, 11.745, 11.809, 11.872, 11.935, 11.998, 12.061, 12.124, 12.187, 12.251, 12.314, 12.377, 12.440, 12.503, 12.566,};
float drop_rate[DATA_LEN] = {0.000, 0.008, 0.016, 0.024, 0.032, 0.039, 0.047, 0.055, 0.063, 0.071, 0.079, 0.086, 0.094, 0.102, 0.110, 0.117, 0.125, 0.133, 0.140, 0.148, 0.155, 0.163, 0.170, 0.178, 0.185, 0.192, 0.200, 0.207, 0.214, 0.221, 0.228, 0.235, 0.242, 0.249, 0.256, 0.262, 0.269, 0.276, 0.282, 0.289, 0.295, 0.302, 0.308, 0.314, 0.320, 0.326, 0.332, 0.338, 0.344, 0.349, 0.355, 0.360, 0.366, 0.371, 0.376, 0.382, 0.387, 0.392, 0.396, 0.401, 0.406, 0.410, 0.415, 0.419, 0.424, 0.428, 0.432, 0.436, 0.439, 0.443, 0.447, 0.450, 0.454, 0.457, 0.460, 0.463, 0.466, 0.469, 0.471, 0.474, 0.476, 0.479, 0.481, 0.483, 0.485, 0.487, 0.489, 0.490, 0.492, 0.493, 0.494, 0.496, 0.496, 0.497, 0.498, 0.499, 0.499, 0.500, 0.500, 0.500, 0.500, 0.500, 0.500, 0.499, 0.499, 0.498, 0.497, 0.496, 0.496, 0.494, 0.493, 0.492, 0.490, 0.489, 0.487, 0.485, 0.483, 0.481, 0.479, 0.476, 0.474, 0.471, 0.469, 0.466, 0.463, 0.460, 0.457, 0.454, 0.450, 0.447, 0.443, 0.439, 0.436, 0.432, 0.428, 0.424, 0.419, 0.415, 0.410, 0.406, 0.401, 0.396, 0.392, 0.387, 0.382, 0.376, 0.371, 0.366, 0.360, 0.355, 0.349, 0.344, 0.338, 0.332, 0.326, 0.320, 0.314, 0.308, 0.302, 0.295, 0.289, 0.282, 0.276, 0.269, 0.262, 0.256, 0.249, 0.242, 0.235, 0.228, 0.221, 0.214, 0.207, 0.200, 0.192, 0.185, 0.178, 0.170, 0.163, 0.155, 0.148, 0.140, 0.133, 0.125, 0.117, 0.110, 0.102, 0.094, 0.086, 0.079, 0.071, 0.063, 0.055, 0.047, 0.039, 0.032, 0.024, 0.016, 0.008, 0.000,};
float delay_time[DATA_LEN] = {0.000, 0.008, 0.016, 0.024, 0.032, 0.039, 0.047, 0.055, 0.063, 0.071, 0.079, 0.086, 0.094, 0.102, 0.110, 0.117, 0.125, 0.133, 0.140, 0.148, 0.155, 0.163, 0.170, 0.178, 0.185, 0.192, 0.200, 0.207, 0.214, 0.221, 0.228, 0.235, 0.242, 0.249, 0.256, 0.262, 0.269, 0.276, 0.282, 0.289, 0.295, 0.302, 0.308, 0.314, 0.320, 0.326, 0.332, 0.338, 0.344, 0.349, 0.355, 0.360, 0.366, 0.371, 0.376, 0.382, 0.387, 0.392, 0.396, 0.401, 0.406, 0.410, 0.415, 0.419, 0.424, 0.428, 0.432, 0.436, 0.439, 0.443, 0.447, 0.450, 0.454, 0.457, 0.460, 0.463, 0.466, 0.469, 0.471, 0.474, 0.476, 0.479, 0.481, 0.483, 0.485, 0.487, 0.489, 0.490, 0.492, 0.493, 0.494, 0.496, 0.496, 0.497, 0.498, 0.499, 0.499, 0.500, 0.500, 0.500, 0.500, 0.500, 0.500, 0.499, 0.499, 0.498, 0.497, 0.496, 0.496, 0.494, 0.493, 0.492, 0.490, 0.489, 0.487, 0.485, 0.483, 0.481, 0.479, 0.476, 0.474, 0.471, 0.469, 0.466, 0.463, 0.460, 0.457, 0.454, 0.450, 0.447, 0.443, 0.439, 0.436, 0.432, 0.428, 0.424, 0.419, 0.415, 0.410, 0.406, 0.401, 0.396, 0.392, 0.387, 0.382, 0.376, 0.371, 0.366, 0.360, 0.355, 0.349, 0.344, 0.338, 0.332, 0.326, 0.320, 0.314, 0.308, 0.302, 0.295, 0.289, 0.282, 0.276, 0.269, 0.262, 0.256, 0.249, 0.242, 0.235, 0.228, 0.221, 0.214, 0.207, 0.200, 0.192, 0.185, 0.178, 0.170, 0.163, 0.155, 0.148, 0.140, 0.133, 0.125, 0.117, 0.110, 0.102, 0.094, 0.086, 0.079, 0.071, 0.063, 0.055, 0.047, 0.039, 0.032, 0.024, 0.016, 0.008, 0.000,};
float disorder_rate[DATA_LEN] = {0.000, 0.008, 0.016, 0.024, 0.032, 0.039, 0.047, 0.055, 0.063, 0.071, 0.079, 0.086, 0.094, 0.102, 0.110, 0.117, 0.125, 0.133, 0.140, 0.148, 0.155, 0.163, 0.170, 0.178, 0.185, 0.192, 0.200, 0.207, 0.214, 0.221, 0.228, 0.235, 0.242, 0.249, 0.256, 0.262, 0.269, 0.276, 0.282, 0.289, 0.295, 0.302, 0.308, 0.314, 0.320, 0.326, 0.332, 0.338, 0.344, 0.349, 0.355, 0.360, 0.366, 0.371, 0.376, 0.382, 0.387, 0.392, 0.396, 0.401, 0.406, 0.410, 0.415, 0.419, 0.424, 0.428, 0.432, 0.436, 0.439, 0.443, 0.447, 0.450, 0.454, 0.457, 0.460, 0.463, 0.466, 0.469, 0.471, 0.474, 0.476, 0.479, 0.481, 0.483, 0.485, 0.487, 0.489, 0.490, 0.492, 0.493, 0.494, 0.496, 0.496, 0.497, 0.498, 0.499, 0.499, 0.500, 0.500, 0.500, 0.500, 0.500, 0.500, 0.499, 0.499, 0.498, 0.497, 0.496, 0.496, 0.494, 0.493, 0.492, 0.490, 0.489, 0.487, 0.485, 0.483, 0.481, 0.479, 0.476, 0.474, 0.471, 0.469, 0.466, 0.463, 0.460, 0.457, 0.454, 0.450, 0.447, 0.443, 0.439, 0.436, 0.432, 0.428, 0.424, 0.419, 0.415, 0.410, 0.406, 0.401, 0.396, 0.392, 0.387, 0.382, 0.376, 0.371, 0.366, 0.360, 0.355, 0.349, 0.344, 0.338, 0.332, 0.326, 0.320, 0.314, 0.308, 0.302, 0.295, 0.289, 0.282, 0.276, 0.269, 0.262, 0.256, 0.249, 0.242, 0.235, 0.228, 0.221, 0.214, 0.207, 0.200, 0.192, 0.185, 0.178, 0.170, 0.163, 0.155, 0.148, 0.140, 0.133, 0.125, 0.117, 0.110, 0.102, 0.094, 0.086, 0.079, 0.071, 0.063, 0.055, 0.047, 0.039, 0.032, 0.024, 0.016, 0.008, 0.000,};
float biterr_rate[DATA_LEN] = {0.000, 0.008, 0.016, 0.024, 0.032, 0.039, 0.047, 0.055, 0.063, 0.071, 0.079, 0.086, 0.094, 0.102, 0.110, 0.117, 0.125, 0.133, 0.140, 0.148, 0.155, 0.163, 0.170, 0.178, 0.185, 0.192, 0.200, 0.207, 0.214, 0.221, 0.228, 0.235, 0.242, 0.249, 0.256, 0.262, 0.269, 0.276, 0.282, 0.289, 0.295, 0.302, 0.308, 0.314, 0.320, 0.326, 0.332, 0.338, 0.344, 0.349, 0.355, 0.360, 0.366, 0.371, 0.376, 0.382, 0.387, 0.392, 0.396, 0.401, 0.406, 0.410, 0.415, 0.419, 0.424, 0.428, 0.432, 0.436, 0.439, 0.443, 0.447, 0.450, 0.454, 0.457, 0.460, 0.463, 0.466, 0.469, 0.471, 0.474, 0.476, 0.479, 0.481, 0.483, 0.485, 0.487, 0.489, 0.490, 0.492, 0.493, 0.494, 0.496, 0.496, 0.497, 0.498, 0.499, 0.499, 0.500, 0.500, 0.500, 0.500, 0.500, 0.500, 0.499, 0.499, 0.498, 0.497, 0.496, 0.496, 0.494, 0.493, 0.492, 0.490, 0.489, 0.487, 0.485, 0.483, 0.481, 0.479, 0.476, 0.474, 0.471, 0.469, 0.466, 0.463, 0.460, 0.457, 0.454, 0.450, 0.447, 0.443, 0.439, 0.436, 0.432, 0.428, 0.424, 0.419, 0.415, 0.410, 0.406, 0.401, 0.396, 0.392, 0.387, 0.382, 0.376, 0.371, 0.366, 0.360, 0.355, 0.349, 0.344, 0.338, 0.332, 0.326, 0.320, 0.314, 0.308, 0.302, 0.295, 0.289, 0.282, 0.276, 0.269, 0.262, 0.256, 0.249, 0.242, 0.235, 0.228, 0.221, 0.214, 0.207, 0.200, 0.192, 0.185, 0.178, 0.170, 0.163, 0.155, 0.148, 0.140, 0.133, 0.125, 0.117, 0.110, 0.102, 0.094, 0.086, 0.079, 0.071, 0.063, 0.055, 0.047, 0.039, 0.032, 0.024, 0.016, 0.008, 0.000,};
float duplicate_rate[DATA_LEN] = {0.000, 0.008, 0.016, 0.024, 0.032, 0.039, 0.047, 0.055, 0.063, 0.071, 0.079, 0.086, 0.094, 0.102, 0.110, 0.117, 0.125, 0.133, 0.140, 0.148, 0.155, 0.163, 0.170, 0.178, 0.185, 0.192, 0.200, 0.207, 0.214, 0.221, 0.228, 0.235, 0.242, 0.249, 0.256, 0.262, 0.269, 0.276, 0.282, 0.289, 0.295, 0.302, 0.308, 0.314, 0.320, 0.326, 0.332, 0.338, 0.344, 0.349, 0.355, 0.360, 0.366, 0.371, 0.376, 0.382, 0.387, 0.392, 0.396, 0.401, 0.406, 0.410, 0.415, 0.419, 0.424, 0.428, 0.432, 0.436, 0.439, 0.443, 0.447, 0.450, 0.454, 0.457, 0.460, 0.463, 0.466, 0.469, 0.471, 0.474, 0.476, 0.479, 0.481, 0.483, 0.485, 0.487, 0.489, 0.490, 0.492, 0.493, 0.494, 0.496, 0.496, 0.497, 0.498, 0.499, 0.499, 0.500, 0.500, 0.500, 0.500, 0.500, 0.500, 0.499, 0.499, 0.498, 0.497, 0.496, 0.496, 0.494, 0.493, 0.492, 0.490, 0.489, 0.487, 0.485, 0.483, 0.481, 0.479, 0.476, 0.474, 0.471, 0.469, 0.466, 0.463, 0.460, 0.457, 0.454, 0.450, 0.447, 0.443, 0.439, 0.436, 0.432, 0.428, 0.424, 0.419, 0.415, 0.410, 0.406, 0.401, 0.396, 0.392, 0.387, 0.382, 0.376, 0.371, 0.366, 0.360, 0.355, 0.349, 0.344, 0.338, 0.332, 0.326, 0.320, 0.314, 0.308, 0.302, 0.295, 0.289, 0.282, 0.276, 0.269, 0.262, 0.256, 0.249, 0.242, 0.235, 0.228, 0.221, 0.214, 0.207, 0.200, 0.192, 0.185, 0.178, 0.170, 0.163, 0.155, 0.148, 0.140, 0.133, 0.125, 0.117, 0.110, 0.102, 0.094, 0.086, 0.079, 0.071, 0.063, 0.055, 0.047, 0.039, 0.032, 0.024, 0.016, 0.008, 0.000,};

float bandwidth_t[2] = {0, 10};
float bandwidth_val[2] = {512, 512};

float throttle_start[] = {0.5, 1.3, 2.5, 3.6, 5.4, 7.1, 9.6, 15};
float throttle_end[] = {0.9, 1.8, 2.9, 4.3, 6.0, 7.9, 10.0, 17};

int main(int argc, char *argv[]) {
    char errmsg[256];
    // set random seed
    srand((u_int)time(NULL));

    // extract process PID
    if (argc == 2) {
        pid = atoi(argv[1]);
    } else {
        puts("Usage: ./emulator <PID>");
        exit(EXIT_FAILURE);
    }

    proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("Watching packets of %s: %d\n", proc_name_buf, pid);

    pid_t pids[1];
    pids[0] = pid;

    // create a handle for divert object
    // not using any flag, just divert all packets
    divert_t *handle = divert_create(0, 0u);

    emulator_config_t *config =
            emulator_create_config(handle);

    pipe_node_t *throttle_pipe =
            throttle_pipe_create(NULL, 8, throttle_start, throttle_end, 65535);

    pipe_node_t *drop_pipe =
            drop_pipe_create(NULL, DATA_LEN, t, drop_rate);

    pipe_node_t *bandwidth_pipe =
            bandwidth_pipe_create(NULL, 2, bandwidth_t, bandwidth_val, 8192);

    pipe_node_t *delay_pipe =
            delay_pipe_create(NULL, DATA_LEN, t, delay_time, 65535);

    pipe_node_t *disorder_pipe =
            disorder_pipe_create(NULL, DATA_LEN, t, disorder_rate, 65535, 10);

    emulator_set_pid_list(config, pids, 1);

    emulator_add_flag(config, EMULATOR_RECHECKSUM);

//    emulator_add_pipe(config, throttle_pipe, DIRECTION_IN);
//    emulator_add_pipe(config, drop_pipe, DIRECTION_IN);
//    emulator_add_pipe(config, bandwidth_pipe, DIRECTION_IN);
//    emulator_add_pipe(config, disorder_pipe, DIRECTION_IN);
    emulator_add_pipe(config, delay_pipe, DIRECTION_IN);

    emulator_set_dump_pcap(config, "/Users/baidu/Downloads");

    if (emulator_config_check(config, errmsg)) {
        puts(errmsg);
        exit(EXIT_FAILURE);
    }

    // set the callback function to handle packets
    divert_set_callback(handle, emulator_callback, config);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle);

    divert_update_ipfw(handle, "ip from any to any via en0");

    if (handle->errmsg[0]) {
        puts(handle->errmsg);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    printf("Divert socket buffer size: %zu\n", handle->bufsize);

    // call the main loop
    divert_loop(handle, -1);

    emulator_flush(config);

    printf("Num reused: %zu, num new allocated: %zu, num large: %zu\n",
           config->pool->num_reuse,
           config->pool->num_alloc,
           config->pool->num_large);

    // clear the emulator config
    emulator_destroy_config(config);

    // output statics information
    printf("Diverted packets: %llu\n", handle->num_diverted);

    // clean the handle to release resources
    if (divert_close(handle) == 0) {
        puts("Successfully cleaned, exit.");
    }
    ipfw_flush(errmsg);
    return 0;
}
