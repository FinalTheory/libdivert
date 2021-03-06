#include "divert.h"
#include <libproc.h>


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

inline double rand_double() {
    return (double)rand() / (double)RAND_MAX;
}

FILE *fp1, *fp2, *fp3;
pid_t pid;
double rate = 0.1;

size_t prev_MB = 0;
size_t total_size = 0;
const size_t size_MB = 1024 * 1024;

struct in_addr localhost;

void callback(void *args, void *proc_info_p,
              struct ip *packet, struct sockaddr *sin) {
    proc_info_t *proc = proc_info_p;
    divert_t *handle = (divert_t *)args;

    pid_t cur_pid = proc->pid == -1 ? proc->epid : proc->pid;
    if (pid == cur_pid) {
        if (divert_is_inbound(sin, NULL)) {
            if (rand_double() < 1 - rate) {
                divert_reinject(handle, packet, -1, sin);
                divert_dump_pcap(packet, fp1);
            }
        } else {
            divert_reinject(handle, packet, -1, sin);
            divert_dump_pcap(packet, fp1);
        }
    } else {
        divert_reinject(handle, packet, -1, sin);
    }

    // dump other packets into fp2 and fp3
    if (packet->ip_src.s_addr != localhost.s_addr &&
        packet->ip_dst.s_addr != localhost.s_addr) {
        if (cur_pid == -1) {
            divert_dump_pcap(packet, fp2);
        }
        if (cur_pid == -1 || pid == cur_pid) {
            divert_dump_pcap(packet, fp3);
            total_size += ntohs(packet->ip_len);
            if (total_size / size_MB != prev_MB) {
                prev_MB = total_size / size_MB;
                printf("%zu MB data transfered.\n", prev_MB);
            }
        }
    }
}

static char proc_name_buf[128];

int main(int argc, char *argv[]) {
    inet_aton("127.0.0.1", &localhost);

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

    proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("Watching packets of %s: %d\n", proc_name_buf, pid);

    // open file for pcap
    fp1 = fopen("data.pcap", "w");
    fp2 = fopen("data_unknown.pcap", "w");
    fp3 = fopen("data_all.pcap", "w");
    divert_init_pcap(fp1);
    divert_init_pcap(fp2);
    divert_init_pcap(fp3);

    // create a handle for divert object
    // not using any flag, just divert all packets
    divert_t *handle = divert_create(0, 0u);

    // set the callback function to handle packets
    divert_set_callback(handle, callback, handle);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle);

    divert_update_ipfw(handle, "ip from any to not 0.0.0.255:24 via en0");

    if (handle->errmsg[0]) {
        puts(handle->errmsg);
        exit(EXIT_FAILURE);
    }

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    printf("Divert socket buffer size: %zu\n", handle->bufsize);

    // call the main loop
    if (divert_loop(handle, -1) != 0) {
        puts(handle->errmsg);
    }

    // output statics information
    printf("Diverted packets: %llu\n", handle->num_diverted);

    printf("Num reused: %zu, num new allocated: %zu, num large: %zu\n",
           handle->pool->num_reuse,
           handle->pool->num_alloc,
           handle->pool->num_large);

    // clean the handle to release resources
    if (divert_close(handle) == 0) {
        puts("Successfully cleaned, exit.");
    }

    fclose(fp1);
    fclose(fp2);
    fclose(fp3);
    return 0;
}
