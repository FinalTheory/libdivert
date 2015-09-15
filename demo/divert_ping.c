#include "divert.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


divert_t *handle;
useconds_t delay = 400;

void intHandler(int signal) {
    puts("Loop stop by SIGINT.");
    divert_loop_stop(handle);
}

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

packet_buf_t *thread_buffer;

typedef struct {
    struct sockaddr *sin;
    struct ip *ip_data;
} __tmp_data_type;

void *reinject_packets(void *args) {
    int *count = malloc(sizeof(int));
    *count = 0;

    while (handle->is_looping) {
        __tmp_data_type *data = divert_buf_remove(thread_buffer);
        if (data == NULL) {
            break;
        }
        // sleep for 200ms
        usleep(delay * 1000);
        divert_reinject(handle, data->ip_data, -1, data->sin);
        free(data->ip_data);
        free(data->sin);
        free(data);
        (*count)++;
    }
    return count;
}

void callback(void *args, struct pktap_header *pktap_hdr, struct ip *packet, struct sockaddr *sin) {
    socklen_t sin_len = sizeof(struct sockaddr);
    size_t ip_len = ntohs(packet->ip_len);
    char ifname[8];

    if (packet->ip_p == IPPROTO_ICMP) {
        // if this is a ICMP packet, then just delay it
        if (divert_is_inbound(sin, ifname)) {
            __tmp_data_type *data = malloc(sizeof(__tmp_data_type));
            data->sin = malloc(sizeof(struct sockaddr));
            data->ip_data = malloc(ip_len);
            memcpy(data->sin, sin, sin_len);
            memcpy(data->ip_data, packet, ip_len);
            divert_buf_insert(thread_buffer, data);
            printf("Inbound ICMP packet on %s\n", ifname);
        } else if (divert_is_outbound(sin)) {
            divert_reinject(handle, packet, -1, sin);
            puts("Outbound ICMP packet, not delayed.");
        } else {
            puts("Error.");
        }
    } else {
        // re-inject the packets without processing
        divert_reinject(handle, packet, -1, sin);
    }
}

int main(int argc, char *argv[]) {
    if (argc == 2) {
        delay = (useconds_t)atoi(argv[1]);
    }

    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];
    void *ret;

    // create a handle for divert object
    // not using any flag, just divert all packets
    handle = divert_create(0, 0u, errmsg);

    // set the callback function to handle packets
    divert_set_callback(handle, callback, handle);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // activate the divert handler
    divert_activate(handle, errmsg);
    if (errmsg[0]) {
        puts(errmsg);
        exit(EXIT_FAILURE);
    }

    // allocate buffer for threads
    thread_buffer = malloc(sizeof(packet_buf_t));
    divert_buf_init(thread_buffer, 4096, errmsg);

    // create a new thread to handle the ICMP packets
    pthread_t reinject_thread;
    pthread_create(&reinject_thread, NULL, reinject_packets, NULL);

    // register signal handler to exit process gracefully
    signal(SIGINT, intHandler);

    printf("Divert socket buffer size: %zu\n", handle->bufsize);
    puts("Note that ICMP packets to localhost are diverted twice, so the delay time would be double.\n");

    // call the main loop
    divert_loop(handle, -1);

    // insert an item to stop the loop of thread
    divert_buf_insert(thread_buffer, NULL);

    // output statics information
    printf("Diverted packets: %llu\n", handle->num_missed);
    pthread_join(reinject_thread, &ret);
    printf("Diverted %d ICMP packets.\n", *(int *)ret);

    // clean the handle to release resources
    if (divert_close(handle, errmsg) == 0) {
        puts("Successfully cleaned, exit.");
    }
    divert_buf_clean(thread_buffer, errmsg);
    return 0;
}