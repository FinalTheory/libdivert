#include "divert.h"
#include <string.h>
#include <unistd.h>
#include <stdlib.h>


divert_t *handle;
useconds_t delay = 200;

void intHandler(int signal) {
    handle->is_looping = 0;
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
    socklen_t sin_len = sizeof(struct sockaddr);

    while (handle->is_looping) {
        __tmp_data_type *data = divert_buf_remove(thread_buffer);
        if (data == NULL) {
            break;
        }
        // sleep for 200ms
        usleep(delay * 1000);
        sendto(handle->divert_fd, data->ip_data,
               ntohs(data->ip_data->ip_len), 0, data->sin, sin_len);
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

    if (packet->ip_p == IPPROTO_ICMP) {
        // delay for 400ms
        __tmp_data_type *data = malloc(sizeof(__tmp_data_type));
        data->sin = malloc(sizeof(struct sockaddr));
        data->ip_data = malloc(ip_len);
        memcpy(data->sin, sin, sin_len);
        memcpy(data->ip_data, packet, ip_len);
        divert_buf_insert(thread_buffer, data);
    } else {
        // re-inject the packets without processing
        sendto(handle->divert_fd, packet,
               ip_len, 0, sin, sin_len);
    }
}

int main(int argc, char *argv[]) {
    if (argc == 2) {
        delay = (useconds_t)atoi(argv[1]) / 2;
    }

    // buffer for error information
    char errmsg[PCAP_ERRBUF_SIZE];
    void *ret;

    // create a handle for divert object
    handle = divert_create(1234, DIVERT_FLAG_WITH_PKTAP |
                                 DIVERT_FLAG_PRECISE_INFO, errmsg);

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
    divert_buf_init(thread_buffer, 1024, errmsg);

    // create a new thread to handle the ICMP packets
    handle->is_looping = 1;
    pthread_t reinject_thread;
    pthread_create(&reinject_thread, NULL, reinject_packets, NULL);

    // register signal handler to exit process gracefully
    signal(SIGINT, intHandler);

    printf("BPF buffer size: %zu\n", handle->bufsize);

    // call the main loop
    divert_loop(handle, -1, callback, handle);

    // insert an item to stop the loop of thread
    divert_buf_insert(thread_buffer, NULL);

    // output statics information
    printf("Captured by BPF device: %llu\n", handle->num_captured);
    printf("Packets without process info: %llu\n", handle->num_missed);
    printf("Diverted by divert socket with process info: %llu\n", handle->num_diverted);
    printf("Accuracy: %f\n", (double)handle->num_diverted /
                             (handle->num_diverted + handle->num_missed));

    /*
     * output the statics information of libpcap
     * the dropped packets means that your network is busy
     * and some packets are dropped without processing
     * because the processing speed is not fast enough
     */
    struct pcap_stat stats;
    pcap_stats(handle->pcap_handle, &stats);
    printf("BPF device received: %d, dropped: %d, dropped by driver: %d\n",
           stats.ps_recv, stats.ps_drop, stats.ps_ifdrop);

    pthread_join(reinject_thread, &ret);
    printf("Diverted %d ICMP packets.\n", *(int *)ret);

    // clean the handle to release resources
    if (divert_clean(handle, errmsg) == 0) {
        puts("Successfully cleaned, exit.");
    }
    divert_buf_clean(thread_buffer, errmsg);
    return 0;
}
