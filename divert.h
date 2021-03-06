#ifndef LIBDIVERT_DIVERT_H
#define LIBDIVERT_DIVERT_H

#ifdef  __cplusplus
extern "C" {
#endif

#include "divert_mem_pool.h"
#include "pqueue.h"
#include <stdio.h>
#include <netinet/ip.h>
#include <libnet.h>
#include <ifaddrs.h>
#include "netinet/ip_fw.h"

/*
 * flags for error handling
 */
#define KEXT_FAILURE        -1
#define DIVERT_FAILURE      -2
#define IPFW_FAILURE        -3
#define CALLBACK_NOT_FOUND  -5
#define PIPE_OPEN_FAILURE   -6
#define INVALID_FAILURE     -8

/*
 * default packet parameters
 */
#define DEFAULT_PACKET_SIZE     1520
#define DEFAULT_IPFW_RULE_ID    1
#define MAX_EVENT_COUNT         16
#define NUM_TCP_STREAMS         2048
#define TIMER_QUEUE_SIZE        1048576

// some default buffer size
#define PIPE_BUFFER_SIZE        32
#define DIVERT_ERRBUF_SIZE      256
#define DIVERT_DEFAULT_BUFSIZE  524288

/*
 * flags to control divert behaviour
 */
#define DIVERT_FLAG_TCP_REASSEM  1u

/*
 * flags for packet buffer and error handling
 */
#define DIVERT_ERROR_NODATA         (1u << 1)
#define DIVERT_ERROR_KQUEUE         (1u << 2)
#define DIVERT_ERROR_INVALID_IP     (1u << 3)

// typedef for divert callback function
typedef void (*divert_callback_t)(void *args, void *proc_info,
                                  struct ip *ip_data, struct sockaddr *sin);

// typedef for divert error handler function
typedef void (*divert_error_handler_t)(u_int64_t errflags);

// typedef for divert signal handler
typedef void (*divert_signal_t)(int sig, void *data);

typedef struct {
    u_int32_t flags;
    divert_mem_pool_t *pool;
    /*
     * file descriptors
     */
    int divert_fd;                  // file descriptor of divert socket
    int kext_fd;                    // file descriptor for kernel-to-userland communication
    int ipfw_id;                    // ID for ipfw rule
    int divert_port;                // port bind to divert socket
    int pipe_fd[2];                 // use pipe descriptor to end event loop gracefully
    int exit_fd[2];                 // use pipe descriptor to wait event loop gracefully

    /*
     * buffer things
     */
    u_char *divert_buffer;
    size_t bufsize;

    /*
     * statics information
     */
    u_int64_t num_unknown;
    u_int64_t num_diverted;

    /*
     * other information
     */
    divert_error_handler_t err_handler;
    divert_callback_t callback;
    void *callback_args;
    pqueue *timer_queue;
    volatile u_char loop_continue, is_looping;

    char *ipfw_filter;
    libnet_t *libnet;
    in_addr_t iface_addr;
    in_addr_t iface_mask;

    // store error code and message
    char errmsg[DIVERT_ERRBUF_SIZE];
} divert_t;

typedef struct {
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    u_char *payload;
    size_t size_ip;
    size_t size_tcp;
    size_t size_udp;
    size_t size_payload;
} packet_hdrs_t;

#define MAX_COMM_LEN 32

typedef struct {
    pid_t pid;
    pid_t epid;
    char comm[MAX_COMM_LEN];
} proc_info_t;

typedef struct {
    struct timeval tv;
    void *data;
    uint32_t flag;
} timeout_event_t;

divert_t *divert_create(int port_number, u_int32_t flags);

int divert_set_data_buffer_size(divert_t *handle, size_t bufsize);

int divert_set_thread_buffer_size(divert_t *handle, size_t bufsize);

int divert_set_device(divert_t *handle, char *dev_name);

int divert_device_inbound(divert_t *handle, struct ip *packet);

int divert_device_outbound(divert_t *handle, struct ip *packet);

int divert_set_callback(divert_t *handle, divert_callback_t callback, void *args);

int divert_set_error_handler(divert_t *handle, divert_error_handler_t handler);

int divert_update_ipfw(divert_t *handle, char *divert_filter);

/*
 * after divert_activate() is called, you should *NOT* do any time-consuming work
 * you *SHOULD* call divert_loop() as soon as possible
 * otherwise the diverted packets couldn't be handled in time
 * and this would make your network connection unstable
 */
int divert_activate(divert_t *divert_handle);

int divert_loop(divert_t *divert_handle, int count);

int divert_register_timer(divert_t *handle,
                          const struct timeval *timeout,
                          void *data, uint32_t flag);

int divert_query_proc_by_packet(divert_t *handle,
                                struct ip *ip_hdr,
                                struct sockaddr *sin,
                                proc_info_t *result);

struct tcp_stream *
        divert_find_tcp_stream(struct ip *ip_hdr);

int divert_init_nids();

int divert_init_pcap(FILE *fp);

int divert_dump_pcap(struct ip *packet, FILE *fp);

int divert_is_inbound(struct sockaddr *sin_raw, char *interface);

int divert_is_outbound(struct sockaddr *sin_raw);

void divert_checksum(struct ip *ip_data);

ssize_t divert_reinject(divert_t *handle, struct ip *packet,
                        ssize_t length, struct sockaddr *sin);

int divert_is_looping(divert_t *handle);

void divert_loop_stop(divert_t *handle);

void divert_loop_wait(divert_t *handle);

/*
 * this function *SHOULD* be called within the thread you call divert_loop()
 * but *NOT* in the thread you call divert_loop_stop() !
 */
int divert_close(divert_t *divert_handle);

int divert_set_signal_handler(int signum,
                              divert_signal_t handler, void *data);

void divert_signal_handler_stop_loop(int signal, void *handle);

#ifdef  __cplusplus
}
#endif

#endif //LIBDIVERT_DIVERT_H
