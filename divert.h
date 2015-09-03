#ifndef LIBDIVERT_DIVERT_H
#define LIBDIVERT_DIVERT_H

#include "net/bpf.h"
#include "net/pktap.h"
#include <netinet/ip.h>
#include "netinet/ip_fw.h"
#include "pcap/pcap.h"
#include "pcap/pcap-int.h"
#include "queue.h"

/*
 * flags for error handling
 */
#define PCAP_FAILURE -1
#define DIVERT_FAILURE -2
#define FIREWALL_FAILURE -3

/*
 * default packet timeout
 */
#define PACKET_TIME_OUT 15

/*
 * flags for packet buffer and error handling
 */
#define DIVERT_NEW_PACKET           (1)
#define DIVERT_ERROR_BPF_INVALID    (1 << 1)
#define DIVERT_ERROR_BPF_NODATA     (1 << 2)
#define DIVERT_ERROR_NOINFO         (1 << 3)
#define DIVERT_STOP_LOOP            (1 << 4)

typedef void (*divert_callback_t)(void *args, u_char *packet);

typedef void (*divert_error_handler_t)(u_int32_t errflags);

typedef struct {
    /*
     * file descriptors
     */
    int bpf_fd;                     // file descriptor of BPF device
    int divert_fd;                  // file descriptor of divert socket

    /*
     * ipfw things
     */
    int ipfw_fd;                    // file descriptor of ipfw socket
    struct ip_fw ipfw_rule;         // ipfw rule data
    struct sockaddr_in divert_port; // port bind to divert socket

    /*
     * buffer things
     */
    u_char *bpf_buffer;
    u_char *divert_buffer;
    size_t bufsize;

    /*
     * pcap handler
     */
    pcap_t *pcap_handle;            // handle for pcap structure
    queue_t *bpf_queue;             // handle for queue structure
    /*
     * statics information
     */
    u_int64_t timeout;
    u_int64_t current_time_stamp;
    u_int64_t num_missed;

    /*
     * other info
     */
    divert_error_handler_t err_handle;
    volatile u_char is_looping;

} divert_t;

typedef struct {
    struct bpf_hdr_ext *bhep_hdr;
    struct pktap_header *pktap_hdr;
    struct ether_header *ether_hdr;
    struct ip *ip_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    u_char *payload;
    size_t size_ip;
    size_t size_tcp;
    size_t size_udp;
    size_t size_payload;
} packet_hdrs_t;

typedef struct {
    u_int64_t time_stamp;
    u_char *raw_data;
    // this pointer points a offset in raw_data
    struct ip *ip_data;
} packet_info_t;

divert_t *divert_create(int port_number, char *errmsg);

int divert_set_buffer_size(divert_t *handle, size_t bufsize);

int divert_set_pcap_filter(divert_t *divert_handle, char *pcap_filter, char *errmsg);

/*
 * after divert_activate() is called, you should *NOT* do any time-consuming work
 * you *SHOULD* call divert_loop() as soon as possible
 * otherwise the diverted packets couldn't be handled in time
 * and this would make your network connection unstable
 */
int divert_activate(divert_t *divert_handle, char *errmsg);

void divert_loop(divert_t *divert_handle, int count,
                 divert_callback_t callback, u_char *args);

void divert_loop_stop(divert_t *handle);

/*
 * this function *SHOULD* be called within the thread you call divert_loop()
 * but *NOT* in the thread you call divert_loop_stop() !
 */
int divert_clean(divert_t *divert_handle, char *errmsg);

#endif //LIBDIVERT_DIVERT_H
