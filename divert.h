#ifndef LIBDIVERT_DIVERT_H
#define LIBDIVERT_DIVERT_H

#include "net/bpf.h"
#include "net/pktap.h"
#include <netinet/ip.h>
#include "netinet/ip_fw.h"
#include "pcap/pcap.h"
#include "pcap/pcap-int.h"

#define PCAP_FAILURE -1
#define DIVERT_FAILURE -2
#define FIREWALL_FAILURE -3

typedef void (*divert_handler_t)();
typedef void (*signal_handler_t)(int);

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
    int bufsize;

    /*
     * pcap handler
     */
    pcap_t *pcap_handle;     // handle for pcap structure

    /*
     * statics information
     */
    u_int64_t current_time_stamp;
    u_int64_t num_missed;

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

divert_t *divert_create(int port_number, char *errmsg);

int divert_set_buffer_size(divert_t *handle, int bufsize);

int divert_set_pcap_filter(divert_t *divert_handle, char *pcap_filter, char *errmsg);

/*
 * after divert_activate() is called, you should *NOT* do any time-consuming work
 * you *SHOULD* call divert_loop() as soon as possible
 * otherwise the diverted packets couldn't be handled in time
 * and this would make your network connection unstable
 */
int divert_activate(divert_t *divert_handle, char *errmsg);

void divert_loop(divert_t *divert_handle, int count,
                 divert_handler_t callback, u_char *args);

void divert_loop_stop();

/*
 * this function *SHOULD* be called within the thread you call divert_loop()
 * but *NOT* in the thread you call divert_loop_stop() !
 */
int divert_clean(divert_t *divert_handle, char *errmsg);

extern volatile u_char is_looping;

#endif //LIBDIVERT_DIVERT_H
