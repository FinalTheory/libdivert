#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/event.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <libproc.h>
#include "divert.h"
#include "divert_ipfw.h"
#include "dump_packet.h"
#include "assert.h"
#include "nids.h"
#define TUPLE4
#include "KernFunc.h"

extern pid_t tcp_stream_pid, tcp_stream_epid;

/*
 * only constant and parameter variables could be assigned here
 * no dynamic memory allocation
 * this function could only be called once within a process
 * if called more than twice, it would return the first created handle
 */
divert_t *divert_create(int port_number, u_int32_t flags, char *errmsg) {
    errmsg[0] = 0;
    divert_t *divert_handle;
    divert_handle = malloc(sizeof(divert_t));

    // all pointers in divert_handle would be NULL
    memset(divert_handle, 0, sizeof(divert_t));

    divert_handle->flags = flags;
    divert_handle->divert_port = port_number;

    divert_handle->thread_buffer_size = PACKET_BUFFER_SIZE;

    return divert_handle;
}

int divert_set_data_buffer_size(divert_t *handle, size_t bufsize) {
    handle->bufsize = bufsize;
    return 0;
}

int divert_set_thread_buffer_size(divert_t *handle, size_t bufsize) {
    handle->thread_buffer_size = bufsize;
    return 0;
}

int divert_set_error_handler(divert_t *handle, divert_error_handler_t handler) {
    handle->err_handler = handler;
    return 0;
}

int divert_set_callback(divert_t *handle, divert_callback_t callback, void *args) {
    handle->callback = callback;
    handle->callback_args = args;
    return 0;
}

int divert_set_pcap_filter(divert_t *divert_handle, char *pcap_filter, char *errmsg) {
    errmsg[0] = 0;
    /* compiled filter program (expression) */
    struct bpf_program fp;

    /* if the pcap filter is not NULL, then apply it */
    if (pcap_filter != NULL) {
        /* compile the filter expression */
        if (pcap_compile(divert_handle->pcap_handle, &fp,
                         pcap_filter, 0, PCAP_NETMASK_UNKNOWN) != 0) {
            sprintf(errmsg, "Couldn't parse filter %s: %s",
                    pcap_filter, pcap_geterr(divert_handle->pcap_handle));
            return PCAP_FAILURE;
        }

        /* apply the compiled filter */
        if (pcap_setfilter(divert_handle->pcap_handle, &fp) != 0) {
            sprintf(errmsg, "Couldn't install filter %s: %s",
                    pcap_filter, pcap_geterr(divert_handle->pcap_handle));
            return PCAP_FAILURE;
        }
    }
    return 0;
}

int divert_set_filter(divert_t *handle, char *divert_filter, char *errmsg) {
    size_t rule_len = strlen(divert_filter);
    char *divert_filter_new = malloc(rule_len + 1);
    strcpy(divert_filter_new, divert_filter);
    // do not use the packet queue
    // because the size may grow and not cleaned in time
    if (ipfw_delete(DEFAULT_IPFW_RULE_ID, errmsg) != 0) {
        return -1;
    }
    int ret_val = ipfw_setup(divert_filter_new,
                             (u_short)handle->divert_port, errmsg);
    free(divert_filter_new);
    return ret_val;
}

static int divert_init_pcap_handle(divert_t *divert_handle, char *errmsg) {

    pcap_t *pcap_handle;
    char *dev = PKTAP_IFNAME ",all";

    /* open capture device */
    pcap_handle = pcap_create(dev, errmsg);
    /* backup the handler of pcap */
    divert_handle->pcap_handle = pcap_handle;

    if (pcap_handle == NULL) {
        sprintf(errmsg, "Couldn't open device %s: %s", dev, strerror(errno));
        return PCAP_FAILURE;
    }

    /*
     * must be called before pcap_activate()
     * do not need error handling for pcap_set_immediate_mode()
     * and pcap_set_want_pktap(), because they just set flags
     */
    pcap_set_immediate_mode(pcap_handle, 1);
    pcap_set_want_pktap(pcap_handle, 1);
    if (divert_handle->bufsize > 0) {
        pcap_set_buffer_size(pcap_handle, (int)divert_handle->bufsize);
    }

    if (pcap_activate(pcap_handle) != 0) {
        sprintf(errmsg, "Couldn't activate pcap handle: %s", strerror(errno));
        return PCAP_FAILURE;
    }

    if (pcap_apple_set_exthdr(pcap_handle, 1) != 0) {
        sprintf(errmsg, "Couldn't set exthdr: %s", strerror(errno));
        return PCAP_FAILURE;
    }

    /*
     * make sure we're capturing on a DLT_PKTAP device
     * or we can't get process information
     */
    int dt = pcap_datalink(pcap_handle);
    if (dt != DLT_PKTAP) {
        sprintf(errmsg, "Error: \"%s\" is not a DLT_PKTAP device, but is: %s",
                dev, pcap_datalink_val_to_name(dt));
        return PCAP_FAILURE;
    }

    if (divert_set_pcap_filter(divert_handle, "", errmsg) != 0) {
        return PCAP_FAILURE;
    }

    /* read the information of pcap handler */
    divert_handle->bpf_fd = pcap_handle->fd;
    divert_handle->bpf_buffer = pcap_handle->buffer;
    divert_handle->bufsize = (size_t)pcap_handle->bufsize;
    // create buffer for divert packets
    divert_handle->packet_map = packet_map_create();

    return 0;
}

static int divert_init_divert_socket(divert_t *divert_handle, char *errmsg) {

    divert_handle->divert_fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_handle->divert_fd == -1) {
        sprintf(errmsg, "Couldn't open a divert socket");
        return DIVERT_FAILURE;
    }

    struct sockaddr_in divert_port_addr;
    // here *MUST* be init although seems no use
    socklen_t sin_len = sizeof(struct sockaddr);

    // fill in the socket address
    divert_port_addr.sin_family = AF_INET;
    divert_port_addr.sin_port = htons(divert_handle->divert_port);
    divert_port_addr.sin_addr.s_addr = 0;

    // bind divert socket to port
    if (bind(divert_handle->divert_fd, (struct sockaddr *)&divert_port_addr,
             sizeof(struct sockaddr_in)) != 0) {
        sprintf(errmsg, "Couldn't bind divert socket "
                "to port: %s", strerror(errno));
        return DIVERT_FAILURE;
    }

    // if this port is auto allocated
    // then find its real value by getsockname()
    if (divert_handle->divert_port == 0) {
        if (getsockname(divert_handle->divert_fd,
                        (struct sockaddr *)&divert_port_addr, &sin_len) != 0) {
            sprintf(errmsg, "Couldn't get the address of "
                    "the divert socket: %s", strerror(errno));
            return DIVERT_FAILURE;
        } else {
            divert_handle->divert_port = ntohs(divert_port_addr.sin_port);
        }
    }

    // setup firewall to redirect all traffic to divert socket
    if (ipfw_setup(NULL, (u_short)divert_handle->divert_port, errmsg) != 0) {
        return FIREWALL_FAILURE;
    }

    /* allocate thread buffer to store labeled packet */
    divert_handle->thread_buffer = malloc(sizeof(packet_buf_t));
    if (divert_buf_init(divert_handle->thread_buffer,
                        divert_handle->thread_buffer_size, errmsg) != 0) {
        return PCAP_BUFFER_FAILURE;
    }

    if (divert_handle->bufsize == 0) {
        divert_handle->bufsize = PCAP_DEFAULT_BUFSIZE;
    }
    // finally allocate memory for divert buffer
    divert_handle->divert_buffer = malloc((size_t)divert_handle->bufsize);
    memset(divert_handle->divert_buffer, 0, (size_t)divert_handle->bufsize);

    return 0;
}

static int divert_init_kernel_ctl_iface(int *fd, char *errmsg) {
    // open socket for pid query
    int kext_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (kext_fd < 0) {
        sprintf(errmsg, "Could not open kext socket: %s", strerror(errno));
        return DIVERT_FAILURE;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, KEXT_CTL_NAME, sizeof(info.ctl_name));
    if (ioctl(kext_fd, CTLIOCGINFO, &info) != 0) {
        sprintf(errmsg, "Could not get ID for kernel control: %s", strerror(errno));
        return DIVERT_FAILURE;
    }

    struct sockaddr_ctl addr;
    bzero(&addr, sizeof(addr));
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = 0;

    int ret_val = connect(kext_fd, (struct sockaddr *)&addr, sizeof(addr));
    if (ret_val != 0) {
        sprintf(errmsg, "Could not connect to kernel control: %s", strerror(errno));
        return DIVERT_FAILURE;
    }

    *fd = kext_fd;
    return 0;
}

int divert_extract_raw_socket_info(struct ip *ip_hdr, struct tuple4 *result) {
    bzero(result, sizeof(struct tuple4));
    size_t ip_len = (ip_hdr->ip_hl) << 2;
    if (ip_len < MIN_IP_HEADER_SIZE) {
        return -1;
    }
    u_char *payload = (u_char *)ip_hdr + ip_len;
    result->saddr = ip_hdr->ip_src.s_addr;
    result->daddr = ip_hdr->ip_dst.s_addr;
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_hdr = (struct tcphdr *)payload;
        result->source = tcp_hdr->th_sport;
        result->dest = tcp_hdr->th_dport;
    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_hdr = (struct udphdr *)payload;
        result->source = udp_hdr->uh_sport;
        result->dest = udp_hdr->uh_dport;
    } else {
        return -1;
    }
    return 0;
}

int divert_query_proc_by_packet(divert_t *handle,
                                struct ip *ip_hdr,
                                struct sockaddr *sin,
                                proc_info_t *result) {
    struct qry_data input_data;
    socklen_t len = sizeof(input_data);
    memset(&input_data, 0, sizeof(input_data));
    input_data.proto = ip_hdr->ip_p;
    strncpy(input_data.iface,
            ((struct sockaddr_in *)sin)->sin_zero,
            sizeof(input_data.iface));
    if (divert_extract_raw_socket_info(ip_hdr,
                                       &input_data.sock_info) != 0) {
        goto fail;
    }

    int ctl_flag = 0;
    if (divert_is_outbound(sin)) {
        ctl_flag = KERN_CTL_OUTBOUND;
    } else if (divert_is_inbound(sin, NULL)) {
        ctl_flag = KERN_CTL_INBOUND;
    } else {
        goto fail;
    }

    if (getsockopt(handle->kext_fd, SYSPROTO_CONTROL,
                   ctl_flag, &input_data, &len) != 0) {
        goto fail;
    }

    result->pid = input_data.pid;
    result->epid = input_data.epid;
    pid_t pid = result->pid == -1 ? result->epid : result->pid;
    if (pid != -1) {
        proc_name(pid, result->comm, sizeof(result->comm));
    } else {
        goto fail;
    }
    return 0;

    fail:
    result->pid = -1;
    result->epid = -1;
    result->comm[0] = 0;
    return -1;
}

struct tcp_stream *
divert_find_tcp_stream(struct ip *ip_hdr) {
    struct tuple4 sock_info, reversed;
    if (divert_extract_raw_socket_info(ip_hdr,
                                       &sock_info) != 0) {
        return NULL;
    } else {
        // convert into host sequence
        sock_info.source = ntohs(sock_info.source);
        sock_info.dest = ntohs(sock_info.dest);
    }
    struct tcp_stream *a_tcp;
    if ((a_tcp = nids_find_tcp_stream(&sock_info)) != NULL) {
        return a_tcp;
    } else {
        reversed.source = sock_info.dest;
        reversed.dest = sock_info.source;
        reversed.saddr = sock_info.daddr;
        reversed.daddr = sock_info.saddr;
        return nids_find_tcp_stream(&reversed);
    }
}

#define TCPDUMP_MAGIC        0xa1b2c3d4

int divert_init_pcap(FILE *fp, char *errmsg) {
    struct pcap_file_header hdr;
    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.snaplen = 65545;
    hdr.sigfigs = 0;
    hdr.linktype = DLT_EN10MB;
    if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1) {
        sprintf(errmsg, "Could not create pcap header: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int divert_dump_pcap(struct ip *packet, FILE *fp, char *errmsg) {
    struct pcap_sf_pkthdr sf_hdr;
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    sf_hdr.ts.tv_sec = (bpf_int32)tv.tv_sec;
    sf_hdr.ts.tv_usec = (bpf_int32)tv.tv_usec;
    size_t ip_len = ntohs(packet->ip_len);
    sf_hdr.caplen = sf_hdr.len = (bpf_int32)(ip_len + ETHER_HDR_LEN);
    struct ether_header ether_hdr;
    memset(&ether_hdr, 0, sizeof(ether_hdr));
    ether_hdr.ether_type = htons(ETHERTYPE_IP);
    size_t ret_val;
    ret_val = fwrite(&sf_hdr, 1, sizeof(sf_hdr), fp);
    if (ret_val != sizeof(sf_hdr)) {
        sprintf(errmsg, "Error on fwrite: %s", strerror(errno));
        return -1;
    }
    ret_val = fwrite(&ether_hdr, 1, sizeof(ether_hdr), fp);
    if (ret_val != sizeof(ether_hdr)) {
        sprintf(errmsg, "Error on fwrite: %s", strerror(errno));
        return -1;
    }
    ret_val = fwrite(packet, 1, ip_len, fp);
    if (ret_val != ip_len) {
        sprintf(errmsg, "Error on fwrite: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int divert_activate(divert_t *divert_handle, char *errmsg) {
    // clean error message
    errmsg[0] = 0;
    int status = 0;

    /*
     * first init pcap metadata
     * if we need pktap header or TCP reassemble
     */
    if (divert_handle->flags & DIVERT_FLAG_USE_PKTAP) {
        status = divert_init_pcap_handle(divert_handle, errmsg);
        if (status != 0) {
            return status;
        }
    } else {
        // if not use PKTAP, then check if KEXT is loaded
        // and setup query file descriptor
        if (divert_init_kernel_ctl_iface(&divert_handle->kext_fd, errmsg) != 0) {
            return DIVERT_FAILURE;
        }
    }

    /*
     * then init divert socket
     */
    status = divert_init_divert_socket(divert_handle, errmsg);
    if (status != 0) {
        return status;
    }

    // if uses blocking IO then set the callback to NULL
    if (divert_handle->flags & DIVERT_FLAG_BLOCK_IO) {
        divert_handle->callback = NULL;
    } else {
        if (divert_handle->callback == NULL) {
            sprintf(errmsg, "Error: callback function not set!");
            return CALLBACK_NOT_FOUND;
        }
    }

    if (pipe(divert_handle->pipe_fd) != 0 ||
        pipe(divert_handle->exit_fd) != 0) {
        sprintf(errmsg, "Could not create pipe: %s", strerror(errno));
        return PIPE_OPEN_FAILURE;
    }

    /*
     * init for TCP reassemble
     */
    nids_params.n_tcp_streams = NUM_TCP_STREAMS;
    nids_params.scan_num_ports = 0;
    if (divert_handle->flags & DIVERT_FLAG_USE_PKTAP) {
        nids_params.pcap_desc = divert_handle->pcap_handle;
    }

    // when packets are diverted before sending,
    // the checksum of that packet is not calculated
    // because of the checksum offload mechanism
    // so we need to disable that procedure
    struct nids_chksum_ctl *chksum_ctl =
            malloc(sizeof(struct nids_chksum_ctl));
    memset(chksum_ctl, 0, sizeof(struct nids_chksum_ctl));
    chksum_ctl->action = NIDS_DONT_CHKSUM;
    nids_register_chksum_ctl(chksum_ctl, 1);
    if (!nids_init()) {
        strcpy(errmsg, nids_errbuf);
        return NIDS_FAILURE;
    }

    divert_handle->is_looping = 1;

    return 0;
}

static inline packet_info_t *divert_new_error_packet(u_int64_t flag) {
    packet_info_t *new_packet = malloc(sizeof(packet_info_t));
    new_packet->ip_data = NULL;
    new_packet->pktap_hdr = NULL;
    new_packet->time_stamp = flag;
    return new_packet;
}

static void divert_feed_nids(struct ip *packet) {
    struct timeval tv;
    struct timezone tz;
    struct pcap_pkthdr pkthdr;

    gettimeofday(&tv, &tz);
    pkthdr.ts.tv_sec = tv.tv_sec;
    pkthdr.ts.tv_usec = tv.tv_usec;
    pkthdr.caplen = pkthdr.len = ntohs(packet->ip_len);
    pkthdr.comment[0] = 0;

    nids_pcap_handler(NULL, &pkthdr, (u_char *)packet);
}

static void *divert_thread_callback(void *arg) {
    packet_info_t *packet;
    divert_t *handle = (divert_t *)arg;
    packet_buf_t *buf = handle->thread_buffer;
    divert_callback_t callback = handle->callback;
    void *callback_args = handle->callback_args;
    while (handle->is_looping) {
        packet = divert_buf_remove(buf);
        // if this is a normal data packet
        if (packet->time_stamp &
            (DIVERT_RAW_BPF_PACKET |
             DIVERT_RAW_IP_PACKET)) {
            // call the callback function
            if (handle->flags & DIVERT_FLAG_USE_PKTAP) {
                callback(callback_args, packet->pktap_hdr,
                         packet->ip_data, packet->sin);
            } else {
                if (handle->flags & DIVERT_FLAG_TCP_REASSEM) {
                    tcp_stream_pid = packet->proc_info->pid;
                    tcp_stream_epid = packet->proc_info->epid;
                    divert_feed_nids(packet->ip_data);
                }
                callback(callback_args, packet->proc_info,
                         packet->ip_data, packet->sin);
            }
            free(packet->ip_data);
            free(packet->proc_info);
            free(packet->sin);
            free(packet);
        } else if (packet->time_stamp &
                   (DIVERT_ERROR_BPF_INVALID |
                    DIVERT_ERROR_BPF_NODATA |
                    DIVERT_ERROR_DIVERT_NODATA |
                    DIVERT_ERROR_KQUEUE)) {
            // call the error handling function
            if (handle->err_handler != NULL) {
                handle->err_handler(packet->time_stamp);
            }
            free(packet);
        } else if (packet->time_stamp & DIVERT_STOP_LOOP) {
            free(packet);
            break;
        }
        // if the cache is too big, and this thread buffer is empty
        if (handle->thread_buffer->size == 0 &&
            handle->flags & (DIVERT_FLAG_USE_PKTAP | DIVERT_FLAG_AUTO_FREE) &&
            packet_map_get_size(handle->packet_map) > PACKET_INFO_CACHE_SIZE) {
            // then just free it
            packet_map_clean(handle->packet_map);
        }
    }
    handle->is_looping = 0;
    return NULL;
}

static u_char divert_extract_IP_port(packet_hdrs_t *packet_hdrs,
                                     in_addr_t *ip_src,
                                     in_addr_t *ip_dst,
                                     u_short *port_src,
                                     u_short *port_dst, unsigned short *chksum) {
    u_char is_tcpudp = 0;
    *ip_src = packet_hdrs->ip_hdr->ip_src.s_addr;
    *ip_dst = packet_hdrs->ip_hdr->ip_dst.s_addr;
    if (packet_hdrs->size_tcp) {
        is_tcpudp = 1;
        *port_src = packet_hdrs->tcp_hdr->th_sport;
        *port_dst = packet_hdrs->tcp_hdr->th_dport;
        *chksum = packet_hdrs->tcp_hdr->th_sum;
    } else if (packet_hdrs->size_udp) {
        is_tcpudp = 1;
        *port_src = packet_hdrs->udp_hdr->uh_sport;
        *port_dst = packet_hdrs->udp_hdr->uh_dport;
        *chksum = packet_hdrs->udp_hdr->uh_sum;
    }
    return is_tcpudp;
}

static void divert_loop_with_pktap(divert_t *divert_handle, int count) {
    u_char found_info;
    in_addr_t ip_src, ip_dst;
    u_short port_src, port_dst, chksum;
    void *ret_val;
    pthread_t *divert_thread_callback_handle = calloc(1, sizeof(pthread_t));
    ssize_t num_divert, num_bpf;
    char errmsg[PCAP_ERRBUF_SIZE];

    socklen_t sin_len = sizeof(struct sockaddr);

    packet_hdrs_t packet_hdrs;

    divert_handle->is_looping = 1;
    divert_handle->num_missed = 0;
    divert_handle->num_diverted = 0;
    divert_handle->num_captured = 0;
    divert_handle->current_time_stamp = 0;

    // only start new thread in non-blocking mode
    if (!(divert_handle->flags & DIVERT_FLAG_BLOCK_IO)) {
        pthread_create(divert_thread_callback_handle, NULL, divert_thread_callback, divert_handle);
    }

    /* register two file descriptor into kqueue */
    int kq = kqueue();
    struct kevent changes[3];
    EV_SET(&changes[0], divert_handle->divert_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&changes[1], divert_handle->bpf_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&changes[2], divert_handle->pipe_fd[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    int ret = kevent(kq, changes, 3, NULL, 0, NULL);
    if (ret == -1) {
        fprintf(stderr, "kevent failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int num_events;
    /* array to hold kqueue events */
    struct kevent events[MAX_EVENT_COUNT];
    while (divert_handle->is_looping) {
        // if the kevent is interrupted by signal, then just retry it
        do {
            num_events = kevent(kq, NULL, 0, events, MAX_EVENT_COUNT, NULL);
        } while (num_events == -1 && errno == EINTR);

        /*
         * this is a small optimization
         * ensure that we first read from BPF device
         * then read and divert packets from socket
         */
        if (num_events == 2) {
            if (events[0].ident == divert_handle->divert_fd) {
                struct kevent tmp;
                tmp = events[0];
                events[0] = events[1];
                events[1] = tmp;
            }
        }
        if (num_events == -1) {
            divert_buf_insert(divert_handle->thread_buffer,
                              divert_new_error_packet(DIVERT_ERROR_KQUEUE));
        } else {
            for (int i = 0; i < num_events; i++) {
                uintptr_t fd = events[i].ident;
                if (fd == divert_handle->bpf_fd) {
                    // returns a packet of BPF structure
                    num_bpf = read(divert_handle->bpf_fd,
                                   divert_handle->bpf_buffer,
                                   divert_handle->bufsize);
                    // divert_handle the BPF packet: just push it into queue
                    // things in the queue are pointers to packet_info_t
                    if (num_bpf > 0) {
                        u_char *data_p = divert_handle->bpf_buffer;
                        u_char *end_p = divert_handle->bpf_buffer + num_bpf;
                        while (data_p < end_p) {
                            // first dump the headers of this packet
                            divert_dump_packet(data_p, &packet_hdrs, ~0u, errmsg);
                            if (packet_hdrs.size_ip) {
                                if (divert_handle->flags & DIVERT_FLAG_TCP_REASSEM) {
                                    // fill in the pcap header structure
                                    struct pcap_pkthdr pkthdr;
                                    pkthdr.ts.tv_sec = packet_hdrs.bhep_hdr->bh_tstamp.tv_sec;
                                    pkthdr.ts.tv_usec = packet_hdrs.bhep_hdr->bh_tstamp.tv_usec;
                                    pkthdr.len = pkthdr.caplen = ntohs(packet_hdrs.ip_hdr->ip_len);
                                    pkthdr.comment[0] = 0;

                                    // call the pcap handler of libnids
                                    nids_pcap_handler(NULL, &pkthdr, (u_char *)packet_hdrs.ip_hdr);
                                }
                                size_t packet_size = BPF_WORDALIGN(packet_hdrs.bhep_hdr->bh_caplen +
                                                                   packet_hdrs.bhep_hdr->bh_hdrlen);
                                if (packet_hdrs.pktap_hdr->pth_pid != -1 ||
                                    packet_hdrs.pktap_hdr->pth_epid != -1) {
                                    // insert it into packet map
                                    if (divert_extract_IP_port(&packet_hdrs, &ip_src,
                                                               &ip_dst, &port_src, &port_dst, &chksum)) {
                                        packet_map_insert(divert_handle->packet_map, ip_src, ip_dst,
                                                          port_src, port_dst, chksum, packet_hdrs.pktap_hdr);
                                    }
                                }
                                divert_handle->num_captured++;
                                // update the data pointer
                                data_p += packet_size;
                            } else {
                                divert_buf_insert(divert_handle->thread_buffer,
                                                  divert_new_error_packet(DIVERT_ERROR_BPF_INVALID));
                                // if there is error when dumping the BPF packet
                                // this means it reaches the end of buffer
                                // just exit the loop
                                break;
                            }
                        }
                    } else {
                        divert_buf_insert(divert_handle->thread_buffer,
                                          divert_new_error_packet(DIVERT_ERROR_BPF_NODATA));
                    }
                } else if (fd == divert_handle->divert_fd) {
                    struct sockaddr *sin = malloc(sin_len);
                    // returns a packet of IP protocol structure
                    num_divert = recvfrom(divert_handle->divert_fd,
                                          divert_handle->divert_buffer,
                                          divert_handle->bufsize, 0,
                                          sin, &sin_len);

                    if (num_divert > 0) {
                        // extract the headers of current packet
                        divert_dump_packet(divert_handle->divert_buffer,
                                           &packet_hdrs, DIVERT_DUMP_IP_HEADER, errmsg);
                        if (packet_hdrs.size_ip) {
                            found_info = 0;
                            struct pktap_header *pktap_hdr;
                            if (divert_extract_IP_port(&packet_hdrs, &ip_src,
                                                       &ip_dst, &port_src, &port_dst, &chksum) &&
                                (pktap_hdr = packet_map_query(divert_handle->packet_map,
                                                              ip_src, ip_dst,
                                                              port_src, port_dst, chksum)) != NULL) {
                                found_info = 1;
                                size_t ip_length = ntohs(packet_hdrs.ip_hdr->ip_len);
                                packet_info_t *new_packet = malloc(sizeof(packet_info_t));
                                new_packet->time_stamp = DIVERT_RAW_IP_PACKET;
                                new_packet->pktap_hdr = pktap_hdr;
                                new_packet->sin = sin;
                                // allocate memory
                                new_packet->ip_data = malloc(ip_length);
                                // and copy data
                                memcpy(new_packet->ip_data, packet_hdrs.ip_hdr, ip_length);
                                divert_buf_insert(divert_handle->thread_buffer, new_packet);
                            }
                            if (!found_info) {
                                // if packet is not found in the queue, then just send it to user
                                size_t ip_length = ntohs(packet_hdrs.ip_hdr->ip_len);
                                packet_info_t *new_packet = malloc(sizeof(packet_info_t));
                                new_packet->sin = sin;
                                new_packet->time_stamp = DIVERT_RAW_IP_PACKET;
                                // but the packet information is NULL
                                new_packet->pktap_hdr = NULL;
                                // allocate memory
                                new_packet->ip_data = malloc(ip_length);
                                // and copy data
                                memcpy(new_packet->ip_data, packet_hdrs.ip_hdr, ip_length);
                                divert_buf_insert(divert_handle->thread_buffer, new_packet);
                                divert_handle->num_missed++;
                            } else {
                                divert_handle->num_diverted++;
                            }
                        }
                    } else {
                        // no valid data, so insert a flag into thread buffer
                        divert_buf_insert(divert_handle->thread_buffer,
                                          divert_new_error_packet(DIVERT_ERROR_DIVERT_NODATA));
                        free(sin);
                    }
                } else if (fd == divert_handle->pipe_fd[0]) {
                    // if we could read from pipe
                    // then just exit the event loop
                    char pipe_buf[PIPE_BUFFER_SIZE];
                    read(divert_handle->pipe_fd[0], pipe_buf, sizeof(pipe_buf));
                    if (pipe_buf[0] == 'e') {
                        goto finish;
                    }
                }
            }
        }
        // increase time stamp
        divert_handle->current_time_stamp++;
        if (count > 0 && divert_handle->num_diverted >= count) {
            goto finish;
        }
    }
    finish:
    divert_handle->is_looping = 0;
    // insert an item into the thread buffer to stop another thread
    divert_buf_insert(divert_handle->thread_buffer,
                      divert_new_error_packet(DIVERT_STOP_LOOP));

    if (!(divert_handle->flags & DIVERT_FLAG_BLOCK_IO)) {
        // wait until the child thread is stopped
        pthread_join(*divert_thread_callback_handle, &ret_val);
    }

    char exit_str[] = "success";
    write(divert_handle->exit_fd[1], exit_str, sizeof(exit_str));
}

static void divert_loop_with_kext(divert_t *divert_handle, int count) {
    // return value of thread
    void *ret_val;
    // number of diverted bytes
    ssize_t num_divert;
    // struct to hold packet headers
    packet_hdrs_t packet_hdrs;
    // error message buffer
    char errmsg[PCAP_ERRBUF_SIZE];
    pthread_t *divert_thread_callback_handle = calloc(1, sizeof(pthread_t));
    socklen_t sin_len = sizeof(struct sockaddr);

    /* store the callback function
     * and arguments into divert handle
     */
    divert_handle->is_looping = 1;
    divert_handle->num_diverted = 0;
    // only start new thread in non-blocking mode
    if (!(divert_handle->flags & DIVERT_FLAG_BLOCK_IO)) {
        pthread_create(divert_thread_callback_handle, NULL, divert_thread_callback, divert_handle);
    }

    /* register two file descriptor into kqueue */
    int kq = kqueue();
    struct kevent changes[2];
    EV_SET(&changes[0], divert_handle->divert_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&changes[1], divert_handle->pipe_fd[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    int ret = kevent(kq, changes, 2, NULL, 0, NULL);
    if (ret == -1) {
        fprintf(stderr, "kevent failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }

    int num_events;
    /* array to hold kqueue events */
    struct kevent events[MAX_EVENT_COUNT];
    while (divert_handle->is_looping) {
        struct sockaddr *sin = calloc(sin_len, sizeof(u_char));
        // if the kevent is interrupted by signal, then just retry it
        do {
            num_events = kevent(kq, NULL, 0, events, MAX_EVENT_COUNT, NULL);
        } while (num_events == -1 && errno == EINTR);

        if (num_events == -1) {
            divert_buf_insert(divert_handle->thread_buffer,
                              divert_new_error_packet(DIVERT_ERROR_KQUEUE));
        } else {
            for (int i = 0; i < num_events; i++) {
                uintptr_t fd = events[i].ident;
                if (fd == divert_handle->divert_fd) {
                    // returns a packet of IP protocol structure
                    num_divert = recvfrom(divert_handle->divert_fd,
                                          divert_handle->divert_buffer,
                                          divert_handle->bufsize, 0,
                                          sin, &sin_len);

                    if (num_divert > 0) {
                        // extract the headers of current packet
                        divert_dump_packet(divert_handle->divert_buffer,
                                           &packet_hdrs, DIVERT_DUMP_IP_HEADER, errmsg);
                        if (packet_hdrs.size_ip) {
                            // if packet is not found in the queue, then just send it to user
                            size_t ip_length = ntohs(packet_hdrs.ip_hdr->ip_len);
                            packet_info_t *new_packet = malloc(sizeof(packet_info_t));
                            new_packet->sin = sin;
                            new_packet->time_stamp = DIVERT_RAW_IP_PACKET;
                            // but the packet information is NULL
                            new_packet->pktap_hdr = NULL;
                            // allocate memory
                            new_packet->ip_data = malloc(ip_length);
                            new_packet->proc_info = malloc(sizeof(proc_info_t));
                            divert_query_proc_by_packet(divert_handle,
                                                        packet_hdrs.ip_hdr, sin,
                                                        new_packet->proc_info);
                            // and copy data
                            memcpy(new_packet->ip_data, packet_hdrs.ip_hdr, ip_length);
                            divert_buf_insert(divert_handle->thread_buffer, new_packet);
                            divert_handle->num_diverted++;
                        }
                    } else {
                        // no valid data, so insert a flag into thread buffer
                        divert_buf_insert(divert_handle->thread_buffer,
                                          divert_new_error_packet(DIVERT_ERROR_DIVERT_NODATA));
                        free(sin);
                    }
                    if (count > 0 && divert_handle->num_diverted > count) {
                        goto finish;
                    }
                } else if (fd == divert_handle->pipe_fd[0]) {
                    // end the event loop
                    char pipe_buf[PIPE_BUFFER_SIZE];
                    read(divert_handle->pipe_fd[0], pipe_buf, sizeof(pipe_buf));
                    if (pipe_buf[0] == 'e') {
                        goto finish;
                    }
                }
            }
        }
    }
    finish:
    divert_handle->is_looping = 0;
    // insert an item into the thread buffer to stop another thread
    divert_buf_insert(divert_handle->thread_buffer,
                      divert_new_error_packet(DIVERT_STOP_LOOP));

    if (!(divert_handle->flags & DIVERT_FLAG_BLOCK_IO)) {
        // wait until the child thread is stopped
        pthread_join(*divert_thread_callback_handle, &ret_val);
    }

    char exit_str[] = "success";
    write(divert_handle->exit_fd[1], exit_str, sizeof(exit_str));
}

typedef void (*divert_loop_func_t)(divert_t *, int);

// this typedef is only used here
typedef struct {
    divert_loop_func_t loop_function;
    divert_t *divert_handle;
    int count;
} __tmp_data_t;

void *divert_non_block_thread(void *args) {
    __tmp_data_t *data = (__tmp_data_t *)args;
    data->loop_function(data->divert_handle, data->count);
    return NULL;
}

void divert_loop(divert_t *divert_handle, int count) {
    divert_loop_func_t loop_function;
    if (divert_handle->flags & DIVERT_FLAG_USE_PKTAP) {
        loop_function = divert_loop_with_pktap;
    } else {
        loop_function = divert_loop_with_kext;
    }

    // if use block IO, then
    // this function should be non-blocking
    if (divert_handle->flags & DIVERT_FLAG_BLOCK_IO) {
        __tmp_data_t *args = malloc(sizeof(__tmp_data_t));
        args->count = count;
        args->divert_handle = divert_handle;
        args->loop_function = loop_function;
        pthread_t non_block_thread;
        pthread_create(&non_block_thread, NULL, divert_non_block_thread, args);
        pthread_detach(non_block_thread);
    } else {
        loop_function(divert_handle, count);
    }
}

int divert_is_inbound(struct sockaddr *sin_raw, char *interface) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sin_raw;
    if (sin->sin_addr.s_addr != INADDR_ANY) {
        if (interface != NULL) {
            strncpy(interface, sin->sin_zero, sizeof(sin->sin_zero));
        }
        return 1;
    } else {
        return 0;
    }
}

int divert_is_outbound(struct sockaddr *sin_raw) {
    struct sockaddr_in *sin = (struct sockaddr_in *)sin_raw;
    return sin->sin_addr.s_addr == INADDR_ANY;
}

ssize_t divert_read(divert_t *handle,
                    u_char *pktap_hdr,
                    u_char *ip_data,
                    u_char *sin) {
    int ret_val = 0;
    // make it non-blocking if event loop is stopped
    if (!handle->is_looping ||
        handle->thread_buffer == NULL) {
        ret_val = DIVERT_READ_EOF;
    } else {
        packet_info_t *packet =
                divert_buf_remove(handle->thread_buffer);
        // do flag checking
        if (packet->time_stamp &
            (DIVERT_RAW_BPF_PACKET |
             DIVERT_RAW_IP_PACKET)) {
            // copy the data to user buffer
            memcpy(ip_data, packet->ip_data,
                   ntohs(packet->ip_data->ip_len));
            memcpy(sin, packet->sin, sizeof(struct sockaddr));
            if (handle->flags & DIVERT_FLAG_USE_PKTAP) {
                // if pktap header is not NULL, copy it
                if (packet->pktap_hdr != NULL) {
                    memcpy(pktap_hdr, packet->pktap_hdr,
                           packet->pktap_hdr->pth_length);
                } else {
                    memset(pktap_hdr, 0, sizeof(struct pktap_header));
                }
            } else {
                if (handle->flags & DIVERT_FLAG_TCP_REASSEM) {
                    tcp_stream_pid = packet->proc_info->pid;
                    tcp_stream_epid = packet->proc_info->epid;
                    divert_feed_nids(packet->ip_data);
                }
                memcpy(pktap_hdr, packet->proc_info, sizeof(proc_info_t));
            }
            // free the allocated memory
            free(packet->ip_data);
            free(packet->proc_info);
            free(packet->sin);
            free(packet);
            ret_val = 0;
        } else if (packet->time_stamp &
                   (DIVERT_ERROR_BPF_INVALID |
                    DIVERT_ERROR_BPF_NODATA |
                    DIVERT_ERROR_DIVERT_NODATA |
                    DIVERT_ERROR_KQUEUE)) {
            free(packet);
            ret_val = (int)packet->time_stamp;
        } else if (packet->time_stamp & DIVERT_STOP_LOOP) {
            free(packet);
            handle->is_looping = 0;
            ret_val = DIVERT_READ_EOF;
        } else {
            ret_val = DIVERT_READ_UNKNOWN_FLAG;
        }

        // if the cache is too big, and this thread buffer is empty
        if (handle->thread_buffer->size == 0 &&
            handle->flags & (DIVERT_FLAG_USE_PKTAP | DIVERT_FLAG_AUTO_FREE) &&
            packet_map_get_size(handle->packet_map) > PACKET_INFO_CACHE_SIZE) {
            // then just free it
            packet_map_clean(handle->packet_map);
        }
    }
    return ret_val;
}

ssize_t divert_reinject(divert_t *handle, struct ip *packet,
                        ssize_t length, struct sockaddr *sin) {
    socklen_t sin_len = sizeof(struct sockaddr);
    if (length < 0) {
        length = ntohs(((struct ip *)packet)->ip_len);
    }
    return sendto(handle->divert_fd, packet,
                  (size_t)length, 0, sin, sin_len);
}

int divert_is_looping(divert_t *handle) {
    return handle->is_looping;
}

void divert_loop_stop(divert_t *handle) {
    char pipe_buf[] = "exit";
    char errmsg[PCAP_ERRBUF_SIZE];
    // set loop flag to zero
    handle->is_looping = 0;
    // write data into pipe to exit event loop
    write(handle->pipe_fd[1], pipe_buf, sizeof(pipe_buf));
    // clean firewall rule
    ipfw_flush(errmsg);
}

int divert_bpf_stats(divert_t *handle, struct pcap_stat *stats) {
    if (handle->pcap_handle != NULL) {
        return pcap_stats(handle->pcap_handle, stats);
    } else {
        return -1;
    }
}

int divert_close(divert_t *divert_handle, char *errmsg) {
    errmsg[0] = 0;

    // guard here to wait until event loop is stopped
    char str_buf[PIPE_BUFFER_SIZE];
    read(divert_handle->exit_fd[0], str_buf, sizeof(str_buf));
    assert(str_buf[0] == 's');

    // close the divert socket and free the buffer
    close(divert_handle->divert_fd);
    if (divert_handle->divert_buffer != NULL) {
        free(divert_handle->divert_buffer);
        divert_buf_clean(divert_handle->thread_buffer, errmsg);
    }

    // close the pcap handler and clean the thread buffer
    if (divert_handle->flags & DIVERT_FLAG_USE_PKTAP) {
        pcap_close(divert_handle->pcap_handle);
        packet_map_free(divert_handle->packet_map);
    } else {
        close(divert_handle->kext_fd);
    }

    // close the pipe descriptor
    close(divert_handle->pipe_fd[0]);
    close(divert_handle->pipe_fd[1]);
    close(divert_handle->exit_fd[0]);
    close(divert_handle->exit_fd[1]);

    memset(divert_handle, 0, sizeof(divert_t));

    return 0;
}

#define MAX_SIGNAL_NUM 128


// array to hold signal handler functions
static divert_signal_t divert_signal_func[MAX_SIGNAL_NUM] = {NULL,};

// array to hold signal handler data
static void *divert_signal_data[MAX_SIGNAL_NUM] = {NULL,};

static u_char divert_signal_flag[MAX_SIGNAL_NUM] = {0,};


void divert_signal_handler(int signum) {
    // if the signal handler is registered
    if (divert_signal_func[signum] != NULL) {
        // then just call the handler funcion with stored data
        divert_signal_func[signum](signum,
                                   divert_signal_data[signum]);
    }
}

int divert_set_signal_handler(int signum,
                              divert_signal_t handler, void *data) {
    if (0 <= signum && signum < MAX_SIGNAL_NUM) {
        divert_signal_func[signum] = handler;
        divert_signal_data[signum] = data;
        if (!divert_signal_flag[signum]) {
            // if it is first time to set signal function
            sig_t ret_val = signal(signum, divert_signal_handler);
            if (ret_val == SIG_ERR) {
                return -1;
            }
            divert_signal_flag[signum] = 1;
        }
        return 0;
    } else {
        return -1;
    }
}

void divert_signal_handler_stop_loop(int signal,
                                     void *handle) {
    divert_loop_stop((divert_t *)handle);
}
