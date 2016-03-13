#include "pcap/pcap-int.h" 
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

int time_greater_than(struct timeval *a,
                      struct timeval *b);

static volatile int ipfw_rule_index = DEFAULT_IPFW_RULE_ID;

static int
cmp_time_event(const void *x, const void *y) {
    if (x == NULL) { return 1; }
    if (y == NULL) { return -1; }
    const timeout_event_t *a = x;
    const timeout_event_t *b = y;
    uint64_t val_a = a->tv.tv_sec *
                     (uint64_t)1000000 +
                     a->tv.tv_usec;
    uint64_t val_b = b->tv.tv_sec *
                     (uint64_t)1000000 +
                     b->tv.tv_usec;
    if (val_a > val_b) {
        return -1;
    } else if (val_a < val_b) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * only constant and parameter variables could be assigned here
 * no dynamic memory allocation
 */
divert_t *divert_create(int port_number, u_int32_t flags) {
    divert_t *divert_handle;
    divert_handle = malloc(sizeof(divert_t));

    // all pointers in divert_handle would be NULL
    memset(divert_handle, 0, sizeof(divert_t));

    divert_handle->pool = divert_create_pool(DEFAULT_PACKET_SIZE);
    if (divert_handle->pool == NULL) {
        free(divert_handle);
        return NULL;
    }
    divert_handle->timer_queue = pqueue_new(cmp_time_event,
                                            TIMER_QUEUE_SIZE);
    divert_handle->flags = flags;
    divert_handle->divert_port = port_number;
    divert_handle->ipfw_id = ipfw_rule_index++;

    return divert_handle;
}

int divert_set_data_buffer_size(divert_t *handle, size_t bufsize) {
    handle->bufsize = bufsize;
    return 0;
}

int divert_set_device(divert_t *handle, char *dev_name) {
    // if already set, just return error
    if (handle->libnet != NULL) {
        sprintf(handle->errmsg, "Device already set.");
        return -1;
    }
    // find the associated ip address of this device
    struct ifaddrs *ifap = NULL, *ifa = NULL;
    struct sockaddr_in *sa = NULL, *sa_mask = NULL;
    int found = 0;
    if (getifaddrs (&ifap)) {
        sprintf(handle->errmsg, "getifaddrs() failed: %s", strerror(errno));
        return -1;
    };
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *)ifa->ifa_addr;
            sa_mask = (struct sockaddr_in *)ifa->ifa_netmask;
            if (strcasecmp(dev_name, ifa->ifa_name) == 0) {
                handle->iface_addr = sa->sin_addr.s_addr;
                handle->iface_mask = sa_mask->sin_addr.s_addr;
                found = 1;
                break;
            }
        }
    }
    handle->iface_addr &= handle->iface_mask;
    freeifaddrs(ifap);
    if (!found) {
        sprintf(handle->errmsg, "Could not find ip address of device %s", dev_name);
        return -1;
    }
    handle->libnet = libnet_init(LIBNET_RAW4_ADV, dev_name, handle->errmsg);
    if (handle->libnet == NULL) { return -1; }
    return 0;
}

int divert_device_inbound(divert_t *handle, struct ip *packet) {
    if (handle->libnet == NULL) { return 0; }
    if ((packet->ip_dst.s_addr & handle->iface_mask) == handle->iface_addr &&
        (packet->ip_src.s_addr & handle->iface_mask) != handle->iface_addr) { return 1; }
    return 0;
}

int divert_device_outbound(divert_t *handle, struct ip *packet) {
    if (handle->libnet == NULL) { return 0; }
    if ((packet->ip_dst.s_addr & handle->iface_mask) != handle->iface_addr &&
        (packet->ip_src.s_addr & handle->iface_mask) == handle->iface_addr) { return 1; }
    return 0;
}

int divert_set_error_handler(divert_t *handle, divert_error_handler_t handler) {
    handle->err_handler = handler;
    return 0;
}

int divert_set_callback(divert_t *handle, divert_callback_t callback, void *args) {
    if (callback == NULL) {
        sprintf(handle->errmsg, "Callback function should not be NULL.");
        return -1;
    }
    handle->callback = callback;
    handle->callback_args = args;
    return 0;
}

int divert_register_timer(divert_t *handle,
                          const struct timeval *timeout,
                          void *data, uint32_t flag) {
    timeout_event_t *event =
            divert_mem_alloc(handle->pool,
                             sizeof(timeout_event_t));
    if (NULL == event) { return -1; }
    event->tv = *timeout;
    event->data = data;
    event->flag = flag;
    return pqueue_enqueue(handle->timer_queue, event);
}

int divert_update_ipfw(divert_t *handle, char *divert_filter) {
    char *new_filter = strdup(divert_filter);
    int ret_val = 0;
    if (handle->loop_continue) {
        ret_val = ipfw_delete(handle->ipfw_id, handle->errmsg);
        if (ret_val != 0) { goto fail; }
        ret_val = ipfw_setup(new_filter,
                             (u_short)handle->ipfw_id,
                             (u_short)handle->divert_port,
                             handle->errmsg);
        if (ret_val != 0) { goto fail; }
    } else {
        handle->ipfw_filter = new_filter;
        goto success;
    }
    fail:
    sprintf(handle->errmsg, "ipfw filter set failed.");
    free(new_filter);
    return ret_val;
    success:
    return 0;
}

static int divert_init_divert_socket(divert_t *divert_handle) {
    divert_handle->errmsg[0] = 0;

    divert_handle->divert_fd = socket(PF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_handle->divert_fd == -1) {
        sprintf(divert_handle->errmsg, "Couldn't open a divert socket");
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
        sprintf(divert_handle->errmsg, "Couldn't bind divert socket "
                "to port: %s", strerror(errno));
        return DIVERT_FAILURE;
    }

    // if this port is auto allocated
    // then find its real value by getsockname()
    if (divert_handle->divert_port == 0) {
        if (getsockname(divert_handle->divert_fd,
                        (struct sockaddr *)&divert_port_addr, &sin_len) != 0) {
            sprintf(divert_handle->errmsg, "Couldn't get the address of "
                    "the divert socket: %s", strerror(errno));
            return DIVERT_FAILURE;
        } else {
            divert_handle->divert_port = ntohs(divert_port_addr.sin_port);
        }
    }

    if (divert_handle->bufsize == 0) {
        divert_handle->bufsize = DIVERT_DEFAULT_BUFSIZE;
    }
    // finally allocate memory for divert buffer
    divert_handle->divert_buffer = divert_mem_alloc(divert_handle->pool,
                                                    (size_t)divert_handle->bufsize);
    memset(divert_handle->divert_buffer, 0, (size_t)divert_handle->bufsize);

    return 0;
}

static int divert_init_kernel_ctl_iface(int *fd, char *errmsg) {
    // open socket for pid query
    int kext_fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (kext_fd < 0) {
        sprintf(errmsg, "Could not open kext socket: %s", strerror(errno));
        return KEXT_FAILURE;
    }

    struct ctl_info info;
    memset(&info, 0, sizeof(info));
    strncpy(info.ctl_name, KEXT_CTL_NAME, sizeof(info.ctl_name));
    if (ioctl(kext_fd, CTLIOCGINFO, &info) != 0) {
        sprintf(errmsg, "Could not get ID for kernel control: %s"
                "\nCheck if kernel extension is loaded.", strerror(errno));
        return KEXT_FAILURE;
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
        return KEXT_FAILURE;
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

int divert_init_pcap(FILE *fp) {
    struct pcap_file_header hdr;
    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.snaplen = 65545;
    hdr.sigfigs = 0;
    hdr.linktype = DLT_EN10MB;
    if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1) {
        return -1;
    }
    return 0;
}

int divert_dump_pcap(struct ip *packet, FILE *fp) {
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
        return -1;
    }
    ret_val = fwrite(&ether_hdr, 1, sizeof(ether_hdr), fp);
    if (ret_val != sizeof(ether_hdr)) {
        return -1;
    }
    ret_val = fwrite(packet, 1, ip_len, fp);
    if (ret_val != ip_len) {
        return -1;
    }
    return 0;
}

int divert_init_nids() {
    static char init_flag = 0;
    if (init_flag) { return 0; }

    nids_params.n_tcp_streams = NUM_TCP_STREAMS;
    nids_params.scan_num_ports = 0;

    // when packets are diverted before sending,
    // the checksum of that packet is not calculated
    // because of the checksum offload mechanism
    // so we need to disable that procedure
    struct nids_chksum_ctl *chksum_ctl =
            calloc(1, sizeof(struct nids_chksum_ctl));
    chksum_ctl->action = NIDS_DONT_CHKSUM;
    nids_register_chksum_ctl(chksum_ctl, 1);
    init_flag = 1;
    return nids_init();
}

int divert_activate(divert_t *divert_handle) {
    // clean error message
    divert_handle->errmsg[0] = 0;

    // first check if it is already looping
    if (divert_handle->is_looping) {
        sprintf(divert_handle->errmsg, "Is already looping.");
        return INVALID_FAILURE;
    }

    int status = 0;

    // check if KEXT is loaded
    // and setup query file descriptor
    if (divert_init_kernel_ctl_iface(&divert_handle->kext_fd,
                                     divert_handle->errmsg) != 0) {
        return DIVERT_FAILURE;
    }

    /*
     * then init divert socket
     */
    status = divert_init_divert_socket(divert_handle);
    if (status != 0) {
        return status;
    }

    if (divert_handle->callback == NULL) {
        sprintf(divert_handle->errmsg, "Error: callback function not set!");
        return CALLBACK_NOT_FOUND;
    }

    if (pipe(divert_handle->pipe_fd) != 0 ||
        pipe(divert_handle->exit_fd) != 0) {
        sprintf(divert_handle->errmsg, "Could not create pipe: %s", strerror(errno));
        return PIPE_OPEN_FAILURE;
    }

    return 0;
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

void divert_loop_wait(divert_t *handle) {
    if (handle->is_looping) {
        char str_buf[PIPE_BUFFER_SIZE];
        read(handle->exit_fd[0], str_buf, sizeof(str_buf));
        // do not need to modify handle->is_looping
        // this value is changed in divert_loop
        assert(str_buf[0] == 'e');
    }
}

int divert_loop(divert_t *divert_handle, int count) {
    divert_handle->errmsg[0] = 0;
    // wait until previous looping is exited
    divert_loop_wait(divert_handle);

    // set current looping flag
    divert_handle->is_looping = 1;

    // setup firewall to redirect all traffic to divert socket
    if (ipfw_setup(divert_handle->ipfw_filter,
                   (u_short)divert_handle->ipfw_id,
                   (u_short)divert_handle->divert_port,
                   divert_handle->errmsg) != 0) {
        // error message is set, just return is OK
        return IPFW_FAILURE;
    }
    // number of diverted bytes
    ssize_t num_divert;
    // struct to hold packet headers
    packet_hdrs_t packet_hdrs;
    // error message buffer
    socklen_t sin_len = sizeof(struct sockaddr);
    divert_handle->num_diverted = 0;
    divert_handle->num_unknown = 0;
    divert_callback_t callback = divert_handle->callback;
    void *callback_args = divert_handle->callback_args;

    // register two file descriptor into kqueue
    int kq = kqueue();
    struct kevent changes[2];
    EV_SET(&changes[0], divert_handle->divert_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&changes[1], divert_handle->pipe_fd[0], EVFILT_READ, EV_ADD, 0, 0, NULL);
    int ret = kevent(kq, changes, 2, NULL, 0, NULL);
    if (ret == -1) {
        sprintf(divert_handle->errmsg, "kevent failed: %s", strerror(errno));
        return -1;
    }

    int num_events;
    /* array to hold kqueue events */
    struct kevent events[MAX_EVENT_COUNT];
    divert_handle->loop_continue = 1;
    struct timeval tv;
    struct timezone tz;
    proc_info_t proc_info;
    struct sockaddr sin;

    while (divert_handle->loop_continue) {
        // find a nearest timer from timer queue (priority queue)
        struct timespec timeout_val = {0, 500000}, *timeout_ptr;
#ifdef USE_TICKLESS
        timeout_ptr = NULL;
        if (!pqueue_is_empty(divert_handle->timer_queue)) {
            // get the nearest timer
            timeout_event_t *ptr =
                    pqueue_head(divert_handle->timer_queue);
            // get current time stamp
            gettimeofday(&tv, &tz);
            // calculate max waiting time
            int64_t secs = ptr->tv.tv_sec - (int64_t)tv.tv_sec;
            int64_t usecs = ptr->tv.tv_usec - (int64_t)tv.tv_usec;
            if (usecs < 0) {
                secs -= 1;
                usecs += 1000000;
            }
            if (secs >= 0 && usecs >= 0) {
                timeout_val.tv_sec = secs;
                timeout_val.tv_nsec = usecs * 1000;
                timeout_ptr = &timeout_val;
            }
        }
#else
        timeout_ptr = &timeout_val;
#endif

        // if the kevent is interrupted by signal, then just retry it
        do {
            num_events = kevent(kq, NULL, 0, events, MAX_EVENT_COUNT, timeout_ptr);
        } while (num_events == -1 && errno == EINTR);

        if (num_events >= 0) {
            // we first delete all timers which are timeout
            gettimeofday(&tv, &tz);
            while (!pqueue_is_empty(divert_handle->timer_queue)) {
                timeout_event_t *ptr =
                        pqueue_head(divert_handle->timer_queue);
                if (ptr == NULL) {
                    fprintf(stderr, "Warning: Invalid timer.");
                    continue;
                }
                // if this timer is timeout
                if (time_greater_than(&tv, &ptr->tv)) {
                    ptr = pqueue_dequeue(divert_handle->timer_queue);
                    callback(callback_args, ptr->data, NULL, NULL);
                    if (ptr->data != NULL) { divert_mem_free(divert_handle->pool, ptr->data); }
                    divert_mem_free(divert_handle->pool, ptr);
                } else {
                    break;
                }
            }
            // then we process all ready fds
            for (int i = 0; i < num_events; i++) {
                uintptr_t fd = events[i].ident;
                if (fd == divert_handle->divert_fd) {
                    // returns a packet of IP protocol structure
                    do {
                        num_divert = recvfrom(divert_handle->divert_fd,
                                              divert_handle->divert_buffer,
                                              divert_handle->bufsize, 0,
                                              &sin, &sin_len);
                    } while (num_divert == -1 && errno == EINTR);

                    if (num_divert > 0) {
                        // extract the headers of current packet
                        divert_dump_packet(divert_handle->divert_buffer,
                                           &packet_hdrs, divert_handle->errmsg);
                        // if this is a valid IP packet
                        if (packet_hdrs.size_ip) {
                            // query process of this packet
                            divert_query_proc_by_packet(divert_handle,
                                                        packet_hdrs.ip_hdr, &sin,
                                                        &proc_info);

                            // first feed this IP packet into libnids
                            if (divert_handle->flags & DIVERT_FLAG_TCP_REASSEM) {
                                tcp_stream_pid = proc_info.pid;
                                tcp_stream_epid = proc_info.epid;
                                divert_feed_nids(packet_hdrs.ip_hdr);
                            }

                            // then call the callback function
                            callback(callback_args, &proc_info, packet_hdrs.ip_hdr, &sin);

                            // finally update statistics
                            if (proc_info.pid == -1 &&
                                proc_info.epid == -1) {
                                divert_handle->num_unknown++;
                            }
                            divert_handle->num_diverted++;
                        } else {
                            // IP packet is invalid
                            if (divert_handle->err_handler) { divert_handle->err_handler(DIVERT_ERROR_INVALID_IP); }
                        }
                    } else {
                        // no valid data, so insert a flag into thread buffer
                        if (divert_handle->err_handler) { divert_handle->err_handler(DIVERT_ERROR_NODATA); }
                    }
                    if (count > 0 && divert_handle->num_diverted > count) {
                        goto finish;
                    }
                } else if (fd == divert_handle->pipe_fd[0]) {
                    // end the event loop
                    char pipe_buf[PIPE_BUFFER_SIZE];
                    read(divert_handle->pipe_fd[0], pipe_buf, sizeof(pipe_buf));
                    assert(pipe_buf[0] == 'q');
                    goto finish;
                }
            }
        } else if (num_events == -1) {
            if (divert_handle->err_handler) { divert_handle->err_handler(DIVERT_ERROR_KQUEUE); }
        }
    }
    finish:
    divert_handle->loop_continue = 0;

    // first clean firewall rule
    ipfw_delete(divert_handle->ipfw_id, divert_handle->errmsg);

    // then clear the timer queue
    while (pqueue_size(divert_handle->timer_queue) > 0) {
        timeout_event_t *ptr = pqueue_dequeue(divert_handle->timer_queue);
        if (ptr->data != NULL) { divert_mem_free(divert_handle->pool, ptr->data); }
        divert_mem_free(divert_handle->pool, ptr);
    }

    // send a message to tell that loop is really stopped
    write(divert_handle->exit_fd[1], "e", 1);

    // finally clear the is_looping flag
    divert_handle->is_looping = 0;
    return 0;
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

void divert_checksum(struct ip *ip_data) {
    size_t iphdr_len = ip_data->ip_hl * 4u;
    size_t ip_len = ntohs(ip_data->ip_len);
    // error packet, just return
    if (iphdr_len >= ip_len) { return; }
    // re-checksum TCP and UDP packets
    if (ip_data->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcp_data = (struct tcphdr *)((u_char *)ip_data + iphdr_len);
        tcp_data->th_sum = 0;
        tcp_data->th_sum = tcp_checksum(tcp_data,
                                        ip_len - iphdr_len,
                                        ip_data->ip_src.s_addr,
                                        ip_data->ip_dst.s_addr);
    } else if (ip_data->ip_p == IPPROTO_UDP) {
        struct udphdr *udp_data = (struct udphdr *)((u_char *)ip_data + iphdr_len);
        udp_data->uh_sum = 0;
        udp_data->uh_sum = udp_checksum(udp_data,
                                        ip_len - iphdr_len,
                                        ip_data->ip_src.s_addr,
                                        ip_data->ip_dst.s_addr);
    }
    // need to re-checksum IP packet
    ip_data->ip_sum = 0;
    ip_data->ip_sum = ip_checksum(ip_data, iphdr_len);
}

ssize_t divert_reinject(divert_t *handle, struct ip *packet,
                        ssize_t length, struct sockaddr *sin) {
    // calculate packet length
    socklen_t sin_len = sizeof(struct sockaddr);
    if (length < 0) {
        length = ntohs(packet->ip_len);
    }
    // check the destination of this packet and judge if
    // we should force inject it into another device
    if (divert_device_inbound(handle, packet)) {
        int ret;
        do {
            ret = libnet_adv_write_raw_ipv4(handle->libnet,
                                            (u_int8_t *)packet, (uint32_t)length);
        } while (ret == -1 && errno == EINTR);
        return ret;
    }
    // re-checksum the packet
    if (packet->ip_sum == 0) {
        divert_checksum(packet);
    }
    ssize_t ret_val;
    do {
        ret_val = sendto(handle->divert_fd, packet,
                         (size_t)length, 0, sin, sin_len);
    } while (ret_val == -1 && errno == EINTR);
    return ret_val;
}

int divert_is_looping(divert_t *handle) {
    return handle->is_looping;
}

void divert_loop_stop(divert_t *handle) {
    // if not looping, just return
    if (!handle->is_looping) { return; }

    // set loop flag to zero
    handle->loop_continue = 0;

    // write data into pipe to quit event loop
    write(handle->pipe_fd[1], "q", 1);
}

int divert_close(divert_t *divert_handle) {
    divert_handle->errmsg[0] = 0;

    // first wait until divert loop is exited
    divert_loop_wait(divert_handle);

    // close the divert socket and release the buffer
    close(divert_handle->divert_fd);
    if (divert_handle->divert_buffer != NULL) {
        divert_mem_free(divert_handle->pool,
                        divert_handle->divert_buffer);
    }

    // close the kext communication descriptor
    close(divert_handle->kext_fd);
    // close the pipe descriptors
    close(divert_handle->pipe_fd[0]);
    close(divert_handle->pipe_fd[1]);
    close(divert_handle->exit_fd[0]);
    close(divert_handle->exit_fd[1]);

    if (divert_handle->libnet != NULL) {
        libnet_destroy(divert_handle->libnet);
    }

    divert_destroy_pool(divert_handle->pool);
    free(divert_handle);
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
