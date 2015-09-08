#include "divert.h"
#include "divert_ipfw.h"
#include "dump_packet.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/event.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// TODO: 实现一个单例模式？
/*
 * only constant and parameter variables could be assigned here
 * no dynamic memory allocation
 */
divert_t *divert_create(int port_number, u_int32_t flags, char *errmsg) {
    errmsg[0] = 0;
    divert_t *divert_handle;
    divert_handle = malloc(sizeof(divert_t));

    // all pointers in divert_handle would be NULL
    memset(divert_handle, 0, sizeof(divert_t));

    divert_handle->flags = flags;
    divert_handle->divert_port.sin_family = AF_INET;
    divert_handle->divert_port.sin_port = htons(port_number);
    divert_handle->divert_port.sin_addr.s_addr = 0;
    divert_handle->divert_sin = malloc(sizeof(struct sockaddr));

    // set default timeout
    divert_handle->timeout = PACKET_TIME_OUT;
    divert_handle->thread_buffer_size = PACKET_BUFFER_SIZE;

    return divert_handle;
}

int divert_set_data_buffer_size(divert_t *handle, size_t bufsize) {
    handle->bufsize = bufsize;
    return 1;
}

int divert_set_thread_buffer_size(divert_t *handle, size_t bufsize) {
    handle->thread_buffer_size = bufsize;
    return 1;
}

int divert_set_error_handler(divert_t *handle, divert_error_handler_t handler) {
    handle->err_handler = handler;
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

static int divert_init_pcap(divert_t *divert_handle, char *errmsg) {

    pcap_t *pcap_handle;
    char *dev = PKTAP_IFNAME;

    /* open capture device */
    pcap_handle = pcap_create(dev, errmsg);
    /* backup the handler of pcap */
    divert_handle->pcap_handle = pcap_handle;

    if (pcap_handle == NULL) {
        sprintf(errmsg, "Couldn't open device %s: %s", dev, errmsg);
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

    /* read the information of pcap handler */
    divert_handle->bpf_fd = pcap_handle->fd;
    divert_handle->bpf_buffer = pcap_handle->buffer;
    divert_handle->bufsize = (size_t)pcap_handle->bufsize;
    /* allocate thread buffer to store labeled packet */
    divert_handle->thread_buffer = malloc(sizeof(packet_buf_t));
    if (divert_buf_init(divert_handle->thread_buffer,
                        divert_handle->thread_buffer_size, errmsg) != 0) {
        return PCAP_BUFFER_FAILURE;
    }
    // create queue for bpf packets
    divert_handle->bpf_queue = queue_create();
    divert_handle->packet_map = packet_map_create();

    return 0;
}

static int divert_init_divert_socket(divert_t *divert_handle, char *errmsg) {

    divert_handle->divert_fd = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_handle->divert_fd == -1) {
        sprintf(errmsg, "Couldn't open a divert socket");
        return DIVERT_FAILURE;
    }

    // bind divert socket to port
    if (bind(divert_handle->divert_fd, (struct sockaddr *)&divert_handle->divert_port,
             sizeof(struct sockaddr_in)) != 0) {
        sprintf(errmsg, "Couldn't bind divert socket to port");
        return DIVERT_FAILURE;
    }

    // setup firewall to redirect all traffic to divert socket
    if (ipfw_setup(divert_handle, errmsg) != 0) {
        return FIREWALL_FAILURE;
    }

    // finally allocate memory for divert buffer
    divert_handle->divert_buffer = malloc((size_t)divert_handle->bufsize);
    memset(divert_handle->divert_buffer, 0, (size_t)divert_handle->bufsize);

    return 0;
}

int divert_activate(divert_t *divert_handle, char *errmsg) {
    // clean error message
    errmsg[0] = 0;
    int status = 0;

    /*
     * first init pcap metadata
     */
    if (divert_handle->flags & DIVERT_FLAG_WITH_APPLE_EXTHDR) {
        status = divert_init_pcap(divert_handle, errmsg);
        if (status != 0) {
            return status;
        }
    }

    /*
     * then init divert socket
     */
    status = divert_init_divert_socket(divert_handle, errmsg);
    if (status != 0) {
        return status;
    }

    return 0;
}

/*
 * compare two packet_info_t structure
 */
static int compare_packet(void *p1, void *p2) {
    // the entire packet should be equal
    // IP header, TCP header and data payload
    packet_info_t *pkt1 = (packet_info_t *)p1;
    packet_info_t *pkt2 = (packet_info_t *)p2;
    size_t len1 = ntohs(pkt1->ip_data->ip_len);
    size_t len2 = ntohs(pkt2->ip_data->ip_len);
    if (len1 == len2 &&
        memcmp(pkt1->ip_data, pkt2->ip_data, len1) == 0) {
        return 1;
    }
    return 0;
}

static int should_drop(void *data, void *args) {
    packet_info_t *pkt_info = (packet_info_t *)data;
    u_int64_t timeout = ((u_int64_t *)args)[0];
    u_int64_t time_stamp = ((u_int64_t *)args)[1];
    if (time_stamp - pkt_info->time_stamp > timeout) {
        return 1;
    } else {
        return 0;
    }
}

static void free_packet_data(void *ptr) {
    packet_info_t *p = (packet_info_t *)ptr;
    free(p->ip_data);
    free(p);
}

static inline packet_info_t *divert_new_error_packet(u_int64_t flag) {
    packet_info_t *new_packet = malloc(sizeof(packet_info_t));
    new_packet->ip_data = NULL;
    new_packet->pktap_hdr = NULL;
    new_packet->time_stamp = flag;
    return new_packet;
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
            callback(callback_args, packet->pktap_hdr,
                     packet->ip_data, handle->divert_sin);
            free(packet->ip_data);
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
        // if the cache is too big, just free it
        if (packet_map_get_size(handle->packet_map) > PACKET_INFO_CACHE_SIZE) {
            packet_map_clean(handle->packet_map);
#ifdef DEBUG
            puts("Now clean buffer.");
            printf("Current size: %zu\n", packet_map_get_size(handle->packet_map));
#endif
        }
    }
    return NULL;
}

static u_char divert_extract_IP_port(packet_hdrs_t *packet_hdrs,
                                     in_addr_t *ip_src,
                                     in_addr_t *ip_dst,
                                     u_short *port_src,
                                     u_short *port_dst) {
    u_char is_tcpudp = 0;
    *ip_src = packet_hdrs->ip_hdr->ip_src.s_addr;
    *ip_dst = packet_hdrs->ip_hdr->ip_dst.s_addr;
    if (packet_hdrs->size_tcp) {
        is_tcpudp = 1;
        *port_src = packet_hdrs->tcp_hdr->th_sport;
        *port_dst = packet_hdrs->tcp_hdr->th_dport;
    } else if (packet_hdrs->size_udp) {
        is_tcpudp = 1;
        *port_src = packet_hdrs->udp_hdr->uh_sport;
        *port_dst = packet_hdrs->udp_hdr->uh_dport;
    }
    return is_tcpudp;
}

void divert_loop(divert_t *divert_handle, int count,
                 divert_callback_t callback, void *args) {
    u_char found_info;
    in_addr_t ip_src, ip_dst;
    u_short port_src, port_dst;
    void *ret_val;
    pthread_t divert_thread_callback_handle;
    ssize_t num_divert, num_bpf;
    queue_node_t *node;
    void *time_info = malloc(2 * sizeof(u_int64_t));
    char errmsg[PCAP_ERRBUF_SIZE];

    socklen_t sin_len = sizeof(struct sockaddr_in);

    packet_hdrs_t packet_hdrs;
    packet_info_t packet_info;

    /* store the callback function and arguments into divert handle */
    divert_handle->callback = callback;
    divert_handle->callback_args = args;
    ((u_int64_t *)time_info)[0] = divert_handle->timeout;

    divert_handle->is_looping = 1;
    divert_handle->num_missed = 0;
    divert_handle->num_diverted = 0;
    divert_handle->num_captured = 0;
    divert_handle->current_time_stamp = 0;
    pthread_create(&divert_thread_callback_handle, NULL, divert_thread_callback, divert_handle);

    /* register two file descriptor into kqueue */
    int kq = kqueue();
    struct kevent changes[2];
    EV_SET(&changes[0], divert_handle->divert_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    EV_SET(&changes[1], divert_handle->bpf_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
    int ret = kevent(kq, changes, 2, NULL, 0, NULL);
    if (ret == -1) {
        fprintf(stderr, "kevent failed: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    /* array to hold kqueue events */
    struct kevent events[MAX_EVENT_COUNT];

    while (divert_handle->is_looping) {
        int num_events = kevent(kq, NULL, 0, events, MAX_EVENT_COUNT, NULL);
        if (num_events == -1) {
            divert_buf_insert(divert_handle->thread_buffer,
                              divert_new_error_packet(DIVERT_ERROR_KQUEUE));
        } else {
            for (int i = 0; i < num_events; i++) {
                uintptr_t fd = events[i].ident;
                //intptr_t data_size = events[i].data;
                if (fd == divert_handle->bpf_fd) {
                    // returns a packet of BPF structure
                    num_bpf = read(divert_handle->bpf_fd,
                                   divert_handle->bpf_buffer,
                                   divert_handle->bufsize);
                    // divert_handle the BPF packet: just push it into queue
                    // things in the queue are pointers to packet_info_t
                    if (num_bpf > 0) {
                        // first dump the headers of this packet
                        divert_dump_bpf_raw_data(divert_handle->bpf_buffer, errmsg, &packet_hdrs);
                        if (packet_hdrs.size_ip) {
                            size_t ip_length = ntohs(packet_hdrs.ip_hdr->ip_len);
                            size_t pktap_len = packet_hdrs.pktap_hdr->pth_length;
                            packet_info_t *new_packet = malloc(sizeof(packet_info_t));
                            // memory of this header should be freed
                            new_packet->time_stamp = divert_handle->current_time_stamp;
                            // allocate memory
                            // note that pth_length is header length
                            // and the length of ip packet should be converted
                            new_packet->pktap_hdr = malloc(pktap_len);
                            new_packet->ip_data = malloc(ip_length);
                            // copy data
                            memcpy(new_packet->pktap_hdr, packet_hdrs.pktap_hdr, pktap_len);
                            memcpy(new_packet->ip_data, packet_hdrs.ip_hdr, ip_length);
                            // calculate position of ip header
                            queue_push(divert_handle->bpf_queue, new_packet);
                            if (divert_extract_IP_port(&packet_hdrs, &ip_src,
                                                       &ip_dst, &port_src, &port_dst)) {
                                packet_map_insert(divert_handle->packet_map, ip_src, ip_dst,
                                                  port_src, port_dst, new_packet->pktap_hdr);
                            }
                            divert_handle->num_captured++;
                        } else {
                            divert_buf_insert(divert_handle->thread_buffer,
                                              divert_new_error_packet(DIVERT_ERROR_BPF_INVALID));
                        }
                    } else {
                        divert_buf_insert(divert_handle->thread_buffer,
                                          divert_new_error_packet(DIVERT_ERROR_BPF_NODATA));
                    }
                } else if (fd == divert_handle->divert_fd) {
                    // returns a packet of IP protocol structure
                    num_divert = recvfrom(divert_handle->divert_fd,
                                          divert_handle->divert_buffer,
                                          divert_handle->bufsize, 0,
                                          divert_handle->divert_sin, &sin_len);

                    if (num_divert > 0) {
                        // store time stamp into variable
                        ((u_int64_t *)time_info)[1] = divert_handle->current_time_stamp;
                        // extract the headers of current packet
                        divert_dump_ip_data(divert_handle->divert_buffer, errmsg, &packet_hdrs);
                        if (packet_hdrs.size_ip) {
                            // set the packet information
                            // note that the divert socket receives a packet of IP protocol
                            packet_info.time_stamp = divert_handle->current_time_stamp;
                            packet_info.ip_data = packet_hdrs.ip_hdr;
                            packet_info.pktap_hdr = NULL;
                            found_info = 0;
                            // search in queue and find process info of this packet
                            if (!found_info) {
                                if ((node = queue_search_and_drop(divert_handle->bpf_queue,
                                                                  &packet_info,
                                                                  time_info,
                                                                  compare_packet,
                                                                  should_drop,
                                                                  free_packet_data)) != NULL) {
                                    found_info = 1;
                                    // insert the packet into thread buffer
                                    // and let another thread handle it
                                    // in order to save time
                                    packet_info_t *current_packet = (packet_info_t *)node->data;
                                    // release the memory of this node
                                    free(node);
                                    current_packet->time_stamp = DIVERT_RAW_IP_PACKET;
                                    divert_buf_insert(divert_handle->thread_buffer, current_packet);
#ifdef DEBUG
                                    // for debug
                                    // see if this two way of finding pid would get different results
                                    struct pktap_header *pktap_hdr;
                                    if (divert_extract_IP_port(&packet_hdrs, &ip_src,
                                                               &ip_dst, &port_src, &port_dst) &&
                                        (pktap_hdr = packet_map_query(divert_handle->packet_map,
                                                                      ip_src, ip_dst,
                                                                      port_src, port_dst)) != NULL) {
                                        if (pktap_hdr->pth_pid != current_packet->pktap_hdr->pth_pid) {
                                            fprintf(stderr, "Error pid: %d: %s, real: %d: %s\n",
                                                   pktap_hdr->pth_pid, pktap_hdr->pth_comm,
                                                   current_packet->pktap_hdr->pth_pid,
                                                   current_packet->pktap_hdr->pth_comm);
                                        }
                                    }
#endif
                                }
                            }
                            if (!found_info) {
                                struct pktap_header *pktap_hdr;
                                if (divert_extract_IP_port(&packet_hdrs, &ip_src,
                                                           &ip_dst, &port_src, &port_dst) &&
                                    (pktap_hdr = packet_map_query(divert_handle->packet_map,
                                                                  ip_src, ip_dst,
                                                                  port_src, port_dst)) != NULL) {
                                    found_info = 1;
                                    size_t ip_length = ntohs(packet_hdrs.ip_hdr->ip_len);
                                    packet_info_t *new_packet = malloc(sizeof(packet_info_t));
                                    new_packet->time_stamp = DIVERT_RAW_IP_PACKET;
                                    new_packet->pktap_hdr = pktap_hdr;
                                    // allocate memory
                                    new_packet->ip_data = malloc(ip_length);
                                    // and copy data
                                    memcpy(new_packet->ip_data, packet_hdrs.ip_hdr, ip_length);
                                    divert_buf_insert(divert_handle->thread_buffer, new_packet);
                                }
                            }
                            if (!found_info) {
                                // if packet is not found in the queue, then just send it to user
                                size_t ip_length = ntohs(packet_hdrs.ip_hdr->ip_len);
                                packet_info_t *new_packet = malloc(sizeof(packet_info_t));
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
                    }
                }
            }
        }
        // increase time stamp
        divert_handle->current_time_stamp++;
        if (count > 0 && divert_handle->num_diverted >= count) {
            divert_handle->is_looping = 0;
            break;
        }
    }
    // insert an item into the thread buffer to stop another thread
    divert_buf_insert(divert_handle->thread_buffer,
                      divert_new_error_packet(DIVERT_STOP_LOOP));
    // wait until the child thread is stopped
    pthread_join(divert_thread_callback_handle, &ret_val);
}

void divert_loop_stop(divert_t *handle) {
    handle->is_looping = 0;
}

int divert_clean(divert_t *divert_handle, char *errmsg) {
    errmsg[0] = 0;
    // delete ipfw firewall rule
    if (ipfw_delete(divert_handle, errmsg) != 0) {
        return FIREWALL_FAILURE;
    }

    // close the divert socket and free the buffer
    close(divert_handle->divert_fd);
    if (divert_handle->divert_buffer != NULL) {
        free(divert_handle->divert_buffer);
    }

    // close the pcap handler and clean the thread buffer
    if (divert_handle->flags & DIVERT_FLAG_WITH_APPLE_EXTHDR) {
        pcap_close(divert_handle->pcap_handle);
        divert_buf_clean(divert_handle->thread_buffer, errmsg);
    }

    return 0;
}
