#include "divert.h"
#include "divert_ipfw.h"
#include "dump_packet.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>

divert_t *divert_create(int port_number, u_int32_t flags, char *errmsg) {
    errmsg[0] = 0;
    divert_t *divert_handle;
    divert_handle = malloc(sizeof(divert_t));
    memset(divert_handle, 0, sizeof(divert_t));

    divert_handle->flags = flags;
    divert_handle->divert_port.sin_family = AF_INET;
    divert_handle->divert_port.sin_port = htons(port_number);
    divert_handle->divert_port.sin_addr.s_addr = 0;

    // create queue for bpf packets
    divert_handle->bpf_queue = queue_create();

    // set default timeout
    divert_handle->timeout = PACKET_TIME_OUT;
    divert_handle->thread_buffer_size = PACKET_BUFFER_SIZE;

    return divert_handle;
}

// TODO: 设计一个新的函数来设置缓存buffer的大小

int divert_set_data_buffer_size(divert_t *handle, size_t bufsize) {
    handle->bufsize = bufsize;
    return 1;
}

int divert_set_thread_buffer_size(divert_t *handle, size_t bufsize) {
    handle->thread_buffer_size = bufsize;
    return 1;
}

int divert_set_pcap_filter(divert_t *divert_handle, char *pcap_filter, char *errmsg) {
    errmsg[0] = 0;
    struct bpf_program fp;          /* compiled filter program (expression) */

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

    if (pcap_apple_set_exthdr(pcap_handle, 1) != 0) {
        sprintf(errmsg, "Couldn't set exthdr!");
        return PCAP_FAILURE;
    }

    if (pcap_activate(pcap_handle) != 0) {
        sprintf(errmsg, "Couldn't activate pcap handle!");
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

    /* backup the handler of pcap */
    divert_handle->pcap_handle = pcap_handle;
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

    return 0;
}

static int divert_init_divert_socket(divert_t *divert_handle, char *errmsg) {

    divert_handle->divert_fd = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_handle->divert_fd == -1) {
        sprintf(errmsg, "Couldn't open a divert socket");
        return DIVERT_FAILURE;
    }

    /*
     * set socket to non-blocking
     * this is used only when we use the extended info
     */
    if (divert_handle->flags & DIVERT_FLAG_WITH_APPLE_EXTHDR) {
        if (fcntl(divert_handle->divert_fd, F_SETFL, O_NONBLOCK) != 0) {
            sprintf(errmsg, "Couldn't set socket to non-blocking mode");
            return DIVERT_FAILURE;
        }
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
static int compare_packet(void *packet_info1, void *packet_info2) {
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

void divert_loop(divert_t *divert_handle, int count,
                 divert_callback_t callback, u_char *args) {
    ssize_t num_divert, num_bpf;
    queue_node_t *node;
    void *time_info = malloc(2 * sizeof(u_int64_t));
    u_char *payload;
    char errmsg[PCAP_ERRBUF_SIZE];

    struct sockaddr sin;
    socklen_t sin_len = sizeof(struct sockaddr_in);

    packet_hdrs_t packet_hdrs;
    packet_info_t packet_info;

    ((u_int64_t *)time_info)[0] = divert_handle->timeout;

    divert_handle->is_looping = 1;
    while (divert_handle->is_looping) {
        // returns a packet of BPF structure
        num_bpf = read(divert_handle->bpf_fd,
                       divert_handle->bpf_buffer,
                       divert_handle->bufsize);

        // handle the BPF packet: just push it into queue
        // things in the queue are pointers to packet_info_t
        if (num_bpf > 0) {
            // first dump the headers of this packet
            payload = divert_dump_bpf_raw_data(divert_handle->bpf_buffer, errmsg, &packet_hdrs);
            if (packet_hdrs.size_ip) {
                size_t bpf_len = BPF_WORDALIGN(packet_hdrs.bhep_hdr->bh_caplen +
                                               packet_hdrs.bhep_hdr->bh_hdrlen);
                packet_info_t *new_packet = malloc(sizeof(packet_info_t));
                new_packet->time_stamp = divert_handle->current_time_stamp;
                // allocate memory
                new_packet->raw_data = malloc(bpf_len);
                // copy data
                memcpy(new_packet->raw_data, divert_handle->bpf_buffer, bpf_len);
                // calculate position of ip header
                new_packet->ip_data = (struct ip *)(new_packet->raw_data +
                                                    ((u_char *)packet_hdrs.ip_hdr -
                                                     (u_char *)packet_hdrs.bhep_hdr));
                queue_push(divert_handle->bpf_queue, new_packet);
            } else {
                // TODO: call the error handler
            }
        } else {
            // TODO: call the error handler
        }

        // returns a packet of IP protocol structure
        num_divert = recvfrom(divert_handle->divert_fd,
                              divert_handle->divert_buffer,
                              divert_handle->bufsize, 0,
                              &sin, &sin_len);

        if (num_divert == -1) {
            if (errno == EWOULDBLOCK) {
                // no data could be read, just continue
            }
        } else if (num_divert > 0) {
            // store time stamp into variable
            ((u_int64_t *)time_info)[1] = divert_handle->current_time_stamp;
            // extract the headers of current packet
            payload = divert_dump_ip_data(divert_handle->divert_buffer, errmsg, &packet_hdrs);
            if (packet_hdrs.size_ip) {
                // set the packet information
                packet_info.time_stamp = divert_handle->current_time_stamp;
                packet_info.raw_data = (u_char *)packet_hdrs.bhep_hdr;
                packet_info.ip_data = packet_hdrs.ip_hdr;
                // search in queue and find process info of this packet
                if ((node = queue_search_and_drop(divert_handle->bpf_queue,
                                                  &packet_info,
                                                  time_info,
                                                  compare_packet,
                                                  should_drop)) != NULL) {
                    // TODO: call the callback function

                    free(node);
                } else {
                    // if packet is not found in the queue, then just re-inject it
                    recvfrom(divert_handle->divert_fd,
                             divert_handle->divert_buffer,
                             (size_t)num_divert, 0,
                             &sin, &sin_len);
                    // TODO: call the error handler
                }
            }
        }
        // increase time stamp
        divert_handle->current_time_stamp++;
    }

}

void divert_working_thread(divert_t *handle) {

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

    if (divert_handle->flags & DIVERT_FLAG_WITH_APPLE_EXTHDR) {
        // close the pcap handler
        pcap_close(divert_handle->pcap_handle);
        divert_buf_clean(divert_handle->thread_buffer, errmsg);
    }

    return 0;
}
