#include "divert.h"
#include "divert_ipfw.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

volatile u_char is_looping;

divert_t *divert_create(int port_number, char *errmsg) {
    errmsg[0] = 0;
    divert_t *divert_handle;
    divert_handle = malloc(sizeof(divert_t));
    memset(divert_handle, 0, sizeof(divert_t));

    divert_handle->divert_port.sin_family = AF_INET;
    divert_handle->divert_port.sin_port = htons(port_number);
    divert_handle->divert_port.sin_addr.s_addr = 0;

    return divert_handle;
}

int divert_set_buffer_size(divert_t *handle, int bufsize) {
    handle->bufsize = bufsize;
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

int divert_activate(divert_t *divert_handle, char *errmsg) {
    errmsg[0] = 0;
    /*
     * first init pcap metadata
     */
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
     */
    // TODO: 这里要做错误处理！
    pcap_set_immediate_mode(pcap_handle, 1);
    pcap_set_want_pktap(pcap_handle, 1);
    if (divert_handle->bufsize > 0) {
        pcap_set_buffer_size(pcap_handle, divert_handle->bufsize);
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
    divert_handle->bpf_fd = pcap_handle->fd;
    divert_handle->bpf_buffer = pcap_handle->buffer;
    divert_handle->bufsize = pcap_handle->bufsize;

    /*
     * then init divert socket
     */
    divert_handle->divert_fd = socket(AF_INET, SOCK_RAW, IPPROTO_DIVERT);
    if (divert_handle->divert_fd == -1) {
        sprintf(errmsg, "Couldn't open a divert socket");
        return DIVERT_FAILURE;
    }

    // set socket to non-blocking
    if (fcntl(divert_handle->divert_fd, F_SETFL, O_NONBLOCK) != 0) {
        sprintf(errmsg, "Couldn't set socket to non-blocking mode");
        return DIVERT_FAILURE;
    }

    if (bind(divert_handle->divert_fd, (struct sockaddr *)&divert_handle->divert_port,
             sizeof(struct sockaddr_in)) != 0) {
        sprintf(errmsg, "Couldn't bind divert socket to port");
        return DIVERT_FAILURE;
    }

    if (ipfw_setup(divert_handle, errmsg) != 0) {
        return FIREWALL_FAILURE;
    }

    divert_handle->divert_buffer = malloc((size_t)divert_handle->bufsize);
    memset(divert_handle->divert_buffer, 0, (size_t)divert_handle->bufsize);

    return 0;
}

void divert_loop(divert_t *divert_handle, int count,
                 divert_handler_t callback, u_char *args) {
    is_looping = 1;
    while (is_looping) {

    }

}

void divert_loop_stop() {
    is_looping = 0;
}

int divert_clean(divert_t *divert_handle, char *errmsg) {
    errmsg[0] = 0;
    // delete ipfw firewall rule
    if (ipfw_delete(divert_handle, errmsg) != 0) {
        return FIREWALL_FAILURE;
    }
    // close the pcap handler
    pcap_close(divert_handle->pcap_handle);
    // close the divert socket and free the buffer
    close(divert_handle->divert_fd);
    if (divert_handle->divert_buffer != NULL) {
        free(divert_handle->divert_buffer);
    }
    return 0;
}
