#include "divert.h"
#include "nids.h"
#include <libproc.h>


static pid_t pid;
static char proc_name_buf[128];


void error_handler(u_int64_t flags) {
    if (flags & DIVERT_ERROR_NODATA) {
        puts("Didn't read data from divert socket or data error.");
    }
    if (flags & DIVERT_ERROR_KQUEUE) {
        puts("kqueue error.");
    }
    if (flags & DIVERT_ERROR_INVALID_IP) {
        puts("Invalid IP packet.");
    }
}

#define int_ntoa(x)    inet_ntoa(*((struct in_addr *)&x))

// struct tuple4 contains addresses and port numbers of the TCP connections
// the following auxiliary function produces a string looking like
// 10.0.0.1,1024,10.0.0.2,23
char *adres(struct tuple4 addr) {
    static char buf[256];
    strcpy (buf, int_ntoa(addr.saddr));
    sprintf (buf + strlen(buf), "(%i)-", addr.source);
    strcat (buf, int_ntoa(addr.daddr));
    sprintf (buf + strlen(buf), "(%i)", addr.dest);
    return buf;
}


void ip_callback(void *args, void *proc_info_p,
                 struct ip *packet, struct sockaddr *sin) {
    divert_t *handle = args;
    // re-inject packets into TCP/IP stack
    divert_reinject(handle, packet, -1, sin);
}

void tcp_callback(struct tcp_stream *a_tcp,
                  void **not_needed, void *data) {
    // if this is not the stream we're concerning about
    // we just return and do nothing
    if (tcp_stream_pid != pid &&
        tcp_stream_epid != pid) {
        return;
    }
    char addr_buf[1024];
    strcpy (addr_buf, adres(a_tcp->addr)); // we put conn params into buf
    if (a_tcp->nids_state == NIDS_JUST_EST) {
        a_tcp->client.collect++; // we want data received by a client
        a_tcp->server.collect++; // and by a server, too
        fprintf(stderr, "%s established\n", addr_buf);
        // clean the data file
        FILE *fp = fopen(addr_buf, "wb");
        fclose(fp);
        return;
    } else if (a_tcp->nids_state == NIDS_CLOSE) {
        // connection has been closed normally
        fprintf(stderr, "%s closing\n", addr_buf);
        return;
    } else if (a_tcp->nids_state == NIDS_RESET) {
        // connection has been closed by RST
        fprintf(stderr, "%s reset\n", addr_buf);
        return;
    } else if (a_tcp->nids_state == NIDS_DATA) {
        // new data has arrived
        // gotta determine in what direction
        struct half_stream *hlf;
        if (a_tcp->client.count_new) {
            // new data for client
            hlf = &a_tcp->client; // from now on, we will deal with hlf var,
        } else {
            hlf = &a_tcp->server; // analogical
        }
        // and save the connection data into files
        fprintf(stderr, "Save data of connection: %s\n", addr_buf);
        FILE *fp = fopen(addr_buf, "a");
        fwrite(hlf->data, 1, (size_t)hlf->count_new, fp);
        fclose(fp);
    }
    return;
}

int main(int argc, char *argv[]) {
    if (argc == 2) {
        pid = atoi(argv[1]);
    } else {
        puts("Usage: ./tcp_reassemble <PID>");
        exit(EXIT_FAILURE);
    }

    proc_name(pid, proc_name_buf, sizeof(proc_name_buf));
    printf("Watching packets of process %s: %d\n", proc_name_buf, pid);

    // first manually init libnids
    divert_init_nids();

    // register callback function for TCP connection
    nids_register_tcp(tcp_callback);

    // create a handle for divert object
    divert_t *handle = divert_create(0, DIVERT_FLAG_TCP_REASSEM);

    // set the error handler to display error information
    divert_set_error_handler(handle, error_handler);

    // register callback function for IP packet
    divert_set_callback(handle, ip_callback, handle);

    // register signal handler to exit process gracefully
    divert_set_signal_handler(SIGINT, divert_signal_handler_stop_loop, (void *)handle);

    // update ipfw rule
    divert_update_ipfw(handle, "tcp from any to not 0.0.0.255:24 via en0");

    // activate the divert handler
    divert_activate(handle);
    if (handle->errmsg[0]) {
        puts(handle->errmsg);
        exit(EXIT_FAILURE);
    }

    printf("Packet buffer size: %zu\n", handle->bufsize);

    // call the main loop
    printf("Divert Loop Exit Status: %d\n", divert_loop(handle, -1));

    // clean the handle to release resources
    if (divert_close(handle) == 0) {
        puts("Successfully cleaned.");
    }
    return 0;
}
