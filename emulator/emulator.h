#ifndef DIVERT_EMULATOR_CONFIG_H
#define DIVERT_EMULATOR_CONFIG_H

#include "divert.h"
#include "divert_mem_pool.h"
#include "queue.h"
#include "pqueue.h"
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/time.h>


enum {
    DIRECTION_IN = 0,
    DIRECTION_OUT = 1,
    DIRECTION_UNKNOWN = 2,
};

enum {
    PIPE_DROP = 0,
    PIPE_DELAY = 1,
    PIPE_THROTTLE = 2,
    PIPE_DISORDER = 3,
    PIPE_BITERR = 4,
    PIPE_DUPLICATE = 5,
    PIPE_BANDWIDTH = 6,
    PIPE_REINJECT = 7,

};

// TODO: add event driven mode
enum {
    MODE_TIME_DRIVEN = 0,
    MODE_EVENT_DRIVEN = 1,
};

enum {
    NEW_PACKET = 0,
    TIMEOUT_EVENT = 1,
    EVENT_QUIT = 2,
};


// WARNING: you should not use this flags in your code
#define EMULATOR_IS_RUNNING (1u << 0)
#define EMULATOR_DUMP_PCAP  (1u << 1)
#define EMULATOR_RECHECKSUM (1u << 2)



#define TIMER_QUEUE_SIZE    4096


#define BITS_PER_BYTE       8
#define FLOAT_EPS           (1e-7)

#define offsetof(type, member) (size_t)&(((type*)0)->member)

#define container_of(ptr, type, member) ({                      \
        const typeof( ((type *)0)->member ) *__mptr = (ptr);    \
        (type *)( (char *)__mptr - offsetof(type, member) );})

#define CHECK_AND_FREE(VAR)     \
    if ((VAR) != NULL) {        \
        free((VAR));            \
    }

#define MALLOC_AND_COPY(DST, SRC, NUM, TYPE)     \
    (DST) = malloc(sizeof(TYPE) * (NUM));      \
    memcpy((DST), (SRC), sizeof(TYPE) * (NUM));


typedef struct {
    struct ip *ip_data;
    struct sockaddr sin;
    proc_info_t proc_info;
    packet_hdrs_t headers;
    int32_t label;
    u_char direction;
} emulator_packet_t;

typedef struct pipe_node pipe_node_t;

typedef struct emulator emulator_config_t;

typedef void (*pipe_insert_func_t)(pipe_node_t *node,
                                   emulator_packet_t *packet);

typedef void (*pipe_process_func_t)(pipe_node_t *node);

typedef pipe_process_func_t pipe_clear_func_t;

typedef pipe_process_func_t pipe_free_func_t;

typedef struct {
    size_t *size;
    float *rate;
    size_t num;
} packet_size_filter;

struct pipe_node {
    /*
     * init when create
     */
    int pipe_type;
    pipe_insert_func_t insert;
    pipe_process_func_t process;
    pipe_clear_func_t clear;
    pipe_free_func_t free;

    ssize_t p;
    ssize_t num;
    packet_size_filter *size_filter;

    /*
     * init when insert
     */
    pipe_node_t *next;
    emulator_config_t *config;

    /*
     * init when start
     */
    struct timeval tv_start;
};

typedef struct {
    struct timeval tv;
    int flag;
} timeout_event_t;

struct emulator {
    uint64_t flags;                 // only in callback function and config set, safe
    divert_mem_pool_t *pool;

    /*
     * initialized by emulator_set_dump_pcap()
     */
    char *dump_path;                // only use in config set, safe
    FILE *dump_normal;              // these are accessed after initialize, safe
    FILE *dump_unknown;
    FILE *dump_affected;

    /*
     * initialized by emulator_set_pid_list()
     */
    ssize_t num_pid;                // ensured to be accessed after set
    pid_t *pid_list;

    /*
     * thread control variables
     * initialized in emulator_create_config()
     * and emulator_thread_func()
     */
    pthread_t emulator_thread;
    pthread_t timer_thread;

    /*
     * first node of processing pipes
     * and a exit pipe
     */
    pipe_node_t *pipe[3];
    uint64_t dsize[3];
    pipe_node_t *exit_pipe;

    /*
     * store all packets and events
     */
    circ_buf_t *packet_queue;

    /*
     * store timeout events
     */
    pqueue *timer_queue;

    emulator_packet_t timeout_packet;
};


/*
 * Internal functions
 */

double rand_double();

int time_greater_than(struct timeval *a,
                      struct timeval *b);

double time_minus(struct timeval *a,
                  struct timeval *b);

double
calc_val_by_time(float *t, float *val,
                 ssize_t n, ssize_t *p,
                 struct timeval *tv_start);

void time_add(struct timeval *tv, double time);

int is_effect_applied(packet_size_filter *filter,
                      size_t real_size);

void
register_timer(pipe_node_t *node,
               struct timeval *tv);

void *emulator_thread_func(void *args);

/*
 * Interfaces
 */

void emulator_callback(void *, void *, struct ip *, struct sockaddr *);

emulator_config_t *
emulator_create_config(divert_t *handle,
                       size_t buf_size);

void emulator_destroy_config(emulator_config_t *config);

void emulator_start(emulator_config_t *config);

void emulator_stop(emulator_config_t *config);

uint64_t emulator_data_size(emulator_config_t *config, int direction);

int emulator_add_pipe(emulator_config_t *config,
                      pipe_node_t *node, int direction);

int emulator_del_pipe(emulator_config_t *config,
                      pipe_node_t *node, int free_mem);

void emulator_add_flag(emulator_config_t *config, uint64_t new_flag);

void emulator_clear_flags(emulator_config_t *config);

void emulator_clear_flag(emulator_config_t *config, uint64_t flag);

void emulator_set_dump_pcap(emulator_config_t *config,
                            char *dump_path);

void emulator_set_pid_list(emulator_config_t *config,
                           pid_t *pid_list, ssize_t num);

int emulator_config_check(emulator_config_t *config, char *errmsg);

int emulator_is_running(emulator_config_t *config);

packet_size_filter *
emulator_create_size_filter(size_t num, size_t *size, float *rate);

void emulator_free_size_filter(packet_size_filter *filter);

#endif //DIVERT_EMULATOR_CONFIG_H
