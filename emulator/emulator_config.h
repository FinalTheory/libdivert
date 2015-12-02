#ifndef DIVERT_EMULATOR_CONFIG_H
#define DIVERT_EMULATOR_CONFIG_H

#include "divert.h"
#include "queue.h"
#include "pqueue.h"
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h>

enum {
    DIRECTION_IN = 0,
    DIRECTION_OUT = 1,
    DIRECTION_BOTH = 2,
    DIRECTION_UNKNOWN = 3,
};


#define EMULATOR_EFFECTS    6

enum {
    OFFSET_DROP         = 0,
    OFFSET_DELAY        = 1,
    OFFSET_THROTTLE     = 2,
    OFFSET_DISORDER     = 3,
    OFFSET_TAMPER       = 4,
    OFFSET_DUPLICATE    = 5,

    OFFSET_DUMP_PCAP    = 6,
    OFFSET_RECHECKSUM   = 7,
    OFFSET_RUNNING      = 8,
};

#define EMULATOR_DROP       (1u << OFFSET_DROP)
#define EMULATOR_DELAY      (1u << OFFSET_DELAY)
#define EMULATOR_THROTTLE   (1u << OFFSET_THROTTLE)
#define EMULATOR_DISORDER   (1u << OFFSET_DISORDER)
#define EMULATOR_TAMPER     (1u << OFFSET_TAMPER)
#define EMULATOR_DUPLICATE  (1u << OFFSET_DUPLICATE)

#define EMULATOR_DUMP_PCAP  (1u << OFFSET_DUMP_PCAP)
#define EMULATOR_RECHECKSUM (1u << OFFSET_RECHECKSUM)
// WARNING: you should not use these flags in your code
#define EMULATOR_IS_RUNNING (1u << OFFSET_RUNNING)


// size of packet buffer
#define DISORDER_BUF_SIZE   1024
#define DELAY_BUF_SIZE      1024
// latency for at most 10 packets
#define MAX_DISORDER_NUM    10
// max number of duplicate packet
#define MAX_DUPLICATE_NUM   4
// max tamper bytes
#define MAX_TAMPER_BYTES    4
// control the tamper rate
#define TAMPER_CONTROL      4
#define FLOAT_EPS           (1e-7)

typedef struct {
    divert_t *handle;               // only used in divert_reinject(), thread safe
    uint64_t flags;                 // only in callback function and config set, safe

    char *dump_path;                // only use in config set, safe
    FILE *dump_normal;              // these are accessed after initialize, safe
    FILE *dump_unknown;
    FILE *dump_affected;

    ssize_t num_pid;                // ensured to be accessed after set
    pid_t *pid_list;

    /*
     * all these variables are used only in a single thread
     * so they must be thread safe
     */
    ssize_t num[EMULATOR_EFFECTS];
    ssize_t idx[EMULATOR_EFFECTS];
    float *t[EMULATOR_EFFECTS];
    float *val[EMULATOR_EFFECTS];
    struct timeval tv[EMULATOR_EFFECTS];

    size_t *packet_size;
    float *packet_rate;
    size_t num_size;

    /*
     * thread control variables
     * of course thread safe
     */
    pthread_t delay_thread;
    pthread_t throttle_thread;
    pthread_t emulator_thread;

    u_char direction_flags[EMULATOR_EFFECTS];

    uint32_t num_dup;
    uint32_t num_disorder;
    uint64_t counters[2];

    /*
     * these are thread safe data structures
     */
    PQueue *delay_queue;
    queue_t *throttle_queue;
    PQueue *disorder_queue;
    circ_buf_t *packet_queue;
} emulator_config_t;

typedef struct {
    struct ip *packet;
    struct sockaddr sin;
    proc_info_t proc_info;
    int32_t label;
    u_char direction;
} emulator_packet_t;

typedef struct {
    emulator_packet_t *packet;
    uint64_t time_send;
} disorder_packet_t;


typedef struct {
    emulator_packet_t *packet;
    struct timeval time_send;
} delay_packet_t;

typedef delay_packet_t throttle_packet_t;


#define CHECK_AND_FREE(VAR)     \
    if ((VAR) != NULL) {        \
        free((VAR));            \
    }

#define MALLOC_AND_COPY(DST, SRC, NUM, TYPE)     \
    (DST) = malloc(sizeof(TYPE) * (NUM));      \
    memcpy((DST), (SRC), sizeof(TYPE) * (NUM));

emulator_config_t *emulator_create_config();

void emulator_destroy_config(emulator_config_t *config);

void emulator_add_flag(emulator_config_t *config, uint64_t new_flag);

void emulator_clear_flags(emulator_config_t *config);

void emulator_clear_flag(emulator_config_t *config, uint64_t flag);

void emulator_set_handle(emulator_config_t *config, divert_t *handle);

void emulator_set_dump_pcap(emulator_config_t *config,
                            char *dump_path);

void emulator_set_pid_list(emulator_config_t *config,
                           pid_t *pid_list, ssize_t num);

void emulator_set_direction(emulator_config_t *config,
                            int offset, u_char val);

void emulator_set_packet_size_rate(emulator_config_t *config,
                                   size_t num, size_t *size, float *rate);

void emulator_set_data(emulator_config_t *config,
                       int offset, ssize_t num,
                       float *t, float *val);

void emulator_set_num_disorder(emulator_config_t *config,
                               uint32_t num_disorder);

void emulator_set_num_duplicate(emulator_config_t *config,
                                uint32_t duplicate);

int emulator_config_check(emulator_config_t *config, char *errmsg);

int emulator_is_running(emulator_config_t *config);

#endif //DIVERT_EMULATOR_CONFIG_H
