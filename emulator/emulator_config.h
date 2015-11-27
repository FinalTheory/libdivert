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

enum {
    OFFSET_RUNNING      = 0,
    OFFSET_DROP         = 1,
    OFFSET_DELAY        = 2,
    OFFSET_THROTTLE     = 3,
    OFFSET_DISORDER     = 4,
    OFFSET_TAMPER       = 5,
    OFFSET_DUPLICATE    = 6,
    OFFSET_DUMP_PCAP    = 7,
};

#define EMULATOR_DROP       (1u << OFFSET_DROP)
#define EMULATOR_DELAY      (1u << OFFSET_DELAY)
#define EMULATOR_THROTTLE   (1u << OFFSET_THROTTLE)
#define EMULATOR_DISORDER   (1u << OFFSET_DISORDER)
#define EMULATOR_TAMPER     (1u << OFFSET_TAMPER)
#define EMULATOR_DUPLICATE  (1u << OFFSET_DUPLICATE)
#define EMULATOR_DUMP_PCAP  (1u << OFFSET_DUMP_PCAP)
// WARNING: you should not use these flags in your code
#define EMULATOR_IS_RUNNING (1u << OFFSET_RUNNING)


#define PACKET_SIZE_LEVELS  10
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
    divert_t *handle;
    uint64_t flags;

    char *dump_path;
    FILE *dump_normal;
    FILE *dump_unknown;
    FILE *dump_affected;

    ssize_t num_pid;
    pid_t *pid_list;

    // describe packet drop
    ssize_t num_drop;
    ssize_t t_drop;
    float *drop_rate;
    float *time_drop;
    struct timeval drop_start;

    // packet out of order
    ssize_t num_disorder;
    ssize_t t_disorder;
    float *time_disorder;
    float *disorder_rate;
    struct timeval disorder_start;

    // packet tamper
    ssize_t num_tamper;
    ssize_t t_tamper;
    float *time_tamper;
    float *tamper_rate;
    struct timeval tamper_start;

    // packet duplicate
    ssize_t num_duplicate;
    ssize_t t_duplicate;
    float *time_duplicate;
    float *duplicate_rate;
    struct timeval duplicate_start;

    // packet lag
    ssize_t num_delay;
    ssize_t t_delay;
    float *time_delay;
    float *delay_time;
    struct timeval delay_start;

    // packet throttle
    ssize_t num_throttle;
    ssize_t t_throttle;
    float *time_start;
    float *time_end;
    struct timeval throttle_start;

    pthread_t delay_thread;
    pthread_t throttle_thread;
    pthread_t emulator_thread;

    size_t packet_size[PACKET_SIZE_LEVELS];
    float packet_rate[PACKET_SIZE_LEVELS];

    u_char direction_flags[8];

    PQueue *delay_queue;
    queue_t *throttle_queue;
    PQueue *disorder_queue;

    uint64_t counters[2];

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

void emulator_set_handle(emulator_config_t *config, divert_t *handle);

void emulator_set_pid(emulator_config_t *config,
                      pid_t *pid_list, ssize_t num);

void emulator_set_direction(emulator_config_t *config,
                            int offset, u_char val);

#define EMULATOR_SET_FUNC_IFACE(NAME, ARR1, ARR2)               \
    void emulator_set_##NAME(emulator_config_t *config,         \
                             ssize_t num_##NAME,                \
                             float *ARR1, float *ARR2);

EMULATOR_SET_FUNC_IFACE(drop, time_drop, drop_rate)

EMULATOR_SET_FUNC_IFACE(delay, time_delay, delay_time)

EMULATOR_SET_FUNC_IFACE(disorder, time_disorder, disorder_rate)

EMULATOR_SET_FUNC_IFACE(tamper, time_tamper, tamper_rate)

EMULATOR_SET_FUNC_IFACE(duplicate, time_duplicate, duplicate_rate)

EMULATOR_SET_FUNC_IFACE(throttle, time_start, time_end)


#endif //DIVERT_EMULATOR_CONFIG_H
