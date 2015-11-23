#ifndef DIVERT_EMULATOR_CONFIG_H
#define DIVERT_EMULATOR_CONFIG_H

#include "divert.h"
#include "queue.h"
#include "pqueue.h"
#include <ctype.h>
#include <unistd.h>
#include <sys/time.h>

#define EMULATOE_IS_RUNNING (1u)
#define EMULATOR_DROP       (1u << 1)
#define EMULATOR_DELAY      (1u << 2)
#define EMULATOR_THROTTLE   (1u << 3)
#define EMULATOR_DISORDER   (1u << 4)
#define EMULATOR_TAMPER     (1u << 5)
#define EMULATOR_DUPLICATE  (1u << 6)

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

typedef struct {
    divert_t *handle;
    uint64_t flags;
    uint64_t counter;

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

    // TODO: 为乱序、延迟的packet设置优先队列

    pthread_mutex_t *mutex;

    size_t packet_size[PACKET_SIZE_LEVELS];
    float packet_rate[PACKET_SIZE_LEVELS];

    PQueue *delay_queue;
    PQueue *disorder_queue;
} emulator_config_t;

typedef struct {
    struct ip *packet;
    struct sockaddr *sin;
    uint64_t time_send;
} disorder_packet_t;


typedef struct {
    struct ip *packet;
    struct sockaddr *sin;
    struct timeval time_send;
} delay_packet_t;


#define CHECK_AND_FREE(VAR)     \
    if ((VAR) != NULL) {        \
        free((VAR));            \
    }

#define MALLOC_AND_COPY(DST, SRC, NUM, TYPE)     \
    (DST) = malloc(sizeof(TYPE) * (NUM));      \
    memcpy((DST), (SRC), sizeof(TYPE) * (NUM));


#endif //DIVERT_EMULATOR_CONFIG_H
