#include "emulator_config.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int cmp_disorder_packet(const void *x, const void *y) {
    disorder_packet_t *a = (disorder_packet_t *)x;
    disorder_packet_t *b = (disorder_packet_t *)y;
    if (a->time_send > b->time_send) {
        return -1;
    } else if (a->time_send < b->time_send) {
        return 1;
    } else {
        return 0;
    }
}

int cmp_delay_packet(const void *x, const void *y) {
    delay_packet_t *a = (delay_packet_t *)x;
    delay_packet_t *b = (delay_packet_t *)y;
    uint64_t val_a = a->time_send.tv_sec * 1000000ull + a->time_send.tv_usec;
    uint64_t val_b = b->time_send.tv_sec * 1000000ull + b->time_send.tv_usec;
    if (val_a > val_b) {
        return -1;
    } else if (val_a < val_b) {
        return 1;
    } else {
        return 0;
    }
}

emulator_config_t *emulator_create_config() {
    emulator_config_t *config = calloc(sizeof(emulator_config_t), 1);
    // init mutex
    config->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(config->mutex, NULL);
    // init thread control
    config->delay_thread = (pthread_t)-1;
    config->throttle_thread = (pthread_t)-1;
    // init packet size array
    memset(config->packet_size, -1,
           sizeof(config->packet_size));
    // init priority queues
    config->disorder_queue =
            pqueue_new(cmp_disorder_packet, DISORDER_BUF_SIZE);
    config->delay_queue =
            pqueue_new(cmp_delay_packet, DELAY_BUF_SIZE);
    return config;
}

void free_emulator_config(emulator_config_t *config) {
    if (config != NULL) {
        // TODO: free all pointers

        free(config);
    }
}

void emulator_set_pid(emulator_config_t *config,
                      pid_t *pid_list, ssize_t num) {
    config->pid_list = malloc(sizeof(pid_t) * num);
    memcpy(config->pid_list, pid_list, sizeof(pid_t) * num);
}

void emulator_set_divert_handle(emulator_config_t *config,
                                divert_t *handle) {
    config->handle = handle;
}

void emulator_set_flag(emulator_config_t *config, __uint64_t flags) {
    config->flags = flags;
}

void swap(float **a, float **b) {
    float *tmp = *b;
    *b = *a;
    *a = tmp;
}

#define EMULATOR_SET_FUNC(NAME, ARR1, ARR2)                     \
    void emulator_set_##NAME(emulator_config_t *config,         \
                             ssize_t num_##NAME,                \
                             float *ARR1, float *ARR2) {        \
        config->num_##NAME = num_##NAME;                        \
        config->t_##NAME = 0;                                   \
        float *tmp_##ARR1, *tmp_##ARR2;                         \
        MALLOC_AND_COPY(tmp_##ARR1, (ARR1), (num_##NAME), float)\
        MALLOC_AND_COPY(tmp_##ARR2, (ARR2), (num_##NAME), float)\
        swap(&tmp_##ARR1, &config->ARR1);                       \
        swap(&tmp_##ARR2, &config->ARR2);                       \
        CHECK_AND_FREE(tmp_##ARR1)                              \
        CHECK_AND_FREE(tmp_##ARR2)                              \
    }

EMULATOR_SET_FUNC(drop, time_drop, drop_rate)

EMULATOR_SET_FUNC(delay, time_delay, delay_time)

EMULATOR_SET_FUNC(disorder, time_disorder, disorder_rate)

EMULATOR_SET_FUNC(tamper, time_tamper, tamper_rate)

EMULATOR_SET_FUNC(duplicate, time_duplicate, duplicate_rate)

EMULATOR_SET_FUNC(throttle, time_start, time_end)
