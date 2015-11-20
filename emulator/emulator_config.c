#include "emulator_config.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

emulator_config_t *emulator_create_config() {
    emulator_config_t *config = calloc(sizeof(emulator_config_t), 1);
    config->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(config->mutex, NULL);
    config->delay_thread = (pthread_t)-1;
    config->throttle_thread = (pthread_t)-1;
    memset(config->packet_size, -1,
           sizeof(config->packet_size));
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

#define CHECK_AND_FREE(VAR)     \
    if ((VAR) != NULL) {        \
        free((VAR));            \
    }

#define MALLOC_AND_COPY(DST, SRC, NUM)          \
    (DST) = malloc(sizeof(float) * (NUM));      \
    memcpy((DST), (SRC), sizeof(float *) * (NUM));

#define EMULATOR_SET_FUNC(NAME, ARR1, ARR2)                     \
    void emulator_set_##NAME(emulator_config_t *config,         \
                             ssize_t num_##NAME,                \
                             float *ARR1, float *ARR2) {        \
        config->num_##NAME = num_##NAME;                        \
        config->t_##NAME = 0;                                   \
        CHECK_AND_FREE(config->ARR1)                            \
        CHECK_AND_FREE(config->ARR2)                            \
        MALLOC_AND_COPY(config->ARR1, (ARR1), (num_##NAME))     \
        MALLOC_AND_COPY(config->ARR2, (ARR2), (num_##NAME))     \
    }

EMULATOR_SET_FUNC(drop, time_drop, drop_rate)

EMULATOR_SET_FUNC(delay, time_delay, delay_time)

EMULATOR_SET_FUNC(disorder, time_disorder, disorder_rate)

EMULATOR_SET_FUNC(tamper, time_tamper, tamper_rate)

EMULATOR_SET_FUNC(duplicate, time_duplicate, duplicate_rate)

EMULATOR_SET_FUNC(throttle, time_start, time_end)
