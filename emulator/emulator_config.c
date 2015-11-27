#include "emulator_config.h"
#include "emulator_callback.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

static int
cmp_disorder_packet(const void *x, const void *y) {
    const disorder_packet_t *a = x;
    const disorder_packet_t *b = y;
    if (a->time_send > b->time_send) {
        return -1;
    } else if (a->time_send < b->time_send) {
        return 1;
    } else {
        return 0;
    }
}

static int
cmp_delay_packet(const void *x, const void *y) {
    if (x == NULL) { return 1; }
    if (y == NULL) { return -1; }
    const delay_packet_t *a = x;
    const delay_packet_t *b = y;
    uint64_t val_a = a->time_send.tv_sec *
                     (uint64_t)1000000 +
                     a->time_send.tv_usec;
    uint64_t val_b = b->time_send.tv_sec *
                     (uint64_t)1000000 +
                     b->time_send.tv_usec;
    if (val_a > val_b) {
        return -1;
    } else if (val_a < val_b) {
        return 1;
    } else {
        return 0;
    }
}

static void
throttle_free_node_func(void *p) {
    throttle_packet_t *pkt = (throttle_packet_t *)p;
    CHECK_AND_FREE(pkt->packet)
    CHECK_AND_FREE(pkt)
}

emulator_config_t *emulator_create_config() {
    emulator_config_t *config =
            calloc(sizeof(emulator_config_t), 1);
    // capture packets for both direction by default
    for (int i = 0; i < 8; i++) {
        config->direction_flags[i] = DIRECTION_IN;
    }
    config->delay_thread = (pthread_t)-1;
    config->throttle_thread = (pthread_t)-1;
    config->emulator_thread = (pthread_t)-1;
    // init packet size array
    memset(config->packet_size, -1,
           sizeof(config->packet_size));
    // init priority queues
    config->disorder_queue =
            pqueue_new(cmp_disorder_packet, DISORDER_BUF_SIZE);
    config->delay_queue =
            pqueue_new(cmp_delay_packet, DELAY_BUF_SIZE);
    // normal queue for throttle packets
    config->throttle_queue = queue_create(throttle_free_node_func);
    // buffer for packet processing
    config->packet_queue = circ_buf_create(DIVERT_DEFAULT_BUFSIZE * 2);

    // create emulator thread
    // all three threads are associated with emulator_config_t
    pthread_create(&config->emulator_thread, NULL,
                   emulator_thread_func, config);

    return config;
}

void emulator_destroy_config(emulator_config_t *config) {
    void *thread_res;
    if (config != NULL) {
        emulator_packet_t *ptr = malloc(sizeof(emulator_packet_t));
        memset(ptr, 0, sizeof(emulator_packet_t));
        ptr->label = QUIT_THREAD;
        circ_buf_insert(config->packet_queue, ptr);
        // wait child thread to exit
        if (config->emulator_thread != (pthread_t)-1) {
            pthread_join(config->emulator_thread, &thread_res);
            config->emulator_thread = (pthread_t)-1;
        }
        if (config->flags & EMULATOR_DUMP_PCAP) {
            fclose(config->dump_normal);
            fclose(config->dump_affected);
            fclose(config->dump_unknown);
        }
        pqueue_destroy(config->delay_queue);
        pqueue_destroy(config->disorder_queue);
        queue_destroy(config->throttle_queue);
        circ_buf_destroy(config->packet_queue);
        // TODO: free all useless pointers
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

void emulator_add_flag(emulator_config_t *config, uint64_t new_flag) {
    config->flags |= new_flag;
}

void emulator_clear_flagS(emulator_config_t *config) {
    config->flags = 0;
}

void emulator_set_dump_pcap(emulator_config_t *config,
                            char *dump_path) {
    config->flags |= EMULATOR_DUMP_PCAP;
    size_t path_len = strlen(dump_path);
    config->dump_path = strdup(dump_path);

    char *filename = malloc(path_len + 32);
    strcpy(filename, dump_path);
    strcat(filename, "/capture_normal.pcap");
    config->dump_normal = fopen(filename, "wb");
    divert_init_pcap(config->dump_normal);

    strcpy(filename, dump_path);
    strcat(filename, "/capture_unknown.pcap");
    config->dump_unknown = fopen(filename, "wb");
    divert_init_pcap(config->dump_unknown);

    strcpy(filename, dump_path);
    strcat(filename, "/capture_affected.pcap");
    config->dump_affected = fopen(filename, "wb");
    divert_init_pcap(config->dump_affected);

    free(filename);
}

void emulator_set_direction(emulator_config_t *config,
                            int offset, u_char val) {
    config->direction_flags[offset] = val;
}

void emulator_set_handle(emulator_config_t *config,
                         divert_t *handle) {
    config->handle = handle;
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
