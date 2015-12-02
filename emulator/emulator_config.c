#include "emulator_config.h"
#include "emulator_callback.h"
#include <stdlib.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void swap(void **a, void **b) {
    void *tmp = *b;
    *b = *a;
    *a = tmp;
}

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
    for (int i = 0; i < EMULATOR_EFFECTS; i++) {
        config->direction_flags[i] = DIRECTION_IN;
    }
    config->num_dup = MAX_DUPLICATE_NUM;
    config->num_disorder = MAX_DISORDER_NUM;

    config->delay_thread = (pthread_t)-1;
    config->throttle_thread = (pthread_t)-1;
    config->emulator_thread = (pthread_t)-1;

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
    // associated with emulator_config_t
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
            CHECK_AND_FREE(config->dump_path)
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

void emulator_set_pid_list(emulator_config_t *config,
                           pid_t *pid_list, ssize_t num) {
    // copy first
    pid_t *dup_list = malloc(sizeof(pid_t) * num);
    memcpy(dup_list, pid_list, sizeof(pid_t) * num);
    // then swap
    swap((void **)&dup_list, (void **)&config->pid_list);
    config->num_pid = num;
    CHECK_AND_FREE(dup_list)
}

void emulator_add_flag(emulator_config_t *config, uint64_t new_flag) {
    config->flags |= new_flag;
}

void emulator_clear_flags(emulator_config_t *config) {
    config->flags = 0;
}

void emulator_clear_flag(emulator_config_t *config, uint64_t flag) {
    config->flags &= ~((uint64_t)flag);
}

void emulator_set_dump_pcap(emulator_config_t *config,
                            char *dump_path) {
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
    config->flags |= EMULATOR_DUMP_PCAP;
}

void emulator_set_direction(emulator_config_t *config,
                            int offset, u_char val) {
    config->direction_flags[offset] = val;
}

void emulator_set_handle(emulator_config_t *config,
                         divert_t *handle) {
    config->handle = handle;
}

void emulator_set_packet_size_rate(emulator_config_t *config,
                                   size_t num, size_t *size, float *rate) {
    size_t *tmp_size;
    float *tmp_rate;
    MALLOC_AND_COPY(tmp_size, size, num, size_t)
    MALLOC_AND_COPY(tmp_rate, rate, num, float)
    swap((void **)&tmp_size, (void **)&config->packet_size);
    swap((void **)&tmp_rate, (void **)&config->packet_rate);
    CHECK_AND_FREE(tmp_size)
    CHECK_AND_FREE(tmp_rate)
}

void emulator_set_data(emulator_config_t *config,
                       int offset, ssize_t num,
                       float *t, float *val) {
    config->num[offset] = num;
    config->idx[offset] = 0;
    float *tmp_t, *tmp_val;
    MALLOC_AND_COPY(tmp_t, t, num, float)
    MALLOC_AND_COPY(tmp_val, val, num, float)
    swap((void **)&tmp_t, (void **)&config->t[offset]);
    swap((void **)&tmp_val, (void **)&config->val[offset]);
    CHECK_AND_FREE(tmp_t)
    CHECK_AND_FREE(tmp_val)
}

void emulator_set_num_disorder(emulator_config_t *config,
                               uint32_t num_disorder) {
    config->num_disorder = num_disorder;
}

void emulator_set_num_duplicate(emulator_config_t *config,
                               uint32_t duplicate) {
    config->num_dup = duplicate;
}

int emulator_is_running(emulator_config_t *config) {
    return (config->flags & EMULATOR_IS_RUNNING) > 0;
}

int emulator_config_check(emulator_config_t *config, char *errmsg) {
    errmsg[0] = 0;
    uint64_t flags[EMULATOR_EFFECTS];
    flags[OFFSET_DROP] = EMULATOR_DROP;
    flags[OFFSET_DELAY] = EMULATOR_DELAY;
    flags[OFFSET_THROTTLE] = EMULATOR_THROTTLE;
    flags[OFFSET_DISORDER] = EMULATOR_DISORDER;
    flags[OFFSET_DUPLICATE] = EMULATOR_DUPLICATE;
    flags[OFFSET_TAMPER] = EMULATOR_TAMPER;

    if (NULL == config) {
        sprintf(errmsg, "Invalid config handle.");
        return -1;
    }
    if (config->handle == NULL) {
        sprintf(errmsg, "Divert handle not set.");
        return -1;
    }
    for (int i = 0; i < EMULATOR_EFFECTS; i++) {
        if (config->flags & flags[i]) {
            if (config->t[i] == NULL ||
                config->val[i] == NULL ||
                config->num[i] == 0) {
                sprintf(errmsg, "Effect data not set.");
                return -1;
            }
            if (i != OFFSET_THROTTLE &&
                config->t[i][0] > FLOAT_EPS) {
                sprintf(errmsg, "Each periodic function should start from time zero.");
                return -1;
            }
            if (i == OFFSET_THROTTLE) {
                float *t1 = config->t[OFFSET_THROTTLE];
                float *t2 = config->val[OFFSET_THROTTLE];
                for (int k = 0; k < config->num[OFFSET_THROTTLE]; k++) {
                    if (t1[k] >= t2[k]) {
                        sprintf(errmsg, "Throttle start time should "
                                "not later than end time.");
                        return -1;
                    }
                    if (k != 0 && (t1[k] <= t1[k - 1] || t2[k] <= t2[k - 1])) {
                        sprintf(errmsg, "Time values should be ascending order.");
                        return -1;
                    }
                    if (k != 0 && t2[k - 1] >= t1[k]) {
                        sprintf(errmsg, "Time ranges should not overlap.");
                        return -1;
                    }
                }
            }
        }
    }
    if (config->flags & EMULATOR_DUMP_PCAP) {
        if (config->dump_path == NULL ||
            config->dump_normal == NULL ||
            config->dump_affected == NULL ||
            config->dump_unknown == NULL) {
            sprintf(errmsg, "NULL pointers when dump .pcap file.");
            return -1;
        }
    }
    return 0;
}
