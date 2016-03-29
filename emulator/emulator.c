#include <divert.h>
#include <assert.h>
#include "emulator.h"
#include "dump_packet.h"
#include "throttle.h"
#include "reinject.h"
#include "drop.h"
#include "disorder.h"
#include "biterr.h"
#include "bandwidth.h"
#include "duplicate.h"


void swap(void **a, void **b) {
    void *tmp = *b;
    *b = *a;
    *a = tmp;
}

inline double
rand_double() {
    return rand() / (double)RAND_MAX;
}

inline int
time_greater_than(struct timeval *a, struct timeval *b) {
    if (a->tv_sec != b->tv_sec) {
        return a->tv_sec > b->tv_sec;
    } else {
        return a->tv_usec > b->tv_usec;
    }
}

inline double
time_minus(struct timeval *a, struct timeval *b) {
    double delta_secs = a->tv_sec - b->tv_sec;
    double delta_usecs = a->tv_usec - b->tv_usec;
    return delta_secs + delta_usecs / 1000000.;
}

inline void
time_add(struct timeval *tv, double time) {
    tv->tv_sec += (long)time;
    tv->tv_usec += (long)((time - (long)time) * 1000000.);
    if (tv->tv_usec > 1000000) {
        tv->tv_usec -= 1000000;
        tv->tv_sec += 1;
    }
}

inline ssize_t
upper_bound(float *arr, size_t left, size_t right, double val) {
    ssize_t result = -1;
    while (left < right) {
        size_t mid = (left + right) / 2;
        if (arr[mid] > val) {
            result = right = mid;
        } else {
            left = mid + 1;
        }
    }
    return result;
}

inline double
calc_val_by_time(float *t, float *val,
                 ssize_t n, ssize_t *p,
                 struct timeval *tv_start) {
    // guard here to avoid invalid memory access
    if (t == NULL || val == NULL) {
        return 0.;
    }

    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);

    // get end time of this function
    double end_time = t[n - 1];
    // get current time of this period
    double t_now = time_minus(&tv, tv_start);
    // if current time is out of one period
    if (t_now >= end_time) {
        long k = (long)(t_now / end_time);
        // then reset it to beginning
        time_add(tv_start, end_time * k);
        t_now -= end_time * k;
        *p = 0;
    }
    // find a time point just after current time
    int loop_cnt = 0;
    while (t[*p] <= t_now) {
        (*p)++;
        loop_cnt++;
        if (loop_cnt >= 8) {
            *p = upper_bound(t, 0, (size_t)n, t_now);
            break;
        }
    }
    assert((*p >= 0 && *p < n));
    assert(t[*p] > t_now);
    // rewind back a step
    if (*p > 0) { (*p)--; }
    // linear interpolate
    double result = val[*p] +
                    (t_now - t[*p]) *
                    (val[*p + 1] - val[*p]) /
                    (t[*p + 1] - t[*p]);
    return result > 0. ? result : 0.;
}

inline static int
check_pid_in_list(pid_t pid, pid_t *pid_list, ssize_t n) {
    if (n == 0 || pid_list == NULL) {
        // pid_list is empty means match all
        return 1;
    }
    for (int i = 0; i < n; i++) {
        if (pid_list[i] == pid) {
            return 1;
        }
    }
    return 0;
}

int is_effect_applied(packet_size_filter *filter,
                      size_t real_size) {
    // if not configured, apply the effects
    if (filter == NULL ||
        filter->size == NULL ||
        filter->rate == NULL) {
        return 1;
    }
    for (int i = 0; i < filter->num &&
                    filter->size[i] != -1; i++) {
        size_t prev_size = (i == 0 ? 0 : filter->size[i - 1]);
        if (prev_size <= real_size &&
            real_size < filter->size[i]) {
            double rate = filter->rate[i];
            if (rand_double() < rate) {
                return 1;
            } else {
                return 0;
            }
        }
    }
    // for all other situation, apply the effects
    return 1;
}

static void
init_callback_runtime_states(emulator_config_t *config) {
    if (!(config->flags & EMULATOR_IS_RUNNING)) {
        config->flags |= EMULATOR_IS_RUNNING;
        srand((unsigned)time(NULL));
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        // copy values to all time stamps
        for (int dir = 0; dir < 2; dir++) {
            for (pipe_node_t *ptr = config->pipe[dir];
                 ptr; ptr = ptr->next) {
                ptr->tv_start = tv;
            }
        }
    }
}

void emulator_process(emulator_config_t *config,
                      emulator_packet_t *packet) {
    pipe_node_t *node = NULL;

    // check the direction of this packet
    // and take corresponding actions
    int dir = packet->direction;
    if (config->pipe[dir] != NULL) {
        // insert packet into first pipe
        config->pipe[dir]->insert(config->pipe[dir], packet);
        // process each pipe if it has process function
        for (node = config->pipe[dir]; node;
             node = node->next) {
            if (NULL != node->process) {
                node->process(node);
            }
        }
    }
}

void emulator_flush(emulator_config_t *config) {
    // flush all buffered packets
    for (int dir = 0; dir < 2; dir++) {
        for (pipe_node_t *node = config->pipe[dir];
             node; node = node->next) {
            if (NULL != node->clear) {
                node->clear(node);
            }
        }
    }
    // remove the running flag
    config->flags &= ~((uint64_t)EMULATOR_IS_RUNNING);
}

void emulator_callback(void *args, void *proc,
                       struct ip *ip_data,
                       struct sockaddr *sin) {
    char errmsg[DIVERT_ERRBUF_SIZE];
    emulator_config_t *config = args;

    // check if we should fill time stamps
    init_callback_runtime_states(config);

    // first process if this is a timeout event
    if (ip_data == NULL && sin == NULL) {
        emulator_packet_t timeout_packet;
        memset(&timeout_packet, 0, sizeof(emulator_packet_t));
        timeout_packet.direction = (u_char)*(int *)proc;
        timeout_packet.label = TIMEOUT_EVENT;
        emulator_process(config, &timeout_packet);
        return;
    }

    proc_info_t *proc_info = proc;
    pid_t pid = proc_info->pid != -1 ?
                proc_info->pid : proc_info->epid;

    reinject_pipe_t *pipe = container_of(config->exit_pipe,
                                         reinject_pipe_t, node);
    // check direction of this packet
    // note that we should first check
    // if this packet comes from a special device
    u_char direction, match_device = 0;
    if (divert_device_inbound(pipe->handle, ip_data)) {
        match_device = 1;
        direction = DIRECTION_IN;
    } else if (divert_device_outbound(pipe->handle, ip_data)) {
        match_device = 1;
        direction = DIRECTION_OUT;
    } else if (divert_is_inbound(sin, NULL)) {
        direction = DIRECTION_IN;
    } else if (divert_is_outbound(sin)) {
        direction = DIRECTION_OUT;
    } else {
        direction = DIRECTION_UNKNOWN;
    }

    /*
     * if this packet is from unknown PID
     * then we must record it first
     */
    if (!match_device && pid == -1 &&
        (config->flags & EMULATOR_DUMP_PCAP)) {
        divert_dump_pcap(ip_data, config->dump_unknown);
    }

    /*
     * if this packet is not from target process
     * or not from a specified network interface
     * just re-inject and ignore this packet
     * notice that re-inject function is thread safe
     */
    if (!check_pid_in_list(pid, config->pid_list,
                           config->num_pid) && !match_device) {
        // do not re-inject through exit pipe
        // since we're not interested in this packet
        divert_reinject(pipe->handle, ip_data, -1, sin);
        return;
    }

    /*
     * packet dump stage
     */
    if (config->flags & EMULATOR_DUMP_PCAP) {
        if (direction == DIRECTION_IN) {
            divert_dump_pcap(ip_data, config->dump_server);
        } else if (direction == DIRECTION_OUT) {
            divert_dump_pcap(ip_data, config->dump_client);
        }
    }

    /*
     * packets production stage
     */
    emulator_packet_t *packet =
            divert_mem_alloc(config->pool,
                             sizeof(emulator_packet_t));
    /*
     * If no pipe is associated with this packet direction
     * or the direction of this packet is unknown
     * then we mark it as a special packet type
     */
    packet->sin = *sin;
    packet->label = NEW_PACKET;
    packet->direction = direction;
    packet->proc_info = *((proc_info_t *)proc);
    size_t ip_len = ntohs(ip_data->ip_len);
    packet->ip_data = divert_mem_alloc(config->pool, ip_len);
    memcpy(packet->ip_data, ip_data, ip_len);
    divert_dump_packet((u_char *)packet->ip_data,
                       &packet->headers, errmsg);

    emulator_process(config, packet);
}

void register_timer(pipe_node_t *node,
                    struct timeval *tv,
                    int direction) {
    emulator_config_t *config = node->config;
    divert_t *handle = container_of(config->exit_pipe,
                                    reinject_pipe_t, node)->handle;
    int *dir = divert_mem_alloc(handle->pool, sizeof(int));
    *dir = direction;
    divert_register_timer(handle, tv, dir, 0);
}

emulator_config_t *emulator_create_config(divert_t *handle) {
    emulator_config_t *config =
            calloc(sizeof(emulator_config_t), 1);

    config->pool = divert_create_pool(DEFAULT_PACKET_SIZE);

    config->exit_pipe = reinject_pipe_create(handle);
    config->exit_pipe->config = config;

    config->pipe[DIRECTION_IN] = config->exit_pipe;
    config->pipe[DIRECTION_OUT] = config->exit_pipe;
    config->pipe[DIRECTION_UNKNOWN] = config->exit_pipe;

    return config;
}

uint64_t emulator_data_size(emulator_config_t *config, int direction) {
    if (0 <= direction && direction < 3) {
        return config->dsize[direction];
    }
    return 0;
}

void emulator_destroy_config(emulator_config_t *config) {
    if (config != NULL) {
        // free memory of all pipes
        for (int dir = 0; dir < 2; dir++) {
            for (pipe_node_t *node = config->pipe[dir];
                 node; node = node->next)
            if (node->free != NULL) {
                node->free(node);
            }
        }

        // close .pcap files
        if (config->flags & EMULATOR_DUMP_PCAP) {
            CHECK_AND_FREE(config->dump_path)
            fclose(config->dump_client);
            fclose(config->dump_server);
            fclose(config->dump_unknown);
        }

        // free memory pool
        divert_destroy_pool(config->pool);
        free(config);
    }
}

void emulator_set_pid_list(emulator_config_t *config,
                           pid_t *pid_list, ssize_t num) {
    // copy first
    pid_t *dup_list = divert_mem_alloc(config->pool, sizeof(pid_t) * num);
    memcpy(dup_list, pid_list, sizeof(pid_t) * num);
    // then swap
    swap((void **)&dup_list, (void **)&config->pid_list);
    config->num_pid = num;
    divert_mem_free(config->pool, dup_list);
}

void emulator_add_flag(emulator_config_t *config,
                       uint64_t new_flag) {
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

    // this malloc should be freed
    char *filename = malloc(path_len + 32);
    strcpy(filename, dump_path);
    strcat(filename, "/capture_client.pcap");
    config->dump_client = fopen(filename, "wb");
    divert_init_pcap(config->dump_client);

    strcpy(filename, dump_path);
    strcat(filename, "/capture_unknown.pcap");
    config->dump_unknown = fopen(filename, "wb");
    divert_init_pcap(config->dump_unknown);

    strcpy(filename, dump_path);
    strcat(filename, "/capture_server.pcap");
    config->dump_server = fopen(filename, "wb");
    divert_init_pcap(config->dump_server);

    free(filename);
    config->flags |= EMULATOR_DUMP_PCAP;
}

packet_size_filter *
emulator_create_size_filter(size_t num,
                            size_t *size,
                            float *rate) {
    packet_size_filter *filter =
            calloc(1, sizeof(packet_size_filter));
    filter->num = num;
    MALLOC_AND_COPY(filter->size, size, num, size_t)
    MALLOC_AND_COPY(filter->rate, rate, num, float)
    return filter;
}

void emulator_free_size_filter(packet_size_filter *filter) {
    if (filter == NULL) { return; }
    CHECK_AND_FREE(filter->rate)
    CHECK_AND_FREE(filter->size)
    CHECK_AND_FREE(filter)
}

int emulator_is_running(emulator_config_t *config) {
    return (config->flags & EMULATOR_IS_RUNNING) > 0;
}

int emulator_config_check(emulator_config_t *config, char *errmsg) {
    errmsg[0] = 0;

    if (NULL == config) {
        sprintf(errmsg, "Invalid config handle.");
        return -1;
    }
    if (config->exit_pipe == NULL) {
        sprintf(errmsg, "Exit pipe not set.");
        return -1;
    }
    for (int dir = 0; dir < 2; dir++) {
        for (pipe_node_t *cur = config->pipe[dir];
             cur != NULL && cur != config->exit_pipe;
             cur = cur->next) {
            float *t = NULL, *val = NULL;
            switch (cur->pipe_type) {
                case PIPE_REINJECT: {
                    reinject_pipe_t *pipe = container_of(cur, reinject_pipe_t, node);
                    if (pipe->handle == NULL) {
                        sprintf(errmsg, "Divert handle could not be NULL.");
                        return -1;
                    }
                }
                    break;
                case PIPE_THROTTLE: {
                    throttle_pipe_t *pipe = container_of(cur, throttle_pipe_t, node);
                    float *t1 = pipe->t_start;
                    float *t2 = pipe->t_end;
                    for (int k = 0; k < cur->num; k++) {
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
                    break;
                case PIPE_DROP: {
                    drop_pipe_t *pipe = container_of(cur, drop_pipe_t, node);
                    val = pipe->drop_rate;
                }
                case PIPE_DELAY: {
                    delay_pipe_t *pipe = container_of(cur, delay_pipe_t, node);
                    val = pipe->delay_time;
                }
                    if (val == NULL) {
                        sprintf(errmsg, "Emulation data not set.");
                        return -1;
                    }
                    break;
                case PIPE_DISORDER: {
                    disorder_pipe_t *pipe = container_of(cur, disorder_pipe_t, node);
                    t = pipe->t;
                    val = pipe->disorder_rate;
                }
                case PIPE_BITERR: {
                    biterr_pipe_t *pipe = container_of(cur, biterr_pipe_t, node);
                    t = pipe->t;
                    val = pipe->biterr_rate;
                }
                case PIPE_BANDWIDTH: {
                    bandwidth_pipe_t *pipe = container_of(cur, bandwidth_pipe_t, node);
                    t = pipe->t;
                    val = pipe->bandwidth;
                }
                case PIPE_DUPLICATE: {
                    duplicate_pipe_t *pipe = container_of(cur, duplicate_pipe_t, node);
                    t = pipe->t;
                    val = pipe->dup_rate;
                }
                    if (t == NULL ||
                        val == NULL ||
                        cur->num == 0) {
                        sprintf(errmsg, "Effect data not set.");
                        return -1;
                    }
                    if (t[0] > FLOAT_EPS) {
                        sprintf(errmsg, "Each periodic function should start from time zero.");
                        return -1;
                    }
                    break;
                default:
                    sprintf(errmsg, "Unknown PIPE flag.");
                    return -1;
            }
        }
    }

    if (config->flags & EMULATOR_DUMP_PCAP) {
        if (config->dump_path == NULL ||
            config->dump_client == NULL ||
            config->dump_server == NULL ||
            config->dump_unknown == NULL) {
            sprintf(errmsg, "NULL pointers when dump .pcap file.");
            return -1;
        }
    }
    return 0;
}


int emulator_add_pipe(emulator_config_t *config,
                      pipe_node_t *node, int direction) {
    if (direction != 0 && direction != 1) { return -1; }
    // first check if this pipe exists
    for (int dir = 0; dir < 2; dir++) {
        for (pipe_node_t *ptr = config->pipe[dir];
             ptr; ptr = ptr->next) {
            if (ptr == node) {
                return -1;
            }
        }
    }

    node->config = config;
    node->next = config->exit_pipe;
    if (config->pipe[direction] == config->exit_pipe) {
        config->pipe[direction] = node;
    } else {
        pipe_node_t *ptr = config->pipe[direction];
        while (ptr->next != NULL &&
               ptr->next != config->exit_pipe) {
            ptr = ptr->next;
        }
        ptr->next = node;
    }
    return 0;
}

int emulator_del_pipe(emulator_config_t *config,
                      pipe_node_t *node, int free_mem) {
    // the exit pipe should never be deleted
    if (node == config->exit_pipe) {
        return -1;
    }
    for (int dir = 0; dir < 2; dir++) {
        for (pipe_node_t **ptr = &config->pipe[dir];
             *ptr != NULL && *ptr != config->exit_pipe;) {
            pipe_node_t *entry = *ptr;
            if (entry == node) {
                if (free_mem) {
                    if (entry->clear != NULL) { entry->clear(entry); }
                    if (entry->free != NULL) { entry->free(entry); }
                }
                *ptr = entry->next;
            } else {
                ptr = &entry->next;
            }
        }
    }

    return 0;
}
