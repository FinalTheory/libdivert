#include "emulator.h"
#include "dump_packet.h"
#include "throttle.h"
#include "reinject.h"

#include <string.h>


inline void
swap(void **a, void **b) {
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
    while (t[*p] <= t_now) {
        (*p)++;
    }
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

void *emulator_timer_thread_func(void *args) {
    emulator_config_t *config = args;
    struct timeval time_now;
    struct timezone tz;
    timeout_event_t *ptr;

    while (1) {
        // try to send all timeout events
        while (1) {
            ptr = pqueue_head(config->timer_queue);
            // NULL pointer means quit the thread
            if (ptr == NULL) { goto finish; }
            gettimeofday(&time_now, &tz);
            if (time_greater_than(&ptr->tv, &time_now)) { break; }
            ptr = pqueue_dequeue(config->timer_queue);
            circ_buf_insert(config->event_queue,
                            &config->timeout_packet);
            CHECK_AND_FREE(ptr)
        }

        // then wait until next timeout event
        if (pqueue_size(config->timer_queue) > 0) {
            ptr = pqueue_head(config->timer_queue);
            if (time_greater_than(&ptr->tv, &time_now)) {
                pqueue_wait_until(config->timer_queue, &ptr->tv);
            }
        }
    }
    finish:
    return NULL;
}

void *emulator_thread_func(void *args) {
    /*
     * initialize local variables
     * these are of course thread-safe
     */
    void *thread_res;
    emulator_config_t *config = args;
    pipe_node_t *node = NULL;

    // create timer thread
    pthread_create(&config->timer_thread, NULL,
                   emulator_timer_thread_func, config);
    /*
     * config && thread init stage
     */
    init_callback_runtime_states(config);

    while (1) {
        // get a packet from buffer
        emulator_packet_t *packet =
                circ_buf_remove(config->event_queue);

        // check if this is a quit signal
        if (packet->label == EVENT_QUIT) { break; }

        // check direction of this packet
        if (packet->direction != DIRECTION_UNKNOWN) {
            int dir = packet->direction;
            // insert packet into first pipe
            config->pipe[dir]->insert(config->pipe[dir], packet);
            // process each pipe if it has process function
            for (node = config->pipe[dir]; node;
                 node = node->next)
                if (NULL != node->process) {
                    node->process(node);
                }
        } else {
            // for packet with unknown direction, just re-inject it
            config->exit_pipe->insert(config->exit_pipe, packet);
        }
    }

    for (int dir = 0; dir < 2; dir++) {
        // flush all buffered packets
        for (node = config->pipe[dir]; node;
             node = node->next) {
            if (NULL != node->clear) {
                node->clear(node);
            }
        }
    }

    // quit timer thread
    pqueue_enqueue(config->timer_queue, NULL);
    // join the thread
    if (config->timer_thread != (pthread_t)-1) {
        pthread_join(config->timer_thread, &thread_res);
    }
    config->flags &= ~((uint64_t)EMULATOR_IS_RUNNING);
    return NULL;
}

void
register_timer(pipe_node_t *node,
               struct timeval *tv,
               int event_id) {
    emulator_config_t *config = node->config;
    timeout_event_t *event = malloc(sizeof(timeout_event_t));
    event->flag = event_id;
    event->tv = *tv;
    pqueue_enqueue(config->timer_queue, event);
}

void emulator_callback(void *args, void *proc,
                       struct ip *ip_data, struct sockaddr *sin) {
    char errmsg[DIVERT_ERRBUF_SIZE];
    // Note: this function won't be reentry
    emulator_config_t *config = args;
    proc_info_t *proc_info = proc;
    pid_t pid = proc_info->pid != -1 ?
                proc_info->pid : proc_info->epid;

    /*
     * if this packet is from unknown PID
     * then we must record it first
     */
    if (pid == -1 && (config->flags & EMULATOR_DUMP_PCAP)) {
        divert_dump_pcap(ip_data, config->dump_unknown);
    }

    /*
     * if this packet is not from target process
     * just re-inject and ignore this packet
     * notice that re-inject function is thread safe
     */
    if (!check_pid_in_list(pid, config->pid_list,
                           config->num_pid)) {
        reinject_pipe_t *pipe = container_of(config->exit_pipe,
                                             reinject_pipe_t, node);
        divert_reinject(pipe->handle, ip_data, -1, sin);
        return;
    }

    /*
     * packet dump stage
     */
    if (config->flags & EMULATOR_DUMP_PCAP) {
        divert_dump_pcap(ip_data, config->dump_normal);
    }

    /*
     * packets production stage
     */
    emulator_packet_t *packet = malloc(sizeof(emulator_packet_t));
    MALLOC_AND_COPY(packet->ip_data, ip_data,
                    ntohs(ip_data->ip_len), u_char)
    packet->proc_info = *((proc_info_t *)proc);
    packet->sin = *sin;
    packet->label = NEW_PACKET;
    divert_dump_packet((u_char *)packet->ip_data,
                       &packet->headers, errmsg);
    if (divert_is_inbound(sin, NULL)) {
        packet->direction = DIRECTION_IN;
    } else if (divert_is_outbound(sin)) {
        packet->direction = DIRECTION_OUT;
    } else {
        packet->direction = DIRECTION_UNKNOWN;
    }
    circ_buf_insert(config->event_queue, packet);
}

static int
cmp_time_event(const void *x, const void *y) {
    if (x == NULL) { return 1; }
    if (y == NULL) { return -1; }
    const timeout_event_t *a = x;
    const timeout_event_t *b = y;
    uint64_t val_a = a->tv.tv_sec *
                     (uint64_t)1000000 +
                     a->tv.tv_usec;
    uint64_t val_b = b->tv.tv_sec *
                     (uint64_t)1000000 +
                     b->tv.tv_usec;
    if (val_a > val_b) {
        return -1;
    } else if (val_a < val_b) {
        return 1;
    } else {
        return 0;
    }
}

emulator_config_t *emulator_create_config(divert_t *handle,
                                          size_t buf_size) {
    emulator_config_t *config =
            calloc(sizeof(emulator_config_t), 1);

    config->emulator_thread = (pthread_t)-1;
    config->timer_thread = (pthread_t)-1;

    config->pipe[0] = NULL;
    config->pipe[1] = NULL;
    config->exit_pipe = reinject_pipe_create(handle);
    config->exit_pipe->config = config;

    config->event_queue = circ_buf_create(buf_size);
    config->timer_queue = pqueue_new(cmp_time_event, TIMER_QUEUE_SIZE);

    config->timeout_packet.label = TIMEOUT_EVENT;

    // create emulator thread
    // associated with emulator_config_t
    pthread_create(&config->emulator_thread, NULL,
                   emulator_thread_func, config);

    return config;
}

void emulator_destroy_config(emulator_config_t *config) {
    void *thread_res;
    if (config != NULL) {
        // insert a signal to stop the emulator thread
        emulator_packet_t *ptr = malloc(sizeof(emulator_packet_t));
        memset(ptr, 0, sizeof(emulator_packet_t));
        ptr->label = EVENT_QUIT;
        circ_buf_insert(config->event_queue, ptr);

        // wait emulator thread to exit
        if (config->emulator_thread != (pthread_t)-1) {
            pthread_join(config->emulator_thread, &thread_res);
            config->emulator_thread = (pthread_t)-1;
        }

        // close .pcap files
        if (config->flags & EMULATOR_DUMP_PCAP) {
            CHECK_AND_FREE(config->dump_path)
            fclose(config->dump_normal);
            fclose(config->dump_affected);
            fclose(config->dump_unknown);
        }

        // destroy buffer
        circ_buf_destroy(config->event_queue);
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

packet_size_filter *
emulator_create_size_filter(size_t num, size_t *size, float *rate) {
    packet_size_filter *filter = calloc(1, sizeof(packet_size_filter));
    filter->num = num;
    filter->size = size;
    filter->rate = rate;
    return filter;
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
             cur; cur = cur->next) {
            switch (cur->pipe_type) {
                case PIPE_DROP:
                    break;
                case PIPE_DELAY:
                    break;
                case PIPE_THROTTLE:
                {
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
                case PIPE_DISORDER:
                    break;
                case PIPE_BITERR:
                    break;
                case PIPE_BANDWIDTH:
                    break;
                case PIPE_REINJECT:
                    break;
                case PIPE_DUPLICATE:
                    break;
                default:
                    break;
            }
        }
    }

//    for (int i = 0; i < EMULATOR_EFFECTS; i++) {
//        if (config->flags & flags[i]) {
//            if (config->t[i] == NULL ||
//                config->val[i] == NULL ||
//                config->num[i] == 0) {
//                sprintf(errmsg, "Effect data not set.");
//                return -1;
//            }
//            if (i != OFFSET_THROTTLE &&
//                config->t[i][0] > FLOAT_EPS) {
//                sprintf(errmsg, "Each periodic function should start from time zero.");
//                return -1;
//            }
//            if (i == OFFSET_THROTTLE) {
//
//            }
//        }
//    }
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
    if (config->pipe[direction] == NULL) {
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
                      pipe_node_t *node) {
    // the exit pipe should never be deleted
    if (node == config->exit_pipe) {
        return -1;
    }
    for (int dir = 0; dir < 2; dir++) {
        for (pipe_node_t **ptr = &config->pipe[dir];
             *ptr;) {
            pipe_node_t *entry = *ptr;
            if (entry == node) {
                *ptr = entry->next;
            } else {
                ptr = &entry->next;
            }
        }
    }

    return 0;
}
