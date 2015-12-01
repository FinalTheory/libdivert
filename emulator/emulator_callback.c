#include "divert.h"
#include "emulator_callback.h"
#include "emulator_config.h"
#include "dump_packet.h"
#include <stdlib.h>
#include <string.h>
#include <divert.h>


static inline double
rand_double() {
    return rand() / (double)RAND_MAX;
}

inline static int
time_greater_than(struct timeval *a, struct timeval *b) {
    if (a->tv_sec != b->tv_sec) {
        return a->tv_sec > b->tv_sec;
    } else {
        return a->tv_usec > b->tv_usec;
    }
}

inline static double
time_minus(struct timeval *a, struct timeval *b) {
    double delta_secs = a->tv_sec - b->tv_sec;
    double delta_usecs = a->tv_usec - b->tv_usec;
    return delta_secs + delta_usecs / 1000000.;
}

static void
time_add(struct timeval *tv, double time) {
    tv->tv_sec += (long)time;
    tv->tv_usec += (long)((time - (long)time) * 1000000.);
    if (tv->tv_usec > 1000000) {
        tv->tv_usec -= 1000000;
        tv->tv_sec += 1;
    }
}

static int
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

static int
check_direction(u_char *arr, int offset, int direction) {
    if (arr[offset] == DIRECTION_BOTH ||
        arr[offset] == direction) {
        return 1;
    }
    return 0;
}

static void *
delay_thread_func(void *args) {
    emulator_config_t *config = args;

    struct timeval time_now;
    struct timezone tz;
    delay_packet_t *ptr = NULL;

    while (1) {
        // try to send all timeout packets
        gettimeofday(&time_now, &tz);
        while (1) {
            ptr = pqueue_head(config->delay_queue);
            if (ptr == NULL) { goto finish; }
            if (time_greater_than(&ptr->time_send, &time_now)) { break; }
            ptr = pqueue_dequeue(config->delay_queue);
            // TODO: remove this line
            printf("sendtime: %ld:%d\n", ptr->time_send.tv_sec, ptr->time_send.tv_usec);
            ptr->packet->label = STAGE_THROTTLE;
            circ_buf_insert(config->packet_queue, ptr->packet);
            CHECK_AND_FREE(ptr)
        }

        // then wait until next packet could be sent
        if (pqueue_size(config->delay_queue) > 0) {
            ptr = pqueue_head(config->delay_queue);
            if (time_greater_than(&ptr->time_send, &time_now)) {
                pqueue_wait_until(config->delay_queue, &ptr->time_send);
            }
        }
    }
    finish:
    return NULL;
}

static void *
throttle_thread_func(void *args) {
    emulator_config_t *config = args;
    struct timeval time_send, time_now;
    struct timezone tz;

    while (1) {
        // read a packet to determine how long to sleep
        throttle_packet_t *pkt = queue_head(config->throttle_queue);
        if (pkt == NULL) { break; }
        time_send = pkt->time_send;

        // sleep until time to send all buffered packets
        for (gettimeofday(&time_now, &tz);
             time_greater_than(&time_send, &time_now);
             gettimeofday(&time_now, &tz)) {
            double time_delta = time_minus(&time_send, &time_now);
            printf("sleep %f ms\n", time_delta);
            unsigned secs = (unsigned)time_delta;
            useconds_t usecs = (useconds_t)((time_delta - (double)secs) * 1000000.);
            sleep((secs));
            usleep(usecs);
        }

        gettimeofday(&time_now, &tz);
        // send out all timeout packets
        while (queue_size(config->throttle_queue) > 0) {
            pkt = queue_head(config->throttle_queue);
            if (pkt == NULL) { break; }
            if (time_greater_than(&time_now, &pkt->time_send)) {
                pkt = queue_dequeue(config->throttle_queue);
                pkt->packet->label = STAGE_DISORDER;
                circ_buf_insert(config->packet_queue, pkt->packet);
                CHECK_AND_FREE(pkt)
            } else {
                break;
            }
        }
    }
    return NULL;
}

static double
calc_val_by_time(emulator_config_t *config, int offset) {
    float *t = config->t[offset];
    float *val = config->val[offset];
    ssize_t n = config->num[offset];
    ssize_t *p = &config->idx[offset];
    struct timeval *tv_start = &config->tv[offset];

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

static int
calc_rate_by_size(emulator_config_t *config,
                  size_t packet_size) {
    if (config->packet_size == NULL ||
        config->packet_rate == NULL) {
        return 1;
    }
    for (int i = 0; i < config->num_size &&
                    config->packet_size[i] != -1; i++) {
        size_t prev_size = (i == 0 ? 0 : config->packet_size[i - 1]);
        if (prev_size <= packet_size &&
            packet_size < config->packet_size[i]) {
            double rate = config->packet_rate[i];
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

static double
calc_do_throttle(emulator_config_t *config, int offset) {
    float *t1 = config->t[offset];
    float *t2 = config->val[offset];
    ssize_t n = config->num[offset];
    ssize_t *p = &config->idx[offset];
    struct timeval *tv_start = &config->tv[offset];

    // guard here to avoid invalid memory access
    if (t1 == NULL || t2 == NULL) {
        return -1.;
    }

    struct timeval tv;
    struct timezone tz;
    double ret_val = -1.;
    gettimeofday(&tv, &tz);

    double end_time = t2[n - 1];
    double t_now = time_minus(&tv, tv_start);
    if (t_now >= end_time) {
        long k = (long)(t_now / end_time);
        // then reset it to beginning
        time_add(tv_start, end_time * k);
        t_now -= end_time * k;
        *p = 0;
    }

    while (t1[*p] <= t_now) {
        (*p)++;
    }
    if (*p > 0) { (*p)--; }

    if (t1[*p] <= t_now &&
        t_now <= t2[*p]) {
        ret_val = t2[*p];
    }

    return ret_val;
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
        for (int i = 0; i < EMULATOR_EFFECTS; i++) {
            config->tv[i] = tv;
        }
    }
}

static void
clear_delay_queue(emulator_config_t *config) {
    emulator_packet_t *packet;
    while (pqueue_size(config->delay_queue) > 0) {
        delay_packet_t *ptr = pqueue_dequeue(config->delay_queue);
        if (ptr == NULL) { continue; }
        packet = ptr->packet;
        divert_reinject(config->handle, packet->packet, -1, &packet->sin);
        CHECK_AND_FREE(ptr)
        CHECK_AND_FREE(packet->packet)
        CHECK_AND_FREE(packet)
    }
}

static void
clear_disorder_queue(emulator_config_t *config) {
    emulator_packet_t *packet;
    while (pqueue_size(config->disorder_queue) > 0) {
        disorder_packet_t *ptr = pqueue_dequeue(config->disorder_queue);
        if (ptr == NULL) { continue; }
        packet = ptr->packet;
        divert_reinject(config->handle, packet->packet, -1, &packet->sin);
        CHECK_AND_FREE(ptr)
        CHECK_AND_FREE(packet->packet)
        CHECK_AND_FREE(packet)
    }
}

static void
clear_packet_queue(emulator_config_t *config) {
    emulator_packet_t *packet;
    while (circ_buf_size(config->packet_queue) > 0) {
        packet = circ_buf_remove(config->packet_queue);
        if (packet == NULL) { continue; }
        divert_reinject(config->handle, packet->packet, -1, &packet->sin);
        CHECK_AND_FREE(packet->packet)
        CHECK_AND_FREE(packet)
    }
}

static void
clear_throttle_queue(emulator_config_t *config) {
    emulator_packet_t *packet;
    while (queue_size(config->throttle_queue) > 0) {
        delay_packet_t *ptr = queue_dequeue(config->throttle_queue);
        if (ptr == NULL) { continue; }
        packet = ptr->packet;
        divert_reinject(config->handle, packet->packet, -1, &packet->sin);
        CHECK_AND_FREE(ptr)
        CHECK_AND_FREE(packet->packet)
        CHECK_AND_FREE(packet)
    }
}

void *emulator_thread_func(void *args) {
    /*
     * initialize local variables
     * these are of course thread-safe
     */
    void *thread_res;
    char errmsg[DIVERT_ERRBUF_SIZE];
    packet_hdrs_t headers;
    emulator_config_t *config = args;

    /*
     * config && thread init stage
     */
    init_callback_runtime_states(config);
    pthread_create(&config->delay_thread, NULL,
                   delay_thread_func, config);
    pthread_create(&config->throttle_thread, NULL,
                   throttle_thread_func, config);

    while (1) {
        emulator_packet_t *packet = circ_buf_remove(config->packet_queue);
        if (packet->label == QUIT_THREAD) { break; }
        /*
         * extract packet information
         */
        struct sockaddr *sin = &packet->sin;
        struct ip *ip_data = packet->packet;
        // dump info of this packet
        divert_dump_packet((u_char *)ip_data, &headers, errmsg);

        switch (packet->label) {
            case NEW_PACKET:
                /*
                 * this is a dummy entry point
                 * for all newly arrived packets
                 */
            case STAGE_CHECK_SIZE:
                /*
                 * determine if we should apply the effects on this packet
                 * if not, just deliver it to application
                 */
                if (!calc_rate_by_size(config, headers.size_payload)) {
                    goto deliver;
                }
            case STAGE_DROP:
                /*
                 * packet drop stage
                 */
                do {
                    if (!(config->flags & EMULATOR_DROP)) { break; }
                    if (!check_direction(config->direction_flags,
                                         OFFSET_DROP, packet->direction)) { break; }
                    if (calc_val_by_time(config,
                                         OFFSET_DROP) < rand_double()) { break; }
                    // just drop this packet, skip following stage
                    // as if we did not receive this packet
                    goto discard;
                } while (0);
            case STAGE_DELAY:
                /*
                 * packet delay stage
                 */
                do {
                    if (!(config->flags & EMULATOR_DELAY)) { break; }
                    if (!check_direction(config->direction_flags,
                                         OFFSET_DELAY, packet->direction)) { break; }
                    if (pqueue_is_full(config->delay_queue)) { break; }
                    // break if the delay time is too short
                    double delay_time = calc_val_by_time(config, OFFSET_DELAY);
                    if (delay_time < FLOAT_EPS) { break; }

                    // calculate send time
                    struct timeval tv;
                    struct timezone tz;
                    gettimeofday(&tv, &tz);
                    time_add(&tv, delay_time);
                    // TODO: remove this
                    // fprintf(stderr, "Packet delay %f ms\n", delay_time * 1000);
                    delay_packet_t *ptr = malloc(sizeof(delay_packet_t));
                    ptr->packet = packet;
                    ptr->time_send = tv;

                    // insert packet into delay queue and finish processing
                    pqueue_enqueue(config->delay_queue, ptr);
                    goto hijacked;
                } while (0);

            case STAGE_THROTTLE:
                /*
                 * packet throttle stage
                 */
                do {
                    double delay_time;
                    if (!(config->flags & EMULATOR_THROTTLE)) { break; }
                    if (!check_direction(config->direction_flags,
                                         OFFSET_THROTTLE, packet->direction)) { break; }
                    if ((delay_time = calc_do_throttle(config,
                                                       OFFSET_THROTTLE)) < 0.) { break; }

                    throttle_packet_t *ptr = malloc(sizeof(throttle_packet_t));
                    ptr->packet = packet;
                    ptr->time_send = config->tv[OFFSET_THROTTLE];
                    time_add(&ptr->time_send, delay_time);

                    queue_enqueue(config->throttle_queue, ptr);
                    goto hijacked;
                } while (0);

            case STAGE_DISORDER:
                /*
                 * packet disorder stage
                 */
                do {
                    if (!(config->flags & EMULATOR_DISORDER)) { break; }
                    if (!check_direction(config->direction_flags,
                                         OFFSET_DISORDER, packet->direction)) { break; }
                    if (calc_val_by_time(config, OFFSET_DISORDER) < rand_double()) {
                        break;
                    }
                    // check if there is empty slot in queue
                    if (pqueue_is_full(config->disorder_queue)) { break; }
                    if (packet->direction == DIRECTION_UNKNOWN) { break; }

                    disorder_packet_t *ptr =
                            malloc(sizeof(disorder_packet_t));
                    ptr->packet = packet;
                    ptr->time_send = rand() % config->num_disorder +
                                     config->counters[packet->direction];

                    // insert packet into disorder queue and finish processing
                    pqueue_enqueue(config->disorder_queue, ptr);
                    goto hijacked;
                } while (0);
            case STAGE_TAMPER:
                /*
                 * packet tamper stage
                 */
                do {
                    if (!(config->flags & EMULATOR_TAMPER)) { break; }
                    if (!check_direction(config->direction_flags,
                                         OFFSET_TAMPER, packet->direction)) { break; }
                    // only apply for packets with payload
                    if (headers.size_payload <= 0) { break; }
                    if (calc_val_by_time(config, OFFSET_TAMPER) < rand_double()) { break; }
                    for (int i = 0, cnt = 0;
                         i < headers.size_payload &&
                         cnt < MAX_TAMPER_BYTES; i++) {
                        if (rand() % TAMPER_CONTROL == 0) {
                            headers.payload[i] = (u_char)(rand() % 256);
                            cnt++;
                        }
                    }
                    // if this is a TCP packet
                    // we should re-calculate the checksum
                    // TODO: re-checksum
                    if (config->flags & EMULATOR_RECHECKSUM) {
                        if (ip_data->ip_p == IPPROTO_TCP) {
                        } else if (ip_data->ip_p == IPPROTO_UDP) {
                        }
                    }
                } while (0);
            case STAGE_DUPLICATE:
                /*
     * packet duplicate stage
     */
                do {
                    if (!(config->flags & EMULATOR_DUPLICATE)) { break; }
                    if (!check_direction(config->direction_flags,
                                         OFFSET_DUPLICATE, packet->direction)) { break; }
                    if (calc_val_by_time(config, OFFSET_DUPLICATE) < rand_double()) {
                        break;
                    }
                    int times = rand() % config->num_dup + 1;
                    for (int i = 0; i < times; i++) {
                        // just re-inject the packet is OK
                        divert_reinject(config->handle, ip_data, -1, sin);
                    }
                    goto deliver;
                } while (0);
            default:
                break;
        }

        /*
         * deliver state
         * send this packet to application
         * we should do some complex processing
         * 1. re-inject this packet
         * 2. dump packets into .pcap file
         * 3. move disordered packets into packet queue
         */
        deliver:
        // first re-inject the packet
        divert_reinject(config->handle, ip_data, -1, sin);
        // then dump affected packets
        if (config->flags & EMULATOR_DUMP_PCAP) {
            divert_dump_pcap(ip_data, config->dump_affected);
        }
        // calculate a predicted time stamp
        // which means that if we put the disordered packet into queue immediately
        // the largest timestamp at which it would be processed again
        config->counters[packet->direction]++;
        uint64_t predict_ts = config->counters[packet->direction] +
                              circ_buf_size(config->packet_queue);
        // finally move disorder packets into packet queue
        while (pqueue_size(config->disorder_queue) > 0) {
            disorder_packet_t *ptr = pqueue_head(config->disorder_queue);
            if (ptr == NULL || ptr->time_send > predict_ts) {
                break;
            }
            ptr = pqueue_dequeue(config->disorder_queue);
            ptr->packet->label = STAGE_TAMPER;
            circ_buf_insert(config->packet_queue, ptr->packet);
            CHECK_AND_FREE(ptr)
        }
        goto free_mem;

        /*
         * discard state:
         * do not deliver this packet
         * so just free the memory
         */
        discard:
        goto free_mem;

        free_mem:
        CHECK_AND_FREE(packet->packet)
        CHECK_AND_FREE(packet)

        hijacked:
        continue;
    }
    pqueue_enqueue(config->delay_queue, NULL);
    queue_enqueue(config->throttle_queue, NULL);
    if (config->delay_thread != (pthread_t)-1) {
        pthread_join(config->delay_thread, &thread_res);
        config->delay_thread = (pthread_t)-1;
    }
    if (config->throttle_thread != (pthread_t)-1) {
        pthread_join(config->throttle_thread, &thread_res);
        config->throttle_thread = (pthread_t)-1;
    }
    clear_delay_queue(config);
    clear_throttle_queue(config);
    clear_disorder_queue(config);
    clear_packet_queue(config);
    config->flags &= ~((uint64_t)EMULATOR_IS_RUNNING);
    return NULL;
}

void emulator_callback(void *args, void *proc,
                       struct ip *ip_data, struct sockaddr *sin) {
    // Note: this function won't be reentry
    emulator_config_t *config = args;
    proc_info_t *proc_info = proc;
    pid_t pid = proc_info->pid != -1 ?
                proc_info->pid : proc_info->epid;

    // TODO: remove this
//    char errmsg[256];
//    packet_hdrs_t headers;
//    divert_dump_packet((u_char *)ip_data, &headers, errmsg);
//    if (headers.size_payload) {
//        for (int i = 0; i < headers.size_payload; i++) {
//            putchar(headers.payload[i]);
//        }
//        puts("");
//    }

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
        divert_reinject(config->handle, ip_data, -1, sin);
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
    MALLOC_AND_COPY(packet->packet, ip_data,
                    ntohs(ip_data->ip_len), u_char)
    packet->proc_info = *((proc_info_t *)proc);
    packet->sin = *sin;
    packet->label = NEW_PACKET;
    if (divert_is_inbound(sin, NULL)) {
        packet->direction = DIRECTION_IN;
    } else if (divert_is_outbound(sin)) {
        packet->direction = DIRECTION_OUT;
    } else {
        packet->direction = DIRECTION_UNKNOWN;
    }
    circ_buf_insert(config->packet_queue, packet);
}
