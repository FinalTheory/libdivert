#include "divert.h"
#include "emulator_callback.h"
#include "emulator_config.h"
#include "dump_packet.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/time.h>
#include <math.h>
#include <divert.h>


static inline double
rand_double() {
    return rand() / (double)RAND_MAX;
}

static double
time_minus(struct timeval *a, struct timeval *b) {
    double delta_secs = a->tv_sec - b->tv_sec;
    double delta_usecs = a->tv_usec - b->tv_usec;
    return delta_secs + delta_usecs / 1000000.;
}

static void time_add(struct timeval *tv, double time) {
    tv->tv_sec += (long)time;
    tv->tv_usec += (long)((time - (long)time) * 1000000.);
    if (tv->tv_usec > 1000000) {
        tv->tv_usec -= 1000000;
        tv->tv_sec += 1;
    }
}

static int check_pid_in_list(pid_t pid, pid_t *pid_list, ssize_t n) {
    if (pid_list == NULL || n == 0) {
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

void *delay_thread_func(void *args) {
    emulator_config_t *config = (emulator_config_t *)args;
    // in thread we need to keep a copy of args
    // used to call the emulator_callback function
    // at the time that packet should be sent
    emulator_config_t local_config;
    memcpy(&local_config, config, sizeof(emulator_config_t));

    while (config->handle->is_looping) {

    }
    // TODO: send all buffered packets
    config->delay_thread = (pthread_t)-1;
    return NULL;
}

void *throttle_thread_func(void *args) {
    emulator_config_t *config = (emulator_config_t *)args;
    emulator_config_t local_config;
    memcpy(&local_config, config, sizeof(emulator_config_t));


    // TODO: send all buffered packets
    config->throttle_thread = (pthread_t)-1;
    return NULL;
}


static double
calc_val_by_time(float *t, float *val,
                 ssize_t n, ssize_t *p,
                 struct timeval *tv_start) {
    // guard here to avoid invalid memory access
    if (t == NULL || val == NULL) {
        return 1.;
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
    (*p)--;
    // linear interpolate
    return val[*p] +
           (t_now - t[*p]) *
           (val[*p + 1] - val[*p]) /
           (t[*p + 1] - t[*p]);
}

static int
calc_rate_by_size(emulator_config_t *config,
                  size_t packet_size) {
    for (int i = 0; i < PACKET_SIZE_LEVELS &&
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
    // for all other packets, apply the effects
    return 1;
}


#define PTHREAD_GUARD(FUNC_FLAG, THREAD_T, THREAD_FUNC) \
    if ((pthread_t)-1 == (THREAD_T) &&                  \
        (config->flags & FUNC_FLAG)) {                  \
        pthread_create(&THREAD_T, NULL,                 \
                        THREAD_FUNC, config);           \
        pthread_detach(THREAD_T);                       \
    }


static void
init_callback_states(emulator_config_t *config) {
    if (!(config->flags & EMULATOE_IS_RUNNING)) {
        config->flags |= EMULATOE_IS_RUNNING;
        srand((unsigned)time(NULL));
        struct timeval tv;
        struct timezone tz;
        gettimeofday(&tv, &tz);
        // copy values to all time stamps
        memcpy(&config->delay_start, &tv, sizeof(tv));
        memcpy(&config->disorder_start, &tv, sizeof(tv));
        memcpy(&config->drop_start, &tv, sizeof(tv));
        memcpy(&config->duplicate_start, &tv, sizeof(tv));
        memcpy(&config->tamper_start, &tv, sizeof(tv));
        memcpy(&config->throttle_start, &tv, sizeof(tv));
    }
}

static void
send_buffered_disordered_packets(emulator_config_t *config) {
    if (config->disorder_queue->size > 0) {
        while (1) {
            disorder_packet_t *ptr = pqueue_head(config->disorder_queue);
            if (ptr == NULL || config->counter < ptr->time_send) {
                break;
            } else {
                ptr = pqueue_dequeue(config->disorder_queue);
                // re-inject the packet
                divert_reinject(config->handle,
                                ptr->packet, -1, ptr->sin);
                CHECK_AND_FREE(ptr->packet)
                CHECK_AND_FREE(ptr->sin)
                CHECK_AND_FREE(ptr)
            }
        }
    }
}


void emulator_callback(void *args, void *proc,
                       struct ip *ip_data, struct sockaddr *sin) {
    emulator_config_t *config = (emulator_config_t *)args;
    config->counter++;

    // first dump info of this packet
    packet_hdrs_t headers;
    divert_dump_packet((u_char *)ip_data, &headers,
                       config->handle->errmsg);

    // ensure this callback is thread safe
    pthread_mutex_lock(config->mutex);

    proc_info_t *proc_info = (proc_info_t *)proc;
    pid_t pid = proc_info->pid != -1 ? proc_info->pid : proc_info->epid;

    init_callback_states(config);

    PTHREAD_GUARD(EMULATOR_DELAY, config->delay_thread, delay_thread_func)
    PTHREAD_GUARD(EMULATOR_THROTTLE, config->throttle_thread, throttle_thread_func)

    // first check if there is still packets in disorder queue
    send_buffered_disordered_packets(config);

    // just re-inject and return if this packet is not from target process
    if (!check_pid_in_list(pid, config->pid_list,
                           config->num_pid)) {
        goto finish;
    }

    // determine if we should apply the effects on this packet
    // if not, just goto finish state
    if (!calc_rate_by_size(config, headers.size_payload)) {
        goto finish;
    }

    // packet drop stage
    if (config->flags & EMULATOR_DROP) {
        if (calc_val_by_time(config->time_drop,
                             config->drop_rate,
                             config->num_drop,
                             &config->t_drop,
                             &config->drop_start) < rand_double()) {
            // just drop this packet
            goto drop;
        }
    }

    // packet delay stage
    if (config->flags & EMULATOR_DELAY) {
    }

    // packet disorder stage
    if (config->flags & EMULATOR_DISORDER) {
        if (calc_val_by_time(config->time_disorder,
                             config->disorder_rate,
                             config->num_disorder,
                             &config->t_disorder,
                             &config->disorder_start) < rand_double()) {
            disorder_packet_t *ptr = malloc(sizeof(disorder_packet_t));
            MALLOC_AND_COPY(ptr->packet, ip_data, ntohs(ip_data->ip_len), u_char);
            MALLOC_AND_COPY(ptr->sin, sin, 1, struct sockaddr);
            ptr->time_send = rand() % MAX_DISORDER_NUM + config->counter;
            pqueue_enqueue(config->disorder_queue, ptr);
        }
    }

    // packet throttle stage
    if (config->flags & EMULATOR_THROTTLE) {
    }

    // packet tamper stage
    if (config->flags & EMULATOR_TAMPER) {
        // only apply for packets with payload
        if (headers.size_payload > 0) {
            if (calc_val_by_time(config->time_tamper,
                                 config->tamper_rate,
                                 config->num_tamper,
                                 &config->t_tamper,
                                 &config->tamper_start)) {
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
                if (ip_data->ip_p == IPPROTO_TCP) {
                } else if (ip_data->ip_p == IPPROTO_UDP) {
                }
                goto finish;
            }
        }
    }

    // packet duplicate stage
    if (config->flags & EMULATOR_DUPLICATE) {
        if (calc_val_by_time(config->time_duplicate,
                             config->duplicate_rate,
                             config->num_duplicate,
                             &config->t_duplicate,
                             &config->duplicate_start) < rand_double()) {
            int times = rand() % MAX_DUPLICATE_NUM + 2;
            for (int i = 0; i < times; i++) {
                // just re-inject the packet is OK
                divert_reinject(config->handle, ip_data, -1, sin);
            }
            goto drop;
        }
    }

    // note that we should always unlock the mutex
    finish:
    divert_reinject(config->handle, ip_data, -1, sin);
    drop:
    pthread_mutex_unlock(config->mutex);
    return;
}
