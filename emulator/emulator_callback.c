#include "divert.h"
#include "emulator_callback.h"
#include "emulator_config.h"
#include "dump_packet.h"
#include <stdlib.h>
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
        return 0;
    }
    for (int i = 0; i < n; i++) {
        if (pid_list[i] == pid) {
            return 1;
        }
    }
    return 0;
}

void *delay_thread_func(void *args) {
    // in thread we need to keep a copy of args
    // used to call the emulator_callback function
    // at the time that packet should be sent

    return NULL;
}

void *throttle_thread_func(void *args) {

    return NULL;
}

void *disorder_thread_func(void *args) {

    return NULL;
}

#define PTHREAD_GUARD(FUNC_FLAG, THREAD_T, THREAD_FUNC) \
    if ((pthread_t)-1 == (THREAD_T) &&                  \
        (config->flags & FUNC_FLAG)) {                  \
        pthread_create(&THREAD_T, NULL,                 \
                        THREAD_FUNC, config);           \
        pthread_detach(THREAD_T);                       \
    }


static double
calc_val_by_time(float *t, float *val,
                 ssize_t n, ssize_t *p,
                 struct timeval *tv_start) {
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);

    // get end time of this function
    double end_time = t[n - 1];
    // get current of this period
    double t_now = time_minus(&tv, tv_start);
    // if is out if this period
    if (t_now >= end_time) {
        // then reset it to beginning
        time_add(tv_start, end_time);
        t_now -= end_time;
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
        size_t prev_size = i == 0 ? 0 : config->packet_size[i - 1];
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
    return 1;
}


void emulator_callback(void *args, void *proc,
                       struct ip *ip_data, struct sockaddr *sin) {
    emulator_config_t *config = (emulator_config_t *)args;

    // first dump info of this packet
    packet_hdrs_t headers;
    divert_dump_packet((u_char *)ip_data, &headers,
                       config->handle->errmsg);

    // ensure this callback is thread safe
    pthread_mutex_lock(config->mutex);

    proc_info_t *proc_info = (proc_info_t *)proc;
    pid_t pid = proc_info->pid != -1 ? proc_info->pid : proc_info->epid;

    // TODO: 设置初始时间和随机数种子

    PTHREAD_GUARD(EMULATOR_DELAY, config->delay_thread, delay_thread_func)
    PTHREAD_GUARD(EMULATOR_THROTTLE, config->throttle_thread, throttle_thread_func)

    // just re-inject and return if this packet is not from target process
    if ((config->flags & EMULATOR_BY_PID) &&
        !check_pid_in_list(pid, config->pid_list, config->num_pid)) {
        divert_reinject(config->handle, ip_data, -1, sin);
        return;
    }

    // packet drop stage
    if (config->flags & EMULATOR_DROP) {
        if (calc_rate_by_size(config, headers.size_payload)) {
            if (calc_val_by_time(config->time_drop,
                                 config->drop_rate,
                                 config->num_drop,
                                 &config->t_drop,
                                 &config->drop_start)) {
                // do nothing, so just drop this packet
                return;
            }
        }
    }

    // packet delay stage
    if (config->flags & EMULATOR_DELAY) {

    }

    // packet disorder stage
    if (config->flags & EMULATOR_DISORDER) {

    }

    // packet throttle stage
    if (config->flags & EMULATOR_THROTTLE) {

    }

    if (config->flags & EMULATOR_TAMPER) {

    }

    if (config->flags & EMULATOR_DUPLICATE) {

    }

    pthread_mutex_unlock(config->mutex);
}
