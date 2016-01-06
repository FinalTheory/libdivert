#include "circ_buf.h"
#include <stdlib.h>

// TODO: 给这堆东西增加无锁版本!!!


inline static void
free_all_memory(circ_buf_t *sp) {
    free(sp->buffer);
    free(sp);
}

/* Create an empty, bounded, shared FIFO buffer with n slots */
circ_buf_t *circ_buf_create(size_t capacity, int thread_safe) {
    circ_buf_t *sp = malloc(sizeof(circ_buf_t));
    sp->buffer = calloc(capacity, sizeof(void *));
    sp->size = 0;
    /* Buffer holds max of n items */
    sp->capacity = capacity;
    /* Empty buffer if front == rear */
    sp->front = sp->rear = 0;
    /* Decide if this should be thread safe */
    sp->thread_safe = thread_safe;
    if (!thread_safe) {
        return sp;
    }
    /* Initialize condition variables and mutex */
    if (pthread_cond_init(&sp->UntilNotEmpty, NULL) ||
        pthread_cond_init(&sp->UntilNotFull, NULL) ||
        pthread_mutex_init(&sp->mutex, NULL)) {
        free_all_memory(sp);
        return NULL;
    } else {
        return sp;
    }
}

/* Clean up buffer sp */
void circ_buf_destroy(circ_buf_t *sp) {
    if (sp == NULL) return;
    if (sp->thread_safe) {
        pthread_cond_destroy(&sp->UntilNotEmpty);
        pthread_cond_destroy(&sp->UntilNotFull);
        pthread_mutex_destroy(&sp->mutex);
    }
    free_all_memory(sp);
}

size_t circ_buf_size(circ_buf_t *sp) {
    size_t res;
    if (sp->thread_safe) {
        pthread_mutex_lock(&sp->mutex);
    }
    res = sp->size;
    if (sp->thread_safe) {
        pthread_mutex_unlock(&sp->mutex);
    }
    return res;
}

size_t circ_buf_capacity(circ_buf_t *sp) {
    size_t res;
    if (sp->thread_safe) {
        pthread_mutex_lock(&sp->mutex);
    }
    res = sp->capacity;
    if (sp->thread_safe) {
        pthread_mutex_unlock(&sp->mutex);
    }
    return res;
}

int circ_buf_is_full(circ_buf_t *sp) {
    int res = 0;
    if (sp->thread_safe) {
        pthread_mutex_lock(&sp->mutex);
    }
    res = sp->size >= sp->capacity;
    if (sp->thread_safe) {
        pthread_mutex_unlock(&sp->mutex);
    }
    return res;
}

int circ_buf_is_empty(circ_buf_t *sp) {
    int res = 0;
    if (sp->thread_safe) {
        pthread_mutex_lock(&sp->mutex);
    }
    res = sp->size < 1;
    if (sp->thread_safe) {
        pthread_mutex_unlock(&sp->mutex);
    }
    return res;
}

/* Insert item onto the rear of shared buffer sp */
void circ_buf_insert(circ_buf_t *sp, void *item) {
    if (sp->thread_safe) {
        pthread_mutex_lock(&sp->mutex);                      /* Lock the buffer */
        while (sp->size >= sp->capacity) {
            pthread_cond_wait(&sp->UntilNotFull, &sp->mutex);
        }
    }
    if (sp->size >= sp->capacity) {
        return;
    }
    sp->buffer[(++sp->rear) % (sp->capacity)] = item;        /* Insert the item */
    sp->size++;
    if (sp->thread_safe) {
        pthread_cond_signal(&sp->UntilNotEmpty);
        pthread_mutex_unlock(&sp->mutex);                    /* Unlock the buffer */
    }

}

/* Only return the first item from buffer sp */
void *circ_buf_head(circ_buf_t *sp) {
    void *item;
    if (sp->thread_safe) {
        pthread_mutex_lock(&sp->mutex);                       /* Lock the buffer */
        while (sp->size < 1) {
            pthread_cond_wait(&sp->UntilNotEmpty, &sp->mutex);
        }
    }
    if (sp->size == 0) {
        return NULL;
    }
    item = sp->buffer[(sp->front + 1) % (sp->capacity)];      /* Get the item */
    if (sp->thread_safe) {
        pthread_mutex_unlock(&sp->mutex);                     /* Unlock the buffer */
    }
    return item;
}

/* Remove and return the first item from buffer sp */
void *circ_buf_remove(circ_buf_t *sp) {
    void *item;
    if (sp->thread_safe) {
        pthread_mutex_lock(&sp->mutex);                       /* Lock the buffer */
        while (sp->size < 1) {
            pthread_cond_wait(&sp->UntilNotEmpty, &sp->mutex);
        }
    }
    if (sp->size == 0) {
        return NULL;
    }
    item = sp->buffer[(++sp->front) % (sp->capacity)];        /* Remove the item */
    sp->size--;
    if (sp->thread_safe) {
        pthread_cond_signal(&sp->UntilNotFull);
        pthread_mutex_unlock(&sp->mutex);                     /* Unlock the buffer */
    }
    return item;
}

/* Wait until timeout or new item inserted */
void circ_buf_wait_until(circ_buf_t *sp,
                       struct timeval *timeout) {
    if (!sp->thread_safe) {
        return;
    }
    pthread_mutex_lock(&sp->mutex);
    if (timeout == NULL) {
        pthread_cond_wait(&sp->UntilNotEmpty, &sp->mutex);
    } else {
        struct timespec ts;
        ts.tv_sec = timeout->tv_sec;
        ts.tv_nsec = timeout->tv_usec * 1000;
        pthread_cond_timedwait(&sp->UntilNotEmpty, &sp->mutex, &ts);
    }
    pthread_mutex_unlock(&sp->mutex);
}