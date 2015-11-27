#include "buffer.h"
#include <stdlib.h>


inline static void
free_all_memory(circ_buf_t *sp) {
    free(sp->buffer);
    free(sp);
}

/* Create an empty, bounded, shared FIFO buffer with n slots */
circ_buf_t *circ_buf_create(size_t capacity) {
    circ_buf_t *sp = malloc(sizeof(circ_buf_t));
    sp->buffer = calloc(capacity, sizeof(void *));
    sp->size = 0;
    /* Buffer holds max of n items */
    sp->capacity = capacity;
    /* Empty buffer if front == rear */
    sp->front = sp->rear = 0;
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
    pthread_cond_destroy(&sp->UntilNotEmpty);
    pthread_cond_destroy(&sp->UntilNotFull);
    pthread_mutex_destroy(&sp->mutex);
    free_all_memory(sp);
}

size_t circ_buf_size(circ_buf_t *sp) {
    size_t res;
    pthread_mutex_lock(&sp->mutex);
    res = sp->size;
    pthread_mutex_unlock(&sp->mutex);
    return res;
}

size_t circ_buf_capacity(circ_buf_t *sp) {
    size_t res;
    pthread_mutex_lock(&sp->mutex);
    res = sp->capacity;
    pthread_mutex_unlock(&sp->mutex);
    return res;
}

int circ_buf_is_full(circ_buf_t *sp) {
    int res = 0;
    pthread_mutex_lock(&sp->mutex);
    res = sp->size >= sp->capacity;
    pthread_mutex_unlock(&sp->mutex);
    return res;
}

int circ_buf_is_empty(circ_buf_t *sp) {
    int res = 0;
    pthread_mutex_lock(&sp->mutex);
    res = sp->size < 1;
    pthread_mutex_unlock(&sp->mutex);
    return res;
}

/* Insert item onto the rear of shared buffer sp */
void circ_buf_insert(circ_buf_t *sp, void *item) {
    pthread_mutex_lock(&sp->mutex);                      /* Lock the buffer */
    while (sp->size >= sp->capacity) {
        pthread_cond_wait(&sp->UntilNotFull, &sp->mutex);
    }
    sp->buffer[(++sp->rear) % (sp->capacity)] = item;    /* Insert the item */
    sp->size++;
    pthread_cond_signal(&sp->UntilNotEmpty);
    pthread_mutex_unlock(&sp->mutex);                    /* Unlock the buffer */
}

/* Remove and return the first item from buffer sp */
void *circ_buf_remove(circ_buf_t *sp) {
    void *item;
    pthread_mutex_lock(&sp->mutex);                       /* Lock the buffer */
    while (sp->size < 1) {
        pthread_cond_wait(&sp->UntilNotEmpty, &sp->mutex);
    }
    item = sp->buffer[(++sp->front) % (sp->capacity)];    /* Remove the item */
    sp->size--;
    pthread_cond_signal(&sp->UntilNotFull);
    pthread_mutex_unlock(&sp->mutex);                     /* Unlock the buffer */
    return item;
}

/* Wait until timeout or new item inserted */
void circ_buf_wait_until(circ_buf_t *sp,
                       struct timeval *timeout) {
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
