#include "buffer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>


/* Create an empty, bounded, shared FIFO buffer with n slots */
int divert_buf_init(packet_buf_t *sp, size_t n, char *errmsg) {
    sp->buffer = calloc(n, sizeof(void *));
    sp->size = 0;
    /* Buffer holds max of n items */
    sp->n = n;
    /* Empty buffer if front == rear */
    sp->front = sp->rear = 0;
    /* binary semaphore for locking */
    sp->mutex = malloc(sizeof(pthread_mutex_t));
    /* condition variables for notify */
    sp->UntilNotEmpty = malloc(sizeof(pthread_cond_t));
    sp->UntilNotFull = malloc(sizeof(pthread_cond_t));

    if (pthread_cond_init(sp->UntilNotEmpty, NULL) ||
        pthread_cond_init(sp->UntilNotFull, NULL) ||
        pthread_mutex_init(sp->mutex, NULL)) {
        sprintf(errmsg, "Couldn't init mutex or condition variables.");
        return -1;
    } else {
        return 0;
    }
}

/* Clean up buffer sp */
void divert_buf_clean(packet_buf_t *sp) {
    pthread_cond_destroy(sp->UntilNotEmpty);
    pthread_cond_destroy(sp->UntilNotFull);
    pthread_mutex_destroy(sp->mutex);
    free(sp->buffer);
}

/* Insert item onto the rear of shared buffer sp */
void divert_buf_insert(packet_buf_t *sp, void *item) {
    pthread_mutex_lock(sp->mutex);                /* Lock the buffer */
    while (sp->size >= sp->n) {
        pthread_cond_wait(sp->UntilNotFull, sp->mutex);
    }
    sp->buffer[(++sp->rear) % (sp->n)] = item;    /* Insert the item */
    sp->size++;
    pthread_cond_signal(sp->UntilNotEmpty);
    pthread_mutex_unlock(sp->mutex);              /* Unlock the buffer */
}

/* Remove and return the first item from buffer sp */
void *divert_buf_remove(packet_buf_t *sp) {
    void *item;
    pthread_mutex_lock(sp->mutex);                /* Lock the buffer */
    while (sp->size < 1) {
        pthread_cond_wait(sp->UntilNotEmpty, sp->mutex);
    }
    item = sp->buffer[(++sp->front) % (sp->n)];   /* Remove the item */
    sp->size--;
    pthread_cond_signal(sp->UntilNotFull);
    pthread_mutex_unlock(sp->mutex);              /* Unlock the buffer */
    return item;
}
