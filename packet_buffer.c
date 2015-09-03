#include "packet_buffer.h"
#include <stdlib.h>
#include <pthread.h>

/* Create an empty, bounded, shared FIFO buffer with n slots */
void sbuf_init(packet_buf_t *sp, size_t n) {
    sp->buffer = calloc(n, sizeof(void *));
    /* Buffer holds max of n items */
    sp->n = n;
    /* Empty buffer iff front == rear */
    sp->front = sp->rear = 0;
    /* binary semaphore for locking */
    sp->mutex = malloc(sizeof(pthread_mutex_t));
    pthread_mutex_init(sp->mutex, NULL);
    /* initially, buf has n empty slots */
    sp->slots = sem_open(BUF_SEM_SLOT, O_CREAT, S_IRUSR | S_IWUSR, n);
    /* initially, buf has zero data items */
    sp->items = sem_open(BUF_SEM_ITEM, O_CREAT, S_IRUSR | S_IWUSR, 0);
}

/* Clean up buffer sp */
void sbuf_clean(packet_buf_t *sp) {
    sem_close(sp->items);
    sem_close(sp->slots);
    pthread_mutex_destroy(sp->mutex);
    free(sp->buffer);
}

/* Insert item onto the rear of shared buffer sp */
void sbuf_insert(packet_buf_t *sp, void *item) {
    sem_wait(sp->slots);                          /* Wait for available slot */
    pthread_mutex_lock(sp->mutex);                /* Lock the buffer */
    sp->buffer[(++sp->rear) % (sp->n)] = item;    /* Insert the item */
    pthread_mutex_unlock(sp->mutex);              /* Unlock the buffer */
    sem_post(sp->items);                          /* Announce available item */
}

/* Remove and return the first item from buffer sp */
void *sbuf_remove(packet_buf_t *sp) {
    void *item;
    sem_wait(sp->items);                          /* Wait for available item */
    pthread_mutex_lock(sp->mutex);                /* Lock the buffer */
    item = sp->buffer[(++sp->front) % (sp->n)];   /* Remove the item */
    pthread_mutex_unlock(sp->mutex);              /* Unlock the buffer */
    sem_post(sp->slots);                          /* Announce available slot */
    return item;
}
