#include "pqueue.h"
#include <stdlib.h>
#include <stdio.h>

/* Util macros */
#define LEFT(x) (2 * (x) + 1)
#define RIGHT(x) (2 * (x) + 2)
#define PARENT(x) ((x-1) / 2)

void pqueue_heapify(pqueue *q, size_t idx);

/**
* Allocates memory for a new Priority Queue structure .

* 'cmp' function:
*   returns 0 if d1 and d2 have the same priorities
*   returns [negative value] if d1 have a smaller priority than d2
*   returns [positive value] if d1 have a greater priority than d2
*/
pqueue *pqueue_new(int (*cmp)(const void *d1, const void *d2),
                   size_t capacity) {
    pqueue *res = NULL;
    NP_CHECK(cmp);
    res = malloc(sizeof(*res));
    NP_CHECK(res);
    res->cmp = cmp;
    /* The inner representation of data inside the queue is an array of void* */
    res->data = malloc(capacity * sizeof(*(res->data)));
    NP_CHECK(res->data);
    res->size = 0;
    res->capacity = capacity;

    if (pthread_cond_init(&res->UntilNotEmpty, NULL) ||
        pthread_cond_init(&res->UntilNotFull, NULL) ||
        pthread_mutex_init(&res->mutex, NULL)) {
        free(res->data);
        free(res);
        return NULL;
    }
    return (res);
}

/**
* De-allocates memory for a given Priority Queue structure .
*/
void pqueue_destroy(pqueue *q) {
    if (NULL == q) {
        DEBUG("Priority Queue is already NULL. Nothing to free.");
        return;
    } else {
        free(q->data);
        free(q);
    }
}

/*
 * Wait until a new element is inserted
 */
void pqueue_wait_until(pqueue *q,
                       struct timeval *timeout) {
    pthread_mutex_lock(&q->mutex);
    if (timeout == NULL) {
        pthread_cond_wait(&q->UntilNotEmpty, &q->mutex);
    } else {
        struct timespec ts;
        ts.tv_sec = timeout->tv_sec;
        ts.tv_nsec = timeout->tv_usec * 1000;
        pthread_cond_timedwait(&q->UntilNotEmpty, &q->mutex, &ts);
    }
    pthread_mutex_unlock(&q->mutex);
}


/**
* Adds a new element to the Priority Queue .
*/
void pqueue_enqueue(pqueue *q, const void *data) {
    size_t i;
    void *tmp = NULL;
    NP_CHECK(q);
    pthread_mutex_lock(&q->mutex);
    while (q->size >= q->capacity) {
        pthread_cond_wait(&q->UntilNotFull, &q->mutex);
    }
    /* Adds element last */
    q->data[q->size] = (void *)data;
    i = q->size;
    q->size++;
    /* The new element is swapped with its parent as long as its
    precedence is higher */
    while (i > 0 && q->cmp(q->data[i], q->data[PARENT(i)]) > 0) {
        tmp = q->data[i];
        q->data[i] = q->data[PARENT(i)];
        q->data[PARENT(i)] = tmp;
        i = PARENT(i);
    }
    pthread_cond_signal(&q->UntilNotEmpty);
    pthread_mutex_unlock(&q->mutex);
}

/**
* Returns the element with the biggest priority from the queue .
*/
void *pqueue_head(pqueue *q) {
    void *res = NULL;
    pthread_mutex_lock(&q->mutex);
    while (q->size < 1) {
        pthread_cond_wait(&q->UntilNotEmpty, &q->mutex);
    }
    res = (q->data[0]);
    pthread_mutex_unlock(&q->mutex);
    return res;
}

/**
* Returns size and capacity of a queue
*/
size_t pqueue_size(pqueue *q) {
    size_t res = 0;
    pthread_mutex_lock(&q->mutex);
    res = q->size;
    pthread_mutex_unlock(&q->mutex);
    return res;
}

size_t pqueue_capacity(pqueue *q) {
    size_t res = 0;
    pthread_mutex_lock(&q->mutex);
    res = q->capacity;
    pthread_mutex_unlock(&q->mutex);
    return res;
}

int pqueue_is_full(pqueue *q) {
    int res = 0;
    pthread_mutex_lock(&q->mutex);
    res = q->size >= q->capacity;
    pthread_mutex_unlock(&q->mutex);
    return res;
}

int pqueue_is_empty(pqueue *q) {
    int res = 0;
    pthread_mutex_lock(&q->mutex);
    res = q->size < 1;
    pthread_mutex_unlock(&q->mutex);
    return res;
}

/**
* Returns the element with the biggest priority from the queue .
*/
void *pqueue_dequeue(pqueue *q) {
    void *data = NULL;
    NP_CHECK(q);
    pthread_mutex_lock(&q->mutex);
    while (q->size < 1) {
        pthread_cond_wait(&q->UntilNotEmpty, &q->mutex);
    }
    data = q->data[0];
    q->data[0] = q->data[q->size - 1];
    q->size--;
    /* Restore heap property */
    pqueue_heapify(q, 0);
    pthread_cond_signal(&q->UntilNotFull);
    pthread_mutex_unlock(&q->mutex);
    return (data);
}

/**
* Turn an "almost-heap" into a heap .
*/
void pqueue_heapify(pqueue *q, size_t idx) {
    /* left index, right index, largest */
    void *tmp = NULL;
    size_t l_idx, r_idx, lrg_idx;
    NP_CHECK(q);

    l_idx = LEFT(idx);
    r_idx = RIGHT(idx);

    /* Left child exists, compare left child with its parent */
    if (l_idx < q->size && q->cmp(q->data[l_idx], q->data[idx]) > 0) {
        lrg_idx = l_idx;
    } else {
        lrg_idx = idx;
    }

    /* Right child exists, compare right child with the largest element */
    if (r_idx < q->size && q->cmp(q->data[r_idx], q->data[lrg_idx]) > 0) {
        lrg_idx = r_idx;
    }

    /* At this point largest element was determined */
    if (lrg_idx != idx) {
        /* Swap between the index at the largest element */
        tmp = q->data[lrg_idx];
        q->data[lrg_idx] = q->data[idx];
        q->data[idx] = tmp;
        /* Heapify again */
        pqueue_heapify(q, lrg_idx);
    }
}
