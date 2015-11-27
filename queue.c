#include "queue.h"
#include <stdlib.h>
#include <string.h>

queue_t *queue_create(queue_free_function_t free_func) {
    queue_t *q = malloc(sizeof(queue_t));
    memset(q, 0, sizeof(queue_t));
    q->free_data_func = free_func;
    if (pthread_mutex_init(&q->mutex, NULL) ||
        pthread_cond_init(&q->new_item, NULL)) {
        free(q);
        return NULL;
    }
    return q;
}

void queue_destroy(queue_t *q) {
    if (q != NULL) {
        for (queue_node_t *prev = NULL,*cur = q->head;
             cur != NULL;) {
            q->free_data_func(cur->data);
            prev = cur;
            cur = cur->next;
            free(prev);
        }
        free(q);
    }
}

void queue_dump(queue_t *q, FILE *fp) {
    pthread_mutex_lock(&q->mutex);
    queue_node_t *node = q->head;
    while (node != NULL) {
        if (node != q->head) {
            fprintf(fp, " => ");
        }
        fprintf(fp, "%p", node);
        node = node->next;
    }
    fprintf(fp, " => NULL\n");
    pthread_mutex_unlock(&q->mutex);
}

void *queue_head(queue_t *q) {
    void *res = NULL;
    pthread_mutex_lock(&q->mutex);
    if (q->head == NULL || q->tail == NULL) {
        // this is a empty queue
        while (q->size < 1) {
            pthread_cond_wait(&q->new_item, &q->mutex);
        }
    }
    res = q->head->data;
    pthread_mutex_unlock(&q->mutex);
    return res;
}

queue_node_t *queue_enqueue(queue_t *q, void *data) {
    queue_node_t *new_node = malloc(sizeof(queue_node_t));
    new_node->next = NULL;
    new_node->data = data;
    pthread_mutex_lock(&q->mutex);
    // if this queue is empty
    if (q->head == NULL || q->tail == NULL) {
        q->head = new_node;
        q->tail = new_node;
    } else {
        q->tail->next = new_node;
        q->tail = new_node;
    }
    q->size++;
    pthread_cond_signal(&q->new_item);
    pthread_mutex_unlock(&q->mutex);
    return new_node;
}

void *queue_dequeue(queue_t *q) {
    void *result = NULL;
    queue_node_t *ptr = NULL;
    pthread_mutex_lock(&q->mutex);
    if (q->head == NULL || q->tail == NULL) {
        // this is a empty queue
        while (q->size < 1) {
            pthread_cond_wait(&q->new_item, &q->mutex);
        }
    }
    // this queue is not empty
    ptr = q->head;
    result = q->head->data;
    if (q->head == q->tail) {
        // this is a queue with only one element
        q->head = NULL;
        q->tail = NULL;
    } else {
        q->head = q->head->next;
    }
    q->size--;
    pthread_mutex_unlock(&q->mutex);
    free(ptr);
    return result;
}


size_t queue_size(queue_t *q) {
    size_t res = 0;
    pthread_mutex_lock(&q->mutex);
    res = q->size;
    pthread_mutex_unlock(&q->mutex);
    return res;
}

void queue_wait_until(queue_t *q,
                      struct timeval *timeout) {
    pthread_mutex_lock(&q->mutex);
    if (timeout == NULL) {
        pthread_cond_wait(&q->new_item, &q->mutex);
    } else {
        struct timespec ts;
        ts.tv_sec = timeout->tv_sec;
        ts.tv_nsec = timeout->tv_usec * 1000;
        pthread_cond_timedwait(&q->new_item, &q->mutex, &ts);
    }
    pthread_mutex_unlock(&q->mutex);
}
