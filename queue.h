#ifndef DIVERT_QUEUE_H
#define DIVERT_QUEUE_H

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>

// return 1 if two elements are equal
typedef int (*queue_compare_function_t)(void *, void *);

// return 1 if a element should be dropped
typedef int (*queue_drop_function_t)(void *, void *);

// free the memory of queue data
typedef void (*queue_free_function_t)(void *);

struct queue_node {
    void *data;
    struct queue_node *next;
};

typedef struct queue_node queue_node_t;

typedef struct {
    queue_node_t *head;
    queue_node_t *tail;
    u_int32_t size;
    queue_free_function_t free_data_func;
    pthread_mutex_t mutex;
    pthread_cond_t new_item;
} queue_t;


queue_t *queue_create(queue_free_function_t free_func);

void queue_destroy(queue_t *q);

void queue_dump(queue_t *q, FILE *fp);

void *queue_head(queue_t *q);

queue_node_t *queue_enqueue(queue_t *q, void *data);

void *queue_dequeue(queue_t *q);

size_t queue_size(queue_t *q);

void queue_wait_until(queue_t *q, struct timeval *timeout);

#endif //DIVERT_QUEUE_H
