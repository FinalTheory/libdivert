//
// Created by baidu on 15/9/2.
//

#ifndef DIVERT_QUEUE_H
#define DIVERT_QUEUE_H
#include <stdio.h>
#include <sys/types.h>
#include <pthread.h>

struct queue_node {
    void *data;
    struct queue_node *next;
};

typedef struct queue_node queue_node_t;

typedef struct {
    queue_node_t *head;
    queue_node_t *tail;
    u_int32_t size;
} queue_t;

/*
 * functions provided in this file would be thread safe
 */

/*
 * return 1 if two elements are equal
 */
typedef int (*queue_compare_function_t)(void *, void *);

/*
 * return 1 if a element should be dropped
 */
typedef int (*queue_drop_function_t)(void *, void *);

typedef void (*queue_free_function_t)(void *);

queue_t *queue_create();

queue_node_t *queue_push(queue_t *queue, void *data);

queue_node_t *queue_pop(queue_t *queue);

queue_node_t *queue_search_and_drop(queue_t *queue,
                                    void *data, void *args,
                                    queue_compare_function_t cmp,
                                    queue_drop_function_t drop,
                                    queue_free_function_t destroy);

queue_node_t *queue_search(queue_t *queue, void *data);

void queue_dump(queue_t *queue, FILE *fp);;

#endif //DIVERT_QUEUE_H
