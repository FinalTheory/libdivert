#include "queue.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

pthread_mutex_t mutex;

queue_t *queue_create() {
    queue_t *queue = malloc(sizeof(queue_t));
    memset(queue, 0, sizeof(queue_t));
    //queue->mutex = malloc(sizeof(pthread_mutex_t));
    //pthread_mutex_init(queue->mutex, NULL);
    pthread_mutex_init(&mutex, NULL);
    return queue;
}

queue_node_t *queue_push(queue_t *queue, void *data) {
    pthread_mutex_lock(&mutex);
    queue_node_t *new_node = malloc(sizeof(queue_node_t));
    new_node->next = NULL;
    new_node->data = data;
    // if this queue is empty
    if (queue->head == NULL || queue->tail == NULL) {
        queue->head = new_node;
        queue->tail = new_node;
    } else {
        queue->tail->next = new_node;
        queue->tail = new_node;
    }
    queue->size++;
    pthread_mutex_unlock(&mutex);
    return new_node;
}

queue_node_t *queue_pop(queue_t *queue) {
    pthread_mutex_lock(&mutex);
    queue_node_t *result = NULL;
    if (queue->head == NULL || queue->tail == NULL) {
        // this is a empty queue
        result = NULL;
    } else {
        // this queue is not empty
        result = queue->head;
        if (queue->head == queue->tail) {
            // this is a queue with only one element
            queue->head = NULL;
            queue->tail = NULL;
        } else {
            queue->head = queue->head->next;
        }
        queue->size--;
    }
    pthread_mutex_unlock(&mutex);
    return result;
}

static inline void queue_delete_node(queue_t *queue,
                                     queue_node_t *prev,
                                     queue_node_t *next) {
    if (prev == NULL && next == NULL) {
        // if there is only one node
        queue->head = queue->tail = NULL;
    } else if (prev == NULL) {
        // if this is the first node
        queue->head = next;
    } else if (next == NULL) {
        // if this is the last node
        queue->tail = prev;
    } else {
        prev->next = next;
    }
    queue->size--;
}

queue_node_t *queue_search_and_drop(queue_t *queue,
                                    void *data, void *args,
                                    queue_compare_function_t cmp,
                                    queue_drop_function_t drop,
                                    queue_free_function_t destroy) {
    pthread_mutex_lock(&mutex);
    queue_node_t *current_node = queue->head;
    queue_node_t *prev_node = NULL;
    queue_node_t *result = NULL;
    while (current_node != NULL) {
        // if found, then remove
        if (cmp(current_node->data, data)) {
            queue_delete_node(queue, prev_node, current_node->next);
            result = current_node;
            break;
        }
        // if current data should be dropped
        if (drop(current_node->data, args)) {
            queue_delete_node(queue, prev_node, current_node->next);
            destroy(current_node->data);
            //free(current_node);
        } else {
            prev_node = current_node;
        }
        current_node = current_node->next;
    }
    pthread_mutex_unlock(&mutex);
    return result;
}
