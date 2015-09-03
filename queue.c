//
// Created by baidu on 15/9/2.
//

#include "queue.h"
#include <stdlib.h>
#include <string.h>

queue_t *queue_create() {
    queue_t *queue = malloc(sizeof(queue_t));
    memset(queue, 0, sizeof(queue_t));
    return queue;
}

queue_node_t *queue_push(queue_t *queue, void *data) {
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
    return new_node;
}

queue_node_t *queue_pop(queue_t *queue) {
    queue_node_t *result;
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
}

queue_node_t *queue_search_and_drop(queue_t *queue,
                                    void *data, void *args,
                                    queue_compare_function_t cmp,
                                    queue_drop_function_t drop) {
    queue_node_t *current_node = queue->head;
    queue_node_t *prev_node = NULL;

    while (current_node != NULL) {
        // if found, then remove
        if (cmp(current_node->data, data)) {
            queue_delete_node(queue, prev_node, current_node->next);
            return current_node;
        }
        // if current data should be dropped
        if (drop(current_node->data, args)) {
            queue_delete_node(queue, prev_node, current_node->next);
        } else {
            prev_node = current_node;
        }
        current_node = current_node->next;
    }
    return NULL;
}
