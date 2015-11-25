#include "queue.h"
#include <stdlib.h>
#include <string.h>

queue_t *queue_create(queue_free_function_t free_func) {
    queue_t *queue = malloc(sizeof(queue_t));
    memset(queue, 0, sizeof(queue_t));
    queue->free_data_func = free_func;
    return queue;
}

void queue_dump(queue_t *queue, FILE *fp) {
    queue_node_t *node = queue->head;
    while (node != NULL) {
        if (node != queue->head) {
            fprintf(fp, " => ");
        }
        fprintf(fp, "%p", node);
        node = node->next;
    }
    fprintf(fp, " => NULL\n");
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
    return result;
}

queue_node_t *queue_head(queue_t *queue) {
    if (queue == NULL) {
        return NULL;
    } else {
        return queue->head;
    }
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
        prev->next = NULL;
    } else {
        prev->next = next;
    }
    queue->size--;
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
            queue->free_data_func(current_node->data);
            free(current_node);
        } else {
            prev_node = current_node;
        }
        current_node = current_node->next;
    }
    return NULL;
}

void queue_destroy(queue_t *queue) {
    if (queue != NULL) {
        queue_node_t *prev = NULL;
        for (queue_node_t *cur = queue->head;
             cur != NULL; ) {
            queue->free_data_func(cur->data);
            prev = cur;
            cur = cur->next;
            free(prev);
        }
        free(queue);
    }
}
