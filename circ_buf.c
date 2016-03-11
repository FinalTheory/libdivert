#include "circ_buf.h"
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
    return sp;
}

/* Clean up buffer sp */
void circ_buf_destroy(circ_buf_t *sp) {
    if (sp == NULL) return;
    free_all_memory(sp);
}

size_t circ_buf_size(circ_buf_t *sp) {
    return sp->size;
}

size_t circ_buf_capacity(circ_buf_t *sp) {
    return sp->capacity;
}

int circ_buf_is_full(circ_buf_t *sp) {
    return sp->size >= sp->capacity;
}

int circ_buf_is_empty(circ_buf_t *sp) {
    return sp->size < 1;
}

/* Insert item onto the rear of shared buffer sp */
int circ_buf_insert(circ_buf_t *sp, void *item) {
    if (sp->size >= sp->capacity) { return -1; }
    sp->buffer[(++sp->rear) % (sp->capacity)] = item;        /* Insert the item */
    sp->size++;
    return 0;
}

/* Only return the first item from buffer sp */
void *circ_buf_head(circ_buf_t *sp) {
    if (sp->size == 0) { return NULL; }
    return sp->buffer[(sp->front + 1) % (sp->capacity)];
}

/* Remove and return the first item from buffer sp */
void *circ_buf_remove(circ_buf_t *sp) {
    void *item;
    if (sp->size == 0) { return NULL; }
    item = sp->buffer[(++sp->front) % (sp->capacity)];        /* Remove the item */
    sp->size--;
    return item;
}
