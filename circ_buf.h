#ifndef DIVERT_PACKET_BUFFER_H
#define DIVERT_PACKET_BUFFER_H

#include <unistd.h>

typedef struct {
    /* buffer array */
    void **buffer;
    /* size and capacity */
    size_t size;
    size_t capacity;
    /* maximum number of slots */
    size_t front;
    /* buf[(front+1)%n] is first item */
    size_t rear;
    /* buf[rear%n] is last item */
} circ_buf_t;

circ_buf_t *circ_buf_create(size_t capacity);

void circ_buf_destroy(circ_buf_t *sp);

size_t circ_buf_size(circ_buf_t *sp);

size_t circ_buf_capacity(circ_buf_t *sp);

int circ_buf_is_full(circ_buf_t *sp);

int circ_buf_is_empty(circ_buf_t *sp);

int circ_buf_insert(circ_buf_t *sp, void *item);

void *circ_buf_head(circ_buf_t *sp);

void *circ_buf_remove(circ_buf_t *sp);

#endif //DIVERT_PACKET_BUFFER_H
