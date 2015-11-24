#ifndef DIVERT_PACKET_BUFFER_H
#define DIVERT_PACKET_BUFFER_H

#include <pthread.h>

typedef struct {
    void **buffer;         /* buffer array */
    size_t size;
    size_t n;              /* maximum number of slots */
    size_t front;          /* buf[(front+1)%n] is first item */
    size_t rear;           /* buf[rear%n] is last item */
    pthread_mutex_t *mutex;/* buffer mutex lock */
    pthread_cond_t *UntilNotEmpty;
    pthread_cond_t *UntilNotFull;
} packet_buf_t;

int divert_buf_init(packet_buf_t *sp, size_t n, char *errmsg);

void divert_buf_clean(packet_buf_t *sp);

void divert_buf_insert(packet_buf_t *sp, void *item);

void *divert_buf_remove(packet_buf_t *sp);

#endif //DIVERT_PACKET_BUFFER_H
