#ifndef DIVERT_PACKET_BUFFER_H
#define DIVERT_PACKET_BUFFER_H

#include <semaphore.h>

#define BUF_SEM_SLOT "/divert_buffer_slots_"
#define BUF_SEM_ITEM "/divert_buffer_items_"

typedef struct {
    void **buffer;         /* buffer array */
    size_t size;
    size_t n;              /* maximum number of slots */
    size_t front;          /* buf[(front+1)%n] is first item */
    size_t rear;           /* buf[rear%n] is last item */
    sem_t *slots;          /* counts available slots */
    sem_t *items;          /* counts available items */
    pthread_mutex_t *mutex;/* buffer mutex lock */
} packet_buf_t;

int divert_buf_init(packet_buf_t *sp, size_t n, char *errmsg);

void divert_buf_clean(packet_buf_t *sp, char *errmsg);

void divert_buf_insert(packet_buf_t *sp, void *item);

void *divert_buf_remove(packet_buf_t *sp);

#endif //DIVERT_PACKET_BUFFER_H
