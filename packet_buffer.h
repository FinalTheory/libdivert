#ifndef DIVERT_PACKET_BUFFER_H
#define DIVERT_PACKET_BUFFER_H

#include <semaphore.h>

#define BUF_SEM_SLOT "/divert_buffer_slots"
#define BUF_SEM_ITEM "/divert_buffer_items"

typedef struct {
    void **buffer;         /* buffer array */
    size_t n;              /* maximum number of slots */
    size_t front;          /* buf[(front+1)%n] is first item */
    size_t rear;           /* buf[rear%n] is last item */
    sem_t *slots;          /* counts available slots */
    sem_t *items;          /* counts available items */
    pthread_mutex_t *mutex;/* buffer mutex lock */
} packet_buf_t;


#endif //DIVERT_PACKET_BUFFER_H
