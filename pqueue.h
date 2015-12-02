#ifndef __PQUEUE__H__
#define __PQUEUE__H__

#include <unistd.h>
#include <pthread.h>

/**
* Debugging macro .
*
* Checks for a NULL pointer, and prints the error message, source file and
* line via 'stderr' .
* If the check fails the program exits with error code (-1) .
*/
#define NP_CHECK(ptr) \
    { \
        if (NULL == (ptr)) { \
            fprintf(stderr, "%s:%d NULL POINTER: %s n", \
                __FILE__, __LINE__, #ptr); \
            exit(-1); \
        } \
    } \

#define DEBUG(msg) fprintf(stderr, "%s:%d %s", __FILE__, __LINE__, (msg))

/**
* Priority Queue Structure
*/
typedef struct PQueue_s {
    /* The actual size of heap at a certain time */
    size_t size;
    /* The amount of allocated memory for the heap */
    size_t capacity;
    /* An array of (void*), the actual max-heap */
    void **data;
    /* A pointer to a comparator function, used to prioritize elements */
    int (*cmp)(const void *d1, const void *d2);
    pthread_mutex_t mutex;
    pthread_cond_t UntilNotEmpty;
    pthread_cond_t UntilNotFull;
} PQueue;

/** Allocates memory for a new Priority Queue .
Needs a pointer to a comparator function, thus establishing priorities .
*/
PQueue *pqueue_new(int (*cmp)(const void *d1, const void *d2),
                   size_t capacity);

/** De-allocates memory for a given Priority Queue */
void pqueue_destroy(PQueue *q);

/** Add an element inside the Priority Queue */
void pqueue_enqueue(PQueue *q, const void *data);

void pqueue_wait_until(PQueue *q,
                       struct timeval *timeout);

/** Removes the element with the greatest priority from within the Queue */
void *pqueue_dequeue(PQueue *q);

size_t pqueue_size(PQueue *q);

size_t pqueue_capacity(PQueue *q);

int pqueue_is_full(PQueue *q);

int pqueue_is_empty(PQueue *q);

void *pqueue_head(PQueue *q);

#endif