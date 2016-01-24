#include "divert_mem_pool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>


#define MAX_LOOP    10000
#define MEM_SIZE    1300
#define NUM_THREADS 16

void *thread_func(void *p) {
    divert_mem_pool_t *pool = p;
    int *res = calloc(sizeof(int), 1);
    u_char *data = calloc(MEM_SIZE, 1);
    // generate random data
    for (int i = 0; i < MEM_SIZE; i++) {
        data[i] = (u_char)rand();
    }
    for (int i = 0; i < MAX_LOOP; i++) {
        // allocate a block of memory
        void *buf = divert_mem_alloc(pool, MEM_SIZE);
        // copy private data of this thread
        memcpy(buf, data, MEM_SIZE);
        // sleep for up to 10 ms
        usleep((useconds_t)rand() % 10000);
        // check if data in buffer is still right
        for (int j = 0; j < MEM_SIZE; j++) {
            if (((u_char *)buf)[j] != data[j]) {
                puts("Fuck!");
                *res = 1;
            }
        }
        // finally free the memory
        divert_mem_free(pool, buf);
    }
    return res;
}



int main() {
    void *res;
    srand(time(NULL));
    divert_mem_pool_t *pool = divert_create_pool(MEM_SIZE);
    pthread_t threads[NUM_THREADS];
    // threads start
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_create(&threads[i], NULL, thread_func, pool);
    }
    // threads join
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], &res);
    }
    if (*(int *)res == 0) {
        puts("Success");
        divert_destroy_pool(pool);
    } else {
        puts("Failed");
    }
}
