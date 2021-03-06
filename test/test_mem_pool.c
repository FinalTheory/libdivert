#include "divert_mem_pool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>


#define MAX_LOOP    10000
#define MEM_SIZE    1300
#define NUM_THREADS 32

int flag = 0;

void *thread_func(void *p) {
    divert_mem_pool_t *pool = p;
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
        // usleep((useconds_t)rand() % 10000);
        // check if data in buffer is still right
        for (int j = 0; j < MEM_SIZE; j++) {
            if (((u_char *)buf)[j] != data[j]) {
                printf("Fuck, mem addr at offset %d: %p\n", j, buf);
                flag = 1;
                break;
            }
        }
        // randomly free the memory
        if (rand() % 2) {
            divert_mem_free(pool, buf);
        }
    }
    return NULL;
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
    if (flag == 0) {
        puts("Success");
        printf("Num reused: %zu, num new allocated: %zu\n",
               pool->num_reuse, pool->num_alloc);
        divert_destroy_pool(pool);
    } else {
        puts("Failed");
    }
}
