#include "divert_mem_pool.h"
#include <stdlib.h>
#include <string.h>


divert_mem_pool_t *divert_create_pool(size_t max_alloc) {
    divert_mem_pool_t *pool =
            calloc(sizeof(divert_mem_pool_t), 1);
    if (pool == NULL) {
        return NULL;
    }
    pool->pool = calloc(sizeof(divert_mem_block_t *), max_alloc + 1);
    if (pool->pool == NULL) {
        free(pool);
        return NULL;
    }
    pool->max = max_alloc;
    pool->num_alloc = 0;
    pool->num_reuse = 0;
    pool->num_failed = 0;
    pool->num_large = 0;
    return pool;
}

void divert_destroy_pool(divert_mem_pool_t *pool) {
    if (pool != NULL) {
        // first free all memory blocks
        for (int idx = 0; idx <= pool->max; idx++) {
            for (divert_mem_block_t *blk = pool->pool[idx];
                 blk; blk = blk->next) {
                free(blk);
            }
        }
        // then free the entire pool
        if (pool->pool != NULL) {
            free(pool->pool);
        }
        free(pool);
    }
    return;
}

void *divert_mem_alloc(divert_mem_pool_t *pool, size_t size) {
    divert_mem_block_t *block = NULL, *next_blk = NULL;
    // remove a memory block from pool
    if (size <= pool->max) {
        do {
            block = pool->pool[size];
            if (block == NULL) { break; }
            next_blk = block->next;
        } while (!__sync_bool_compare_and_swap(&pool->pool[size], block, next_blk));
    }
    // if got a block of memory, just return it
    if (block != NULL) {
        block->next = NULL;
        // update number of reused blocks
        ATOMIC_INC(&pool->num_reuse);
        // get the memory address and clear the contents
        void *addr = (void *)block + sizeof(divert_mem_block_t);
        memset(addr, 0, size);
        return addr;
    }
    // if not, we allocate a new block of memory
    void *p = calloc(sizeof(divert_mem_block_t) + size, 1);
    if (p != NULL) {
        block = p;
        block->next = NULL;
        block->size = size;
        // update number of new allocated blocks
        ATOMIC_INC(&pool->num_alloc);
        // and number of large blocks
        if (size >= pool->max) { ATOMIC_INC(&pool->num_large); }
        return p + sizeof(divert_mem_block_t);
    } else {
        // return NULL if allocation failed
        ATOMIC_INC(&pool->num_failed);
        return NULL;
    }
}

void divert_mem_free(divert_mem_pool_t *pool, void *p) {
    if (p == NULL) { return; };
    divert_mem_block_t *block = p - sizeof(divert_mem_block_t);
    divert_mem_block_t *item = NULL;
    size_t size = block->size;

    if (size <= pool->max) {
        do {
            item = pool->pool[size];
            block->next = item;
        } while (!CAS(&pool->pool[size], item, block));
    } else {
        free(block);
    }
    return;
}
