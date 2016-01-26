#ifndef DIVERT_DIVERT_MEM_POOL_H
#define DIVERT_DIVERT_MEM_POOL_H


#include <unistd.h>
#include <_types/_uint32_t.h>

typedef size_t markable_t;

typedef struct divert_mem_block_s divert_mem_block_t;

struct divert_mem_block_s {
    size_t size;
    divert_mem_block_t *next;
};

#define HAS_MARK(p)     ((markable_t)p & 0x01)
#define MASK            ((sizeof(divert_mem_block_t) - 1) & ~0x01)
#define MARK(p)         ((divert_mem_block_t *)((markable_t)p | 0x01))
#define STRIP_MARK(p)   ((divert_mem_block_t *)((markable_t)p & ~(MASK | 0x01)))

#define CAS             __sync_bool_compare_and_swap

#define ATOMIC_INC(addr) __sync_fetch_and_add((addr), 1)

typedef struct {
    divert_mem_block_t **pool;
    size_t num_alloc;
    size_t num_reuse;
    size_t num_failed;
    size_t num_large;
    size_t max;
} divert_mem_pool_t;


divert_mem_pool_t *divert_create_pool(size_t max_alloc);

void divert_destroy_pool(divert_mem_pool_t *pool);

void *divert_mem_alloc(divert_mem_pool_t *pool, size_t size);

void divert_mem_free(divert_mem_pool_t *pool, void *p);

#endif //DIVERT_DIVERT_MEM_POOL_H
