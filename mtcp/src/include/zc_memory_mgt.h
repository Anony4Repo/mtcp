#ifndef ZC_MEMORY_MGT_H
#define ZC_MEMORY_MGT_H
/*----------------------------------------------------------------------------*/
#include <rte_common.h>
#include <rte_mempool.h>
/* for rte_versions retrieval */
#include <rte_version.h>
/*----------------------------------------------------------------------------*/
typedef struct rte_mempool mem_pool;
typedef struct rte_mempool* mem_pool_t;
typedef struct rte_mbuf * zc_mbuf_t;
typedef struct rte_mbuf  zc_mbuf;
/* create a memory pool with a chunk size and total size
   an return the pointer to the memory pool */
mem_pool_t
ZC_MPCreate(char *name, int chunk_size, size_t total_size);


zc_mbuf_t
ZC_MPAllocateOne(mem_pool_t mp);

/* destroy the memory pool */
void
ZC_MPDestroy(mem_pool_t mp);

/* retrun the number of free chunks */
int
ZC_MPGetFreeChunks(mem_pool_t mp);
#define MEMPOOL_CACHE_SIZE 64
/*----------------------------------------------------------------------------*/
#endif /* MEMORY_MGT_H */
