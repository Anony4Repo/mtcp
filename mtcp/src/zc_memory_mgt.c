#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include "debug.h"
#include "zc_memory_mgt.h"

mem_pool_t
ZC_MPCreate(char *name, int chunk_size, size_t total_size)
{
	struct rte_mempool *mp;
	size_t items;
	
	items = total_size/chunk_size;
	mp = rte_pktmbuf_pool_create(name, items,MEMPOOL_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	printf("ZC_MPCreate name: %s, items: %lu, chunk_size: %d, total_size: %lu\n", name, items, chunk_size, total_size);
	if (mp == NULL) {
		TRACE_ERROR("Can't allocate memory for mempool!\n");
		exit(EXIT_FAILURE);
	}

	return mp;
}
/*----------------------------------------------------------------------------*/
zc_mbuf_t
ZC_MPAllocateOne(mem_pool_t mp)
{
	zc_mbuf_t mbuf = rte_pktmbuf_alloc(mp);
	if (mbuf == NULL) {
		TRACE_ERROR("Can't allocate memory for mbuf!\n");
        return NULL;
    }
	mbuf->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
	return mbuf;
}

void
ZC_MPDestroy(mem_pool_t mp)
{
	rte_mempool_free(mp);
}
/*----------------------------------------------------------------------------*/
int
ZC_MPGetFreeChunks(mem_pool_t mp)
{
	return (int)rte_mempool_avail_count(mp);
}
/*----------------------------------------------------------------------------*/
