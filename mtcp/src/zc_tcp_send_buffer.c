#include <string.h>

#include "zc_memory_mgt.h"
#include "debug.h"
#include "zc_tcp_send_buffer.h"
#include "zc_tcp_sb_queue.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/*----------------------------------------------------------------------------*/
struct zc_sb_manager
{
	size_t chunk_size;
	uint32_t cur_num;
	uint32_t cnum;
	mem_pool_t mp;
	zc_sb_queue_t freeq;

} zc_sb_manager;
/*----------------------------------------------------------------------------*/
uint32_t
ZC_SBGetCurnum(zc_sb_manager_t sbm)
{
	return sbm->cur_num;
}
/*----------------------------------------------------------------------------*/
zc_sb_manager_t
ZC_SBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum)
{
	zc_sb_manager_t sbm = (zc_sb_manager_t)calloc(1, sizeof(zc_sb_manager));
	if (!sbm)
	{
		TRACE_ERROR("ZC_SBManagerCreate() failed. %s\n", strerror(errno));
		return NULL;
	}

	sbm->chunk_size = chunk_size;
	sbm->cnum = cnum;
	char pool_name[RTE_MEMPOOL_NAMESIZE];
	sprintf(pool_name, "sbm_pool_%d", mtcp->ctx->cpu);
	sbm->mp = (mem_pool_t)ZC_MPCreate(pool_name, chunk_size, (uint64_t)chunk_size * cnum);

	if (!sbm->mp)
	{
		TRACE_ERROR("Failed to create mem pool for sb.\n");
		free(sbm);
		return NULL;
	}

	sbm->freeq = ZC_CreateSBQueue(cnum);
	if (!sbm->freeq)
	{
		TRACE_ERROR("Failed to create free buffer queue.\n");
		ZC_MPDestroy(sbm->mp);
		free(sbm);
		return NULL;
	}

	return sbm;
}
/*----------------------------------------------------------------------------*/

struct zc_tcp_send_buffer *
ZC_SBInit(zc_sb_manager_t sbm, size_t count, uint32_t init_seq)
{
	struct zc_tcp_send_buffer *sndbuf;

	/* first try dequeue from free buffer queue */
	sndbuf = ZC_SBDequeue(sbm->freeq);
	if (!sndbuf)
	{
		sndbuf = (struct zc_tcp_send_buffer *)malloc(sizeof(struct zc_tcp_send_buffer));
		if (!sndbuf)
		{
			perror("malloc() for buf");
			return NULL;
		}
		sndbuf->data = malloc(sizeof(struct mtcp_zc_mbuf) * count);
		assert(sndbuf->data);
		for (int i = 0; i < count; i++)
		{
			sndbuf->data[i].bsd_mbuf = ZC_MPAllocateOne(sbm->mp);
			sndbuf->data[i].off = i;
			sndbuf->data[i].len = 0;
			if (!sndbuf->data[i].bsd_mbuf)
			{
				TRACE_ERROR("Failed to fetch memory chunk for data.\n");
				free(sndbuf);
				return NULL;
			}
			sbm->cur_num++;
		}
		sndbuf->hash_t = (HashTable *)malloc(sizeof(HashTable));
	}
	hash_init(sndbuf->hash_t);
	// sndbuf->head = sndbuf->data;

	sndbuf->tail_off = 0;
	sndbuf->len = sndbuf->cum_len = 0;
	sndbuf->size = count;
	sndbuf->w_head = sndbuf->w_tail = 0;
	sndbuf->cur_idx = 0;

	sndbuf->init_seq = sndbuf->head_seq = init_seq;
	sndbuf->data[0].seq = init_seq;
	// sndbuf->data[count - 1].len = 0;

	return sndbuf;
}

/*----------------------------------------------------------------------------*/
void ZC_SBFree(zc_sb_manager_t sbm, struct zc_tcp_send_buffer *sndbuf)
{
	if (!sndbuf)
		return;

	ZC_SBEnqueue(sbm->freeq, sndbuf);
}

size_t
ZC_SBPut(zc_sb_manager_t sbm, struct zc_tcp_send_buffer *sndbuf, const void *data, size_t len)
{
	size_t to_put;
	size_t remaining_len;
	size_t ret_len = 0;
	size_t pkt_s = 0;
	uint32_t seq;

	if (unlikely(len <= 0))
		return 0;

	uint16_t w_head = sndbuf->w_head;
	/* if no space, return -2 */
	if (unlikely((w_head + 1) % SBUFF_ELE_COUNT == sndbuf->w_tail))
	{
		printf("w_head(%d) w_tail(%d) size(%d) q_len(%d)\n", w_head, sndbuf->w_tail, sndbuf->size, sndbuf->q_len);
		return -2;
	}

	to_put = (len + ZC_PKT_SIZE - 1) / ZC_PKT_SIZE;
	remaining_len = len % ZC_PKT_SIZE;
	if (remaining_len == 0)
	{
		remaining_len = ZC_PKT_SIZE;
	}

	while ((w_head + 1) % SBUFF_ELE_COUNT != sndbuf->w_tail && to_put > 0)
	{

		/* if the data fit into the buffer, copy it */
		pkt_s = to_put == 1 ? remaining_len : ZC_PKT_SIZE;
		rte_pktmbuf_reset(sndbuf->data[w_head].bsd_mbuf);
		void *payload = rte_pktmbuf_append(sndbuf->data[w_head].bsd_mbuf, pkt_s);
		rte_memcpy(payload, (char *)data + ret_len, pkt_s);
		sndbuf->data[w_head].len = pkt_s;
		seq = sndbuf->data[w_head].seq;
		if (!hash_insert(sndbuf->hash_t, seq, w_head))
		{
			assert(0);
		}
		// printf("put ff(%d) seq(%d)\n", sndbuf->w_head, sndbuf->data[sndbuf->w_head].seq);
		w_head = (w_head + 1) % SBUFF_ELE_COUNT;
		sndbuf->data[w_head].seq = seq + pkt_s;
		to_put--;
		ret_len += pkt_s;
	}
	sndbuf->q_len = (w_head + SBUFF_ELE_COUNT - sndbuf->w_tail) % SBUFF_ELE_COUNT;
	sndbuf->w_head = w_head;
	sndbuf->len += ret_len;
	return ret_len;
}

#define MIN(a, b) ((a) < (b) ? (a) : (b))

size_t
ZC_SBRemove(zc_sb_manager_t sbm, struct zc_tcp_send_buffer *sndbuf, size_t len)
{
	size_t to_remove;
	if (len <= 0)
		return 0;

	sndbuf->head_seq += len;
	to_remove = MIN(len, sndbuf->len);
	if (to_remove <= 0)
	{
		printf("error SBRemove len(%ld) sndbuf->len(%u)\n", len, sndbuf->len);
		return -2;
	}
	uint16_t w_tail = sndbuf->w_tail;
	sndbuf->len -= len;
	while (w_tail != sndbuf->w_head && len > 0)
	{
		len -= sndbuf->data[w_tail].len;
		sndbuf->data[w_tail].len = 0;
		hash_delete(sndbuf->hash_t, sndbuf->data[w_tail].seq);
		w_tail = (w_tail + 1) % SBUFF_ELE_COUNT;
		// sndbuf->len -= len;
	}
	assert(len == 0);

	// sndbuf->head = sndbuf->data + w_tail;
	sndbuf->w_tail = w_tail;
	sndbuf->q_len = (sndbuf->w_head + SBUFF_ELE_COUNT - w_tail) % SBUFF_ELE_COUNT;
	// printf("put w_head(%d) w_tail(%d) len(%u) q_len(%d)\n", sndbuf->w_head, sndbuf->w_tail, sndbuf->len, sndbuf->q_len);
	return to_remove;
}

struct mtcp_zc_mbuf *ZC_SBGetIndexBylens(struct zc_tcp_send_buffer *sndbuf, uint32_t seq)
{
	uint16_t cur_idx = sndbuf->cur_idx;
	// printf("w_tail(%d) w_head(%d) len(%ld) sndbuf->len(%u)\n", sndbuf->w_tail, sndbuf->w_head, len,sndbuf->len);
	// while (total_len < seq && i != sndbuf->w_head)
	// {
	// 	total_len += sndbuf->data[i].len;
	// 	i = (i + 1) % sndbuf->size;
	// }

	// ! error code
	// if (cur_idx == sndbuf->w_head)
	// {
	// 	printf("cur_idx(%d) w_head(%d) len(%u) seq(%u) lastseq(%u)\n", cur_idx, sndbuf->w_head, sndbuf->len, seq, sndbuf->data[(sndbuf->w_head + SBUFF_ELE_COUNT - 1) % SBUFF_ELE_COUNT].seq);
	// 	return NULL;
	// }
	if (seq != sndbuf->data[cur_idx].seq)
	{
		cur_idx = hash_lookup(sndbuf->hash_t, seq);
		// printf("put w_head(%d) w_tail(%d) len(%u) q_len(%d)\n", sndbuf->w_head, sndbuf->w_tail, sndbuf->len, sndbuf->q_len);

		// printf("len(%d) cur_idx(%d)\n", (sndbuf->w_head + SBUFF_ELE_COUNT - cur_idx) % SBUFF_ELE_COUNT, cur_idx);
		if (cur_idx == DELETED_VALUE)
		{
			printf("cur_idx(%d) w_head(%d) len(%u) seq(%u) lastseq(%u)\n", cur_idx, sndbuf->w_head, sndbuf->len - (seq - sndbuf->head_seq), seq, sndbuf->data[(sndbuf->w_head + SBUFF_ELE_COUNT - 1) % SBUFF_ELE_COUNT].seq);
			exit(0);
		}

		assert(cur_idx != DELETED_VALUE);
		assert(sndbuf->data[cur_idx].seq == seq);
	}
	sndbuf->cur_idx = (cur_idx + 1) % SBUFF_ELE_COUNT;
	uint16_t current_headroom = rte_pktmbuf_headroom(sndbuf->data[cur_idx].bsd_mbuf);
	if (current_headroom < RTE_HEADER_ROOM)
	{
		rte_pktmbuf_adj(sndbuf->data[cur_idx].bsd_mbuf, 128 - current_headroom);
	}
	return &sndbuf->data[cur_idx];
}
