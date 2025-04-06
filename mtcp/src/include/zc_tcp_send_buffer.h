#ifndef ZC_TCP_SEND_BUFFER_H
#define ZC_TCP_SEND_BUFFER_H

#include <stdlib.h>
#include <stdint.h>
#include "u32hash.h"
#include <rte_mbuf.h>

#define ZC_PKT_SIZE 1448
#define RTE_HEADER_ROOM 128
typedef struct zc_sb_manager *zc_sb_manager_t;
typedef struct mtcp_manager *mtcp_manager_t;
/*----------------------------------------------------------------------------*/

struct mtcp_zc_mbuf
{
	struct rte_mbuf *bsd_mbuf; /* point to the head mbuf */
	uint32_t off;				   /* the offset of total mbuf, APP shouldn't modify it */
	uint32_t len;				   /* the total len of the mbuf chain */
	uint32_t seq;
};

struct zc_tcp_send_buffer
{
	struct mtcp_zc_mbuf *data;
	// struct mtcp_zc_mbuf *head;

	uint16_t tail_off;
	uint16_t q_len;
	uint16_t cur_idx;
	uint16_t w_head;
	uint16_t w_tail;
	uint16_t size;
	uint32_t len;
	uint64_t cum_len;
	HashTable *hash_t;

	uint32_t head_seq;
	uint32_t init_seq;
};
/*----------------------------------------------------------------------------*/
uint32_t
ZC_SBGetCurnum(zc_sb_manager_t sbm);
/*----------------------------------------------------------------------------*/
zc_sb_manager_t
ZC_SBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum);
/*----------------------------------------------------------------------------*/
struct zc_tcp_send_buffer *
ZC_SBInit(zc_sb_manager_t sbm, size_t count, uint32_t init_seq);
/*----------------------------------------------------------------------------*/
void ZC_SBFree(zc_sb_manager_t sbm, struct zc_tcp_send_buffer *buf);
/*----------------------------------------------------------------------------*/
size_t
ZC_SBPut(zc_sb_manager_t sbm, struct zc_tcp_send_buffer *buf, const void *data, size_t len);
/*----------------------------------------------------------------------------*/
size_t
ZC_SBRemove(zc_sb_manager_t sbm, struct zc_tcp_send_buffer *buf, size_t len);
/*----------------------------------------------------------------------------*/
struct mtcp_zc_mbuf* ZC_SBGetIndexBylens(struct zc_tcp_send_buffer *sndbuf, uint32_t seq);
/*----------------------------------------------------------------------------*/
#endif