/* 
 * TCP free send buffer queue - tcp_sb_queue.c/h
 *
 * EunYoung Jeong
 *
 * Part of this code borrows Click's simple queue implementation
 *
 * ============================== Click License =============================
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include "zc_tcp_sb_queue.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif
/*---------------------------------------------------------------------------*/
struct zc_sb_queue
{
	index_type _capacity;
	volatile index_type _head;
	volatile index_type _tail;

	struct zc_tcp_send_buffer * volatile * _q;
};
/*----------------------------------------------------------------------------*/
static inline index_type 
ZC_NextIndex(zc_sb_queue_t sq, index_type i)
{
	return (i != sq->_capacity ? i + 1: 0);
}
/*---------------------------------------------------------------------------*/
static inline index_type 
ZC_PrevIndex(zc_sb_queue_t sq, index_type i)
{
	return (i != 0 ? i - 1: sq->_capacity);
}
/*---------------------------------------------------------------------------*/
static inline void 
ZC_SBMemoryBarrier(struct zc_tcp_send_buffer * volatile buf, volatile index_type index)
{
	__asm__ volatile("" : : "m" (buf), "m" (index));
}
/*---------------------------------------------------------------------------*/
zc_sb_queue_t 
ZC_CreateSBQueue(int capacity)
{
	zc_sb_queue_t sq;

	sq = (zc_sb_queue_t)calloc(1, sizeof(struct zc_sb_queue));
	if (!sq)
		return NULL;

	sq->_q = (struct zc_tcp_send_buffer **)
			calloc(capacity + 1, sizeof(struct zc_tcp_send_buffer *));
	if (!sq->_q) {
		free(sq);
		return NULL;
	}

	sq->_capacity = capacity;
	sq->_head = sq->_tail = 0;

	return sq;
}
/*---------------------------------------------------------------------------*/
void 
ZC_DestroySBQueue(zc_sb_queue_t sq)
{
	if (!sq)
		return;

	if (sq->_q) {
		free((void *)sq->_q);
		sq->_q = NULL;
	}

	free(sq);
}
/*---------------------------------------------------------------------------*/
int 
ZC_SBEnqueue(zc_sb_queue_t sq, struct zc_tcp_send_buffer *buf)
{
	index_type h = sq->_head;
	index_type t = sq->_tail;
	index_type nt = ZC_NextIndex(sq, t);

	if (nt != h) {
		sq->_q[t] = buf;
		ZC_SBMemoryBarrier(sq->_q[t], sq->_tail);
		sq->_tail = nt;
		return 0;
	}

	TRACE_ERROR("Exceed capacity of buf queue!\n");
	return -1;
}
/*---------------------------------------------------------------------------*/
struct zc_tcp_send_buffer *
ZC_SBDequeue(zc_sb_queue_t sq)
{
	index_type h = sq->_head;
	index_type t = sq->_tail;

	if (h != t) {
		struct zc_tcp_send_buffer *buf = sq->_q[h];
		ZC_SBMemoryBarrier(sq->_q[h], sq->_head);
		sq->_head = ZC_NextIndex(sq, h);
		assert(buf);

		return buf;
	}

	return NULL;
}
/*---------------------------------------------------------------------------*/
