
/*
 * 2010.12.10 Shinae Woo
 * Ring buffer structure for managing dynamically allocating ring buffer
 *
 * put data to the tail
 * get/pop/remove data from the head
 *
 * always garantee physically continuous ready in-memory data from data_offset to the data_offset+len
 * automatically increase total buffer size when buffer is full
 * for efficiently managing packet payload and chunking
 *
 */

#ifndef ZC_NRE_RING_BUFFER
#define ZC_NRE_RING_BUFFER

#include <stdint.h>
#include <sys/types.h>

/*----------------------------------------------------------------------------*/
enum rb_caller
{
	AT_APP,
	AT_MTCP
};
/*----------------------------------------------------------------------------*/
typedef struct mtcp_manager *mtcp_manager_t;
typedef struct rb_manager *rb_manager_t;
/*----------------------------------------------------------------------------*/
struct fragment_ctx
{
	uint32_t seq;
	uint32_t len : 31;
	uint32_t is_calloc : 1;
	struct fragment_ctx *next;
};
/*----------------------------------------------------------------------------*/

struct mtcp_zc_rmbuf
{
	struct rte_mbuf *ori_mbuf;
	uint8_t *bsd_mbuf; /* point to the head mbuf */
	uint32_t off;	   /* the offset of total mbuf, APP shouldn't modify it */
	uint32_t len;	   /* the total len of the mbuf chain */
	uint32_t seq;
	uint16_t free;
	uint16_t idx;
	struct mtcp_zc_rmbuf* next;
};

struct rmbuf_list
{
	struct mtcp_zc_rmbuf *data;
	struct rmbuf_list *next;
};

#define ZC_PKT_COUNT 512
#define ZC_UNSORTED_PKT_COUNT 512
#define WINDOWS_SIZE (ZC_PKT_COUNT * 1024)

struct zc_tcp_ring_buffer
{
	struct mtcp_zc_rmbuf *data[ZC_PKT_COUNT]; /* buffered data */

	struct rmbuf_list *unsort_data; //
	struct rmbuf_list *free_list;	//
	uint16_t free_list_len;
	uint16_t u_qlen;

	uint32_t head_offset; /* offset for the head (head - data) */
	// uint32_t tail_offset;	/* offset fot the last byte (null byte) */
	uint16_t q_len;
	uint16_t r_head;
	uint16_t r_tail;

	int merged_len;	  /* contiguously merged length */
	uint64_t cum_len; /* cummulatively merged length */
	// int last_len;			/* currently saved data length */
	// int size;				/* total ring buffer size */

	/* TCP payload features */
	uint32_t head_seq;
	uint32_t init_seq;
	uint32_t need_seq;

	struct fragment_ctx *fctx;
	struct rmbuf_list list_pool[ZC_UNSORTED_PKT_COUNT ];
};
/*----------------------------------------------------------------------------*/
// uint32_t RBGetCurnum(rb_manager_t rbm);
void ZC_RBPrintInfo(struct zc_tcp_ring_buffer *buff);
void ZC_RBPrintStr(struct zc_tcp_ring_buffer *buff);
void ZC_RBPrintHex(struct zc_tcp_ring_buffer *buff);
/*----------------------------------------------------------------------------*/
rb_manager_t RBManagerCreate(mtcp_manager_t mtcp, size_t chunk_size, uint32_t cnum);
/*----------------------------------------------------------------------------*/
struct zc_tcp_ring_buffer *ZC_RBInit(rb_manager_t rbm, uint32_t init_seq);
void ZC_RBFree(rb_manager_t rbm, struct zc_tcp_ring_buffer *buff);
/*----------------------------------------------------------------------------*/
/* data manupulation functions */
int ZC_RBPut(rb_manager_t rbm, struct zc_tcp_ring_buffer *buff,
			 struct mtcp_zc_rmbuf *data, uint32_t len, uint32_t seq);
size_t ZC_RBRemove(rb_manager_t rbm, struct zc_tcp_ring_buffer *buff,
				   size_t len, int option);
void ZC_FreeAllBuffer(struct zc_tcp_ring_buffer *buff);
/*----------------------------------------------------------------------------*/

#endif
