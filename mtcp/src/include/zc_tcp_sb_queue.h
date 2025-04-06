#ifndef TCP_SB_QUEUE
#define TCP_SB_QUEUE

#include "zc_tcp_send_buffer.h"

/*---------------------------------------------------------------------------*/
typedef struct zc_sb_queue* zc_sb_queue_t;
/*---------------------------------------------------------------------------*/
zc_sb_queue_t 
ZC_CreateSBQueue(int capacity);
/*---------------------------------------------------------------------------*/
void 
ZC_DestroySBQueue(zc_sb_queue_t sq);
/*---------------------------------------------------------------------------*/
int 
ZC_SBEnqueue(zc_sb_queue_t sq, struct zc_tcp_send_buffer *buf);
/*---------------------------------------------------------------------------*/
struct zc_tcp_send_buffer *
ZC_SBDequeue(zc_sb_queue_t sq);
/*---------------------------------------------------------------------------*/

#endif /* TCP_SB_QUEUE */
