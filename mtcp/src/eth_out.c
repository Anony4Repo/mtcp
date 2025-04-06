#include <stdio.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>

#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <netinet/ip.h>

#include "mtcp.h"
#include "arp.h"
#include "eth_out.h"
#include "debug.h"

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#ifndef ERROR
#define ERROR (-1)
#endif

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define MAX_WINDOW_SIZE 65535

/*----------------------------------------------------------------------------*/
uint8_t *
ZC_EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto,
				  int nif, unsigned char *dst_haddr, struct mtcp_zc_mbuf *zc_mbuf, uint16_t iplen)

{
	uint8_t *buf;
	struct ethhdr *ethh;
	int i, eidx;

	/*
	 * -sanity check-
	 * return early if no interface is set (if routing entry does not exist)
	 */
	if(zc_mbuf == NULL)
	{
		printf("zc_mbuf is NULL\n");
		exit(0);
	}

	if (nif < 0)
	{
		TRACE_INFO("No interface set!\n");
		return NULL;
	}

	eidx = CONFIG.nif_to_eidx[nif];
	if (unlikely(eidx < 0))
	{
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}
	if (mtcp->iom->put_wptr(mtcp->ctx, eidx, (uint8_t*)zc_mbuf->bsd_mbuf))
	{
		TRACE_ERROR("Failed to put wptr\n");
		return NULL;
	}
	buf = (uint8_t *)rte_pktmbuf_prepend(zc_mbuf->bsd_mbuf, iplen + ETHERNET_HEADER_LEN - zc_mbuf->len);
	if (!buf)
	{
		printf("data len(%d) iplen(%d) ETHERNET_HEADER_LEN(%d) head_room(%d)\n", zc_mbuf->len, iplen, ETHERNET_HEADER_LEN,rte_pktmbuf_headroom(zc_mbuf->bsd_mbuf));
		//data len(600) iplen(1500) ETHERNET_HEADER_LEN(14) head_room(128
		TRACE_ERROR("zc Failed to get available write buffer\n");
		exit(0);
		return NULL;
	}
	// ! HL modify
	// memset(buf, 0, ETHERNET_HEADER_LEN + iplen);

	// #if 1
	// 	TRACE_INFO("dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
	// 				dst_haddr[0], dst_haddr[1],
	// 				dst_haddr[2], dst_haddr[3],
	// 				dst_haddr[4], dst_haddr[5]);
	// #endif

	ethh = (struct ethhdr *)buf;
	for (i = 0; i < ETH_ALEN; i++)
	{
		ethh->h_source[i] = CONFIG.eths[eidx].haddr[i];
		ethh->h_dest[i] = dst_haddr[i];
	}
	ethh->h_proto = htons(h_proto);

	return (uint8_t *)(ethh + 1);
}
/*----------------------------------------------------------------------------*/

uint8_t *
EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto,
			   int nif, unsigned char *dst_haddr, uint16_t iplen)

{
	uint8_t *buf;
	struct ethhdr *ethh;
	int i, eidx;

	/*
	 * -sanity check-
	 * return early if no interface is set (if routing entry does not exist)
	 */
	if (nif < 0)
	{
		TRACE_INFO("No interface set!\n");
		return NULL;
	}

	eidx = CONFIG.nif_to_eidx[nif];
	if (unlikely(eidx < 0))
	{
		TRACE_INFO("No interface selected!\n");
		return NULL;
	}

	buf = mtcp->iom->get_wptr(mtcp->ctx, eidx, iplen + ETHERNET_HEADER_LEN);
	if (!buf)
	{
		TRACE_ERROR("Failed to get available write buffer\n");
		return NULL;
	}
	// ! HL modify
	// memset(buf, 0, ETHERNET_HEADER_LEN + iplen);

	// #if 1
	// 	TRACE_INFO("dst_hwaddr: %02X:%02X:%02X:%02X:%02X:%02X\n",
	// 				dst_haddr[0], dst_haddr[1],
	// 				dst_haddr[2], dst_haddr[3],
	// 				dst_haddr[4], dst_haddr[5]);
	// #endif

	ethh = (struct ethhdr *)buf;
	for (i = 0; i < ETH_ALEN; i++)
	{
		ethh->h_source[i] = CONFIG.eths[eidx].haddr[i];
		ethh->h_dest[i] = dst_haddr[i];
	}
	ethh->h_proto = htons(h_proto);

	return (uint8_t *)(ethh + 1);
}
/*----------------------------------------------------------------------------*/
