#ifndef ETH_OUT_H
#define ETH_OUT_H

#include <stdint.h>

#include "mtcp.h"
#include "tcp_stream.h"

#define MAX_SEND_PCK_CHUNK 64

uint8_t *
ZC_EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto,
			   int nif, unsigned char *dst_haddr, struct mtcp_zc_mbuf *zc_mbuf, uint16_t iplen);

uint8_t *
EthernetOutput(struct mtcp_manager *mtcp, uint16_t h_proto,
			   int nif, unsigned char *dst_haddr, uint16_t iplen);


#endif /* ETH_OUT_H */
