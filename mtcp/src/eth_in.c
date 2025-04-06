#include "ip_in.h"
#include "eth_in.h"
#include "arp.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
// return value is unused
int ProcessPacket(mtcp_manager_t mtcp, const int ifidx,
				  uint32_t cur_ts, unsigned char *pkt_data, int len)
{
	HL_PRINT("[+] in ProcessPacket\n");
#ifdef ZERO_COPY_VERSION
	struct ethhdr *ethh = (struct ethhdr *)((struct mtcp_zc_rmbuf *)pkt_data)->bsd_mbuf;
#else
	struct ethhdr *ethh = (struct ethhdr *)pkt_data;
#endif
	u_short ip_proto = ntohs(ethh->h_proto);
	int ret;

#ifdef PKTDUMP
	DumpPacket(mtcp, (char *)pkt_data, len, "IN", ifidx);
#endif

#ifdef NETSTAT
	mtcp->nstat.rx_packets[ifidx]++;
	mtcp->nstat.rx_bytes[ifidx] += len + 24;
#endif /* NETSTAT */

	if (ip_proto == ETH_P_IP)
	{
		/* process ipv4 packet */
		// printf("[+]3*******************cwnd(%d)\n",*((int*)0x10b4b3b38));
		ret = ProcessIPv4Packet(mtcp, cur_ts, ifidx, pkt_data, len);
		// printf("[+]4*******************cwnd(%d)\n",*((int*)0x10b4b3b38));
	}
	else if (ip_proto == ETH_P_ARP)
	{
#ifdef ZERO_COPY_VERSION
		ProcessARPPacket(mtcp, cur_ts, ifidx, ((struct mtcp_zc_rmbuf *)pkt_data)->bsd_mbuf, len);
#else
		ProcessARPPacket(mtcp, cur_ts, ifidx, pkt_data, len);
#endif
		return TRUE;
	}
	else
	{
		// DumpPacket(mtcp, (char *)pkt_data, len, "??", ifidx);
		// mtcp->iom->release_pkt(mtcp->ctx, ifidx, pkt_data, len);
		return TRUE;
	}

#ifdef NETSTAT
	if (ret < 0)
	{
		mtcp->nstat.rx_errors[ifidx]++;
	}
#endif

	return ret;
}
