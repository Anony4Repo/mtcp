/* for io_module_func def'ns */
#include "io_module.h"
#ifndef DISABLE_DPDK
/* for mtcp related def'ns */
#include "mtcp.h"
/* for errno */
#include <errno.h>
/* for logging */
#include "debug.h"
/* for num_devices_* */
#include "config.h"
/* for rte_max_eth_ports */
#include <rte_common.h>
/* for rte_eth_rxconf */
#include <rte_ethdev.h>
/* for delay funcs */
#include <rte_cycles.h>
#include <rte_errno.h>
#define ENABLE_STATS_IOCTL 1
#ifdef ENABLE_STATS_IOCTL
/* for close */
#include <unistd.h>
/* for open */
#include <fcntl.h>
/* for ioctl */
#include <sys/ioctl.h>
#endif /* !ENABLE_STATS_IOCTL */
/* for ip pseudo-chksum */
#include <rte_ip.h>
// #define IP_DEFRAG			1
#ifdef IP_DEFRAG
/* for ip defragging */
#include <rte_ip_frag.h>
#endif
/* for retrieving rte version(s) */
#include <rte_version.h>
/*----------------------------------------------------------------------------*/
/* Essential macros */
#define MAX_RX_QUEUE_PER_LCORE MAX_CPUS
#define MAX_TX_QUEUE_PER_PORT MAX_CPUS

// !!! HLMODIFY very important
#ifdef ENABLELRO
#define BUF_SIZE 16384
#else
#define BUF_SIZE 1644
// sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM == 128
// #define BUF_SIZE 16384
#endif
#define MBUF_SIZE (BUF_SIZE + sizeof(struct rte_mbuf) + RTE_PKTMBUF_HEADROOM)

#define NB_MBUF 12288
#define MEMPOOL_CACHE_SIZE 64
#ifdef ENFORCE_RX_IDLE
#define RX_IDLE_ENABLE 1
#define RX_IDLE_TIMEOUT 1 /* in micro-seconds */
#endif

/*
 * RX and TX Prefetch, Host, and Write-back threshold values should be
 * carefully set for optimal performance. Consult the nedptwork
 * controller's datasheet and supporting DPDK documentation for guidance
 * on how these parameters should be set.
 */
#define RX_PTHRESH 8 /**< Default values of RX prefetch threshold reg. */
#define RX_HTHRESH 8 /**< Default values of RX host threshold reg. */
#define RX_WTHRESH 4 /**< Default values of RX write-back threshold reg. */

/*
 * These default values are optimized for use with the Intel(R) 82599 10 GbE
 * Controller and the DPDK ixgbe PMD. Consider using other values for other
 * network controllers and/or network drivers.
 */
#define TX_PTHRESH 36 /**< Default values of TX prefetch threshold reg. */
#define TX_HTHRESH 0  /**< Default values of TX host threshold reg. */
#define TX_WTHRESH 0  /**< Default values of TX write-back threshold reg. */

#define TX_QUEUE_NUM 4096
#define RX_QUEUE_NUM 8192
#define MAX_PKT_BURST 128 // 64 /*128*/
#define MAX_RX_PKT_BURST 512

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

/*
 * Ethernet frame overhead
 */

#define ETHER_IFG 12
#define ETHER_PREAMBLE 8
#define ETHER_OVR (RTE_ETHER_CRC_LEN + ETHER_PREAMBLE + ETHER_IFG)

static const uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static const uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
/*----------------------------------------------------------------------------*/
/* packet memory pools for storing packet bufs */
static struct rte_mempool *pktmbuf_pool[MAX_CPUS] = {NULL};

// #define DEBUG				1
#ifdef DEBUG
/* ethernet addresses of ports */
static struct rte_ether_addr ports_eth_addr[HL_MAX_ETHPORTS];
#endif

static struct rte_eth_dev_info dev_info[HL_MAX_ETHPORTS];

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.mtu = 1500,

		.split_hdr_size = 0,
		// DEV_RX_OFFLOAD_TCP_LRO
		.offloads = DEV_RX_OFFLOAD_CHECKSUM ,
	},
	.rx_adv_conf = {
		.rss_conf = {.rss_key = NULL, .rss_hf = ETH_RSS_TCP | ETH_RSS_UDP | ETH_RSS_IP},
		// .rss_conf = { .rss_hf = ETH_RSS_TCP | ETH_RSS_UDP | ETH_RSS_IP | ETH_RSS_L2_PAYLOAD},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
		.offloads = (DEV_TX_OFFLOAD_IPV4_CKSUM | DEV_TX_OFFLOAD_UDP_CKSUM | DEV_TX_OFFLOAD_TCP_CKSUM | DEV_TX_OFFLOAD_MULTI_SEGS),
	},
};

static const struct rte_eth_rxconf rx_conf = {
	.rx_thresh = {
		.pthresh = RX_PTHRESH, /* RX prefetch threshold reg */
		.hthresh = RX_HTHRESH, /* RX host threshold reg */
		.wthresh = RX_WTHRESH, /* RX write-back threshold reg */
	},
	.rx_free_thresh = 32,
};

static const struct rte_eth_txconf tx_conf = {
	.tx_thresh = {
		.pthresh = TX_PTHRESH, /* TX prefetch threshold reg */
		.hthresh = TX_HTHRESH, /* TX host threshold reg */
		.wthresh = TX_WTHRESH, /* TX write-back threshold reg */
	},
	.tx_free_thresh = 0, /* Use PMD default values */
	.tx_rs_thresh = 0,	 /* Use PMD default values */
};

struct mbuf_table
{
	uint16_t len; /* length of queued packets */
	uint16_t tail;
	uint16_t head;
	uint16_t unused;
	struct rte_mbuf *m_table[TX_QUEUE_NUM];
};

struct rmbuf_table
{
	uint16_t len; /* length of queued packets */
	uint16_t free_len;
	uint16_t last_access;
	// struct mtcp_zc_rmbuf *used_list;
	// struct mtcp_zc_rmbuf *free_list;
	struct mtcp_zc_rmbuf r_table[RX_QUEUE_NUM];
};

struct dpdk_private_context
{
	struct rmbuf_table rmbufs[HL_MAX_ETHPORTS];
	struct mbuf_table wmbufs[HL_MAX_ETHPORTS];
	struct rte_mempool *pktmbuf_pool;
	struct rte_mbuf *pkts_burst[MAX_RX_PKT_BURST];
#ifdef RX_IDLE_ENABLE
	uint8_t rx_idle;
#endif
#ifdef IP_DEFRAG
	struct rte_ip_frag_tbl *frag_tbl;
	struct rte_ip_frag_death_row death_row;
#endif
#ifdef ENABLELRO
	struct rte_mbuf *cur_rx_m;
#endif
#ifdef ENABLE_STATS_IOCTL
	int fd;
	uint32_t cur_ts;
#endif /* !ENABLE_STATS_IOCTL */
} __rte_cache_aligned;

#ifdef ENABLE_STATS_IOCTL
/**
 * stats struct passed on from user space to the driver
 */
struct stats_struct
{
	uint64_t tx_bytes;
	uint64_t tx_pkts;
	uint64_t rx_bytes;
	uint64_t rx_pkts;
	uint64_t rmiss;
	uint64_t rerr;
	uint64_t terr;
	uint8_t qid;
	uint8_t dev;
};
#endif /* !ENABLE_STATS_IOCTL */

#ifdef IP_DEFRAG
/* Should be power of two. */
#define IP_FRAG_TBL_BUCKET_ENTRIES 16
#define RTE_LOGTYPE_IP_RSMBL RTE_LOGTYPE_USER1
#define MAX_FRAG_NUM RTE_LIBRTE_IP_FRAG_MAX_FRAG
#endif /* !IP_DEFRAG */
/*----------------------------------------------------------------------------*/
void dpdk_init_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int j;
	char mempool_name[RTE_MEMPOOL_NAMESIZE];

	/* create and initialize private I/O module context */
	printf("dpdk_init_handle cpu (%d)\n", ctxt->cpu);
	ctxt->io_private_context = calloc(1, sizeof(struct dpdk_private_context));
	if (ctxt->io_private_context == NULL)
	{
		TRACE_ERROR("Failed to initialize ctxt->io_private_context: "
					"Can't allocate memory\n");
		exit(EXIT_FAILURE);
	}

	sprintf(mempool_name, "mbuf_pool-%d", ctxt->cpu);
	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	dpc->pktmbuf_pool = pktmbuf_pool[ctxt->cpu];

	/* set wmbufs correctly */
	for (j = 0; j < num_devices_attached; j++)
	{
/* Allocate wmbufs for each registered port */
#ifndef ZERO_COPY_VERSION
		for (i = 0; i < TX_QUEUE_NUM; i++)
		{
			dpc->wmbufs[j].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool[ctxt->cpu]);
			if (dpc->wmbufs[j].m_table[i] == NULL)
			{
				TRACE_ERROR("Failed to allocate %d:wmbuf[%d] on device %d!\n",
							ctxt->cpu, i, j);
				exit(EXIT_FAILURE);
			}
		}
#endif
		/* set mbufs queue length to 0 to begin with */
		dpc->wmbufs[j].len = 0;
		dpc->wmbufs[j].head = 0;
		dpc->wmbufs[j].tail = 0;
		dpc->wmbufs[j].unused = 0;

		dpc->rmbufs[j].len = 0;
		dpc->rmbufs[j].free_len = RX_QUEUE_NUM;
		dpc->rmbufs[j].last_access = 0;
		for (int k = 0; k < RX_QUEUE_NUM; k++)
		{
			dpc->rmbufs[j].r_table[k].free = 1;
			dpc->rmbufs[j].r_table[k].ori_mbuf = NULL;
		}
		// for (int k = 0; k < RX_QUEUE_NUM - 1; k++)
		// {
		// 	dpc->rmbufs[j].r_table[k].next = &dpc->rmbufs[j].r_table[k + 1];
		// }
		// dpc->rmbufs[j].r_table[RX_QUEUE_NUM - 1].next = NULL;
		// dpc->rmbufs[j].used_list = NULL;
		// dpc->rmbufs[j].free_list = &dpc->rmbufs[j].r_table[0];
	}

#ifdef IP_DEFRAG
	int max_flows;
	int socket;
	uint64_t frag_cycles;

	max_flows = CONFIG.max_concurrency / CONFIG.num_cores;
	frag_cycles = (rte_get_tsc_hz() + MS_PER_S - 1) / MS_PER_S * max_flows;
	socket = rte_lcore_to_socket_id(ctxt->cpu);

	if ((dpc->frag_tbl = rte_ip_frag_table_create(max_flows,
												  IP_FRAG_TBL_BUCKET_ENTRIES,
												  max_flows,
												  frag_cycles,
												  socket)) == NULL)
	{
		RTE_LOG(ERR, IP_RSMBL, "ip_frag_tbl_create(%u) on "
							   "lcore: %u for queue: %u failed\n",
				max_flows, ctxt->cpu, ctxt->cpu);
		exit(EXIT_FAILURE);
	}
#endif /* !IP_DEFRAG */

	// #ifdef ENABLE_STATS_IOCTL
	// 	dpc->fd = open(DEV_PATH, O_RDWR);
	// 	if (dpc->fd == -1)
	// 	{
	// 		TRACE_ERROR("Can't open " DEV_PATH " for context->cpu: %d! "
	// 					"Are you using mlx4/mlx5 driver?\n",
	// 					ctxt->cpu);
	// 	}
	// #endif /* !ENABLE_STATS_IOCTL */
}
/*----------------------------------------------------------------------------*/
int dpdk_link_devices(struct mtcp_thread_context *ctxt)
{
	/* linking takes place during mtcp_init() */

	return 0;
}
/*----------------------------------------------------------------------------*/
void dpdk_release_pkt(struct mtcp_thread_context *ctxt, int ifidx)
{
	/*
	 * do nothing over here - memory reclamation
	 * will take place in dpdk_recv_pkts
	 */

	// struct dpdk_private_context *dpc;
	// int tail, head;

	// dpc = (struct dpdk_private_context *)ctxt->io_private_context;

	// struct rmbuf_table *rmbufs = &dpc->rmbufs[ifidx];
	// struct mtcp_zc_rmbuf *prev, *q, *node;
	// q = rmbufs->used_list;
	// prev = NULL;
	// while (q != NULL)
	// {
	// 	if (q->free == 1)
	// 	{
	// 		rte_pktmbuf_free(q->ori_mbuf);
	// 		rmbufs->free_len++;
	// 		rmbufs->len--;
	// 		node = q;
	// 		q = q->next;
	// 		if (prev == NULL)
	// 		{
	// 			rmbufs->used_list = q;
	// 		}
	// 		else
	// 		{
	// 			prev->next = q;
	// 		}
	// 		node->next = rmbufs->free_list;
	// 		rmbufs->free_list = node;
	// 	}
	// 	else
	// 	{
	// 		prev = q;
	// 		q = q->next;
	// 	}
	// }
}
/*----------------------------------------------------------------------------*/
int dpdk_send_pkts(struct mtcp_thread_context *ctxt, int ifidx, int flag)
{
	struct dpdk_private_context *dpc;
	int ret, i, portid = CONFIG.eths[ifidx].ifindex;
	int head, cnt, try_count, tail, max_cnt;
	struct rte_mbuf **pkts;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	ret = 0;
	cnt = dpc->wmbufs[ifidx].len;
	// dpc->wmbufs[ifidx].unused = (dpc->wmbufs[ifidx].unused * 9 / 10 + cnt / 10);
	/* if there are packets in the queue... flush them out to the wire */
	if ((flag == FORCE_SEND && cnt > 0) || (flag == TRY_SEND && cnt >= MAX_PKT_BURST))
	{
		// unsigned long time = 0;
		// asm volatile("MRS %0, PMCCNTR_EL0" : "=r"(time));
		// printf("dpdk wirte (%ld)\n", time);

		head = dpc->wmbufs[ifidx].head;
		tail = dpc->wmbufs[ifidx].tail;

		// printf("send cnt(%d)\n", cnt);
		try_count = TRY_COUNT;

		while (head != tail && (flag == FORCE_SEND || try_count > 0))
		{
			// max_cnt = RET_MIN(RET_MIN(TX_QUEUE_NUM, head + cnt) - head,HL_PKT_BURST);
			max_cnt = RTE_MIN(TX_QUEUE_NUM, head + cnt) - head;
			// printf("max_cnt(%d) head(%d) cnt(%d) tail(%d) TX_QUEUE_NUM(%d)\n", max_cnt, head, cnt, tail, TX_QUEUE_NUM);
			cnt -= max_cnt;
			i = 0;
			pkts = dpc->wmbufs[ifidx].m_table;
			pkts += head;
			while (max_cnt > 0 && (flag == FORCE_SEND || try_count > 0))
			{
				/* tx max_cnt # of packets */
				ret = rte_eth_tx_burst(portid, ctxt->cpu, pkts, max_cnt);
				if (unlikely(ret < 0))
				{
					printf("!!!!!  rte_eth_tx_burst failed (ret < 0) \n\n\n\\n");
				}
				max_cnt -= ret;
				i += ret;
				pkts += ret;
				/* if not all pkts were sent... then repeat the cycle */
				try_count--;
			}
			head = (head + i) % TX_QUEUE_NUM;
			cnt += max_cnt;
		}
		tail = head;

		// tail is my send index in the wmbufs temporarily
		head = dpc->wmbufs[ifidx].head;
		for (i = head; i != tail; i = (i + 1) % TX_QUEUE_NUM)
		{
#ifdef ZERO_COPY_VERSION
			dpc->wmbufs[ifidx].m_table[i] = NULL;
#else
			dpc->wmbufs[ifidx].m_table[i] = rte_pktmbuf_alloc(pktmbuf_pool[ctxt->cpu]);
			if (unlikely(dpc->wmbufs[ifidx].m_table[i] == NULL))
			{
				TRACE_ERROR("Failed to allocate %d:wmbuf[%d] on device %d!\n",
							ctxt->cpu, i, ifidx);
				exit(EXIT_FAILURE);
			}
#endif
		}
		dpc->wmbufs[ifidx].head = tail;
		dpc->wmbufs[ifidx].len = (dpc->wmbufs[ifidx].tail + TX_QUEUE_NUM - tail) % TX_QUEUE_NUM;
		// printf("head(%d) tail(%d) len(%d)\n", dpc->wmbufs[ifidx].head, dpc->wmbufs[ifidx].tail, dpc->wmbufs[ifidx].len);
	}

	return ret;
}
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_wptr(struct mtcp_thread_context *ctxt, int ifidx, uint16_t pktsize)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	uint8_t *ptr;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	/* sanity check */
	// if (unlikely(dpc->wmbufs[ifidx].len == MAX_PKT_BURST))
	// {
	// 	printf("unlikely(dpc->wmbufs[ifidx].len == MAX_PKT_BURST HL_MAX_ETHPORTS(%d) num_devices_attached(%d) sanity check failed\n", HL_MAX_ETHPORTS, num_devices_attached);
	// 	return NULL;
	// }

	int len = dpc->wmbufs[ifidx].len;
	// printf("dpc->wmbufs[ifidx].tail (%d)) head(%d),len(%d), alpha(%d)\n", dpc->wmbufs[ifidx].tail, dpc->wmbufs[ifidx].head, dpc->wmbufs[ifidx].len, dpc->wmbufs[ifidx].unused);
	if (unlikely((dpc->wmbufs[ifidx].tail + 1) % TX_QUEUE_NUM == dpc->wmbufs[ifidx].head))
	{
		dpdk_send_pkts(ctxt, ifidx, FORCE_SEND);
		printf("dpc->wmbufs[ifidx].tail (%d)) head(%d),len(%d), alpha(%d)\n", dpc->wmbufs[ifidx].tail, dpc->wmbufs[ifidx].head, dpc->wmbufs[ifidx].len, dpc->wmbufs[ifidx].unused);
		return NULL;
	}

	int idx = dpc->wmbufs[ifidx].tail;
	dpc->wmbufs[ifidx].tail = (dpc->wmbufs[ifidx].tail + 1) % TX_QUEUE_NUM;
#ifdef ZERO_COPY_VERSION
	dpc->wmbufs[ifidx].m_table[idx] = rte_pktmbuf_alloc(pktmbuf_pool[ctxt->cpu]);
	if (unlikely(dpc->wmbufs[ifidx].m_table[idx] == NULL))
	{
		TRACE_ERROR("Failed to allocate %d:wmbuf[%d] on device %d!\n",
					ctxt->cpu, idx, ifidx);
		exit(EXIT_FAILURE);
	}
#endif
	m = dpc->wmbufs[ifidx].m_table[idx];

	/* retrieve the right write offset */
	ptr = (void *)rte_pktmbuf_mtod(m, struct ether_hdr *);
	m->pkt_len = m->data_len = pktsize;
	m->nb_segs = 1;
	m->next = NULL;

	/* increment the len_of_mbuf var */
	// dpc->wmbufs[ifidx].len = (dpc->wmbufs[ifidx].tail + TX_QUEUE_NUM - dpc->wmbufs[ifidx].head) % TX_QUEUE_NUM;
	dpc->wmbufs[ifidx].len = (len + 1) % TX_QUEUE_NUM;
	// printf("idx(%d)%p head(%d) tail(%d)\n", len, ptr, dpc->wmbufs[ifidx].head, dpc->wmbufs[ifidx].tail);

	return (uint8_t *)ptr;
}

int dpdk_put_wptr(struct mtcp_thread_context *ctxt, int ifidx, uint8_t *m)
{
	struct dpdk_private_context *dpc;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	/* sanity check */
	// if (unlikely(dpc->wmbufs[ifidx].len == MAX_PKT_BURST))
	// {
	// 	printf("unlikely(dpc->wmbufs[ifidx].len == MAX_PKT_BURST HL_MAX_ETHPORTS(%d) num_devices_attached(%d) sanity check failed\n", HL_MAX_ETHPORTS, num_devices_attached);
	// 	return NULL;
	// }

	int len = dpc->wmbufs[ifidx].len;
	if (unlikely((dpc->wmbufs[ifidx].tail + 1) % TX_QUEUE_NUM == dpc->wmbufs[ifidx].head))
	{
		dpdk_send_pkts(ctxt, ifidx, FORCE_SEND);
		// assert(0);
		printf("put dpc->wmbufs[ifidx].tail (%d)) head(%d),len(%d), alpha(%d)\n", dpc->wmbufs[ifidx].tail, dpc->wmbufs[ifidx].head, dpc->wmbufs[ifidx].len, dpc->wmbufs[ifidx].unused);
		return -1;
	}

	int idx = dpc->wmbufs[ifidx].tail;
	dpc->wmbufs[ifidx].tail = (dpc->wmbufs[ifidx].tail + 1) % TX_QUEUE_NUM;

	dpc->wmbufs[ifidx].m_table[idx] = (struct rte_mbuf *)m;
	rte_pktmbuf_refcnt_update((struct rte_mbuf *)m, 1);
	/* increment the len_of_mbuf var */
	// dpc->wmbufs[ifidx].len = (dpc->wmbufs[ifidx].tail + TX_QUEUE_NUM - dpc->wmbufs[ifidx].head) % TX_QUEUE_NUM;
	dpc->wmbufs[ifidx].len = (len + 1) % TX_QUEUE_NUM;
	return 0;
}

/*----------------------------------------------------------------------------*/
static inline void
free_pkts(struct rte_mbuf **mtable, unsigned len)
{
	int i;

	/* free the freaking packets */
	for (i = 0; i < len; i++)
	{
		rte_pktmbuf_free(mtable[i]);
		RTE_MBUF_PREFETCH_TO_FREE(mtable[i + 1]);
	}
}
/*----------------------------------------------------------------------------*/
// int32_t
// dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
// {
// 	struct dpdk_private_context *dpc;
// 	int ret;

// 	dpc = (struct dpdk_private_context *)ctxt->io_private_context;

// 	if (dpc->rmbufs[ifidx].len != 0)
// 	{
// 		free_pkts(dpc->rmbufs[ifidx].m_table, dpc->rmbufs[ifidx].len);
// 		dpc->rmbufs[ifidx].len = 0;
// 	}

// 	int portid = CONFIG.eths[ifidx].ifindex;
// 	ret = rte_eth_rx_burst((uint8_t)portid, ctxt->cpu,
// 						   dpc->pkts_burst, TX_QUEUE_NUM);
// #ifdef RX_IDLE_ENABLE
// 	dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;
// #endif
// 	dpc->rmbufs[ifidx].len = ret;

// 	return ret;
// }

#define RED "\x1B[31m"
#define RESET "\x1B[0m"
#define PRINT_ERROR(fmt, ...) \
	printf(RED "Error: " fmt RESET "\n", ##__VA_ARGS__)

int32_t
dpdk_recv_pkts(struct mtcp_thread_context *ctxt, int ifidx)
{
	struct dpdk_private_context *dpc;
	int ret;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;

	// int cnt = MAX_RX_PKT_BURST > dpc->rmbufs[ifidx].free_len ? dpc->rmbufs[ifidx].free_len : MAX_RX_PKT_BURST;
	// if (cnt < 10)
	// {
	// 	PRINT_ERROR("dpdk_recv_pkts cnt(%d) free_len(%d)\n", cnt, dpc->rmbufs[ifidx].free_len);
	// }
	int portid = CONFIG.eths[ifidx].ifindex;
	ret = rte_eth_rx_burst((uint8_t)portid, ctxt->cpu,
						   dpc->pkts_burst, MAX_RX_PKT_BURST);
#ifdef RX_IDLE_ENABLE
	dpc->rx_idle = (likely(ret != 0)) ? 0 : dpc->rx_idle + 1;
#endif
	// printf("dpdk_recv_pkts ret(%d) cnt(%d)\n", ret, cnt);
	return ret;
}
/*----------------------------------------------------------------------------*/
#ifdef IP_DEFRAG
struct rte_mbuf *
ip_reassemble(struct dpdk_private_context *dpc, struct rte_mbuf *m)
{
	struct ether_hdr *eth_hdr;
	struct rte_ip_frag_tbl *tbl;
	struct rte_ip_frag_death_row *dr;

	/* if packet is IPv4 */
	if (RTE_ETH_IS_IPV4_HDR(m->packet_type))
	{
		struct ipv4_hdr *ip_hdr;

		eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);
		ip_hdr = (struct ipv4_hdr *)(eth_hdr + 1);

		/* if it is a fragmented packet, then try to reassemble. */
		if (rte_ipv4_frag_pkt_is_fragmented(ip_hdr))
		{
			struct rte_mbuf *mo;

			tbl = dpc->frag_tbl;
			dr = &dpc->death_row;

			/* prepare mbuf: setup l2_len/l3_len. */
			m->l2_len = sizeof(*eth_hdr);
			m->l3_len = sizeof(*ip_hdr);

			/* process this fragment. */
			mo = rte_ipv4_frag_reassemble_packet(tbl, dr, m, rte_rdtsc(), ip_hdr);
			if (mo == NULL)
				/* no packet to send out. */
				return NULL;

			/* we have our packet reassembled. */
			if (mo != m)
				m = mo;
		}
	}

	/* if packet isn't IPv4, just accept it! */
	return m;
}
#endif
/*----------------------------------------------------------------------------*/
uint8_t *
dpdk_get_rptr(struct mtcp_thread_context *ctxt, int ifidx, int index, uint16_t *len)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	uint8_t *pktbuf;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;

	m = dpc->pkts_burst[index];
#ifdef IP_DEFRAG
	m = ip_reassemble(dpc, m);
#endif
	*len = m->pkt_len;
	pktbuf = rte_pktmbuf_mtod(m, uint8_t *);
	if (pktbuf == NULL)
	{
		return NULL;
	}

	/* enqueue the pkt ptr in mbuf */
	// if (unlikely(dpc->rmbufs[ifidx].free_len <= 0))
	// {
	// 	PRINT_ERROR("dpdk_get_rptr free_len(%d) ifidx(%d) index(%d)\n", dpc->rmbufs[ifidx].free_len, ifidx, index);
	// 	return NULL;
	// }
	int idx = dpc->rmbufs[ifidx].last_access;
	struct mtcp_zc_rmbuf *node = NULL;
	int i = idx;

	do
	{
		if (dpc->rmbufs[ifidx].r_table[i].free == 1)
		{
			if (dpc->rmbufs[ifidx].r_table[i].ori_mbuf != NULL)
			{
				rte_pktmbuf_free(dpc->rmbufs[ifidx].r_table[i].ori_mbuf);
			}
			node = &dpc->rmbufs[ifidx].r_table[i];
			dpc->rmbufs[ifidx].last_access = (i + 1) % RX_QUEUE_NUM;
			break;
		}
		i = (i + 1) % RX_QUEUE_NUM;
	} while (i != idx);

	// struct mtcp_zc_rmbuf *node = dpc->rmbufs[ifidx].free_list;
	// dpc->rmbufs[ifidx].free_list = node->next;
	// dpc->rmbufs[ifidx].free_len--;
	// dpc->rmbufs[ifidx].len++;
	if (node == NULL)
	{
		PRINT_ERROR("dpdk_get_rptr node is NULL\n");
		return NULL;
	}

	node->ori_mbuf = m;
	node->bsd_mbuf = pktbuf;
	node->len = *len;
	node->off = 0;
	node->free = 1;

	// node->next = dpc->rmbufs[ifidx].used_list;
	// dpc->rmbufs[ifidx].used_list = node;

	/* verify checksum values from ol_flags */
	if ((m->ol_flags & (RTE_MBUF_F_RX_L4_CKSUM_BAD | RTE_MBUF_F_RX_IP_CKSUM_BAD)) != 0)
	{
		TRACE_ERROR("%s(%p, %d, %d): mbuf with invalid checksum: "
					"%p(%lu);\n",
					__func__, ctxt, ifidx, index, m, m->ol_flags);
		pktbuf = NULL;
	}
#ifdef ENABLELRO
	dpc->cur_rx_m = m;
#endif

	return (uint8_t *)node;
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_select(struct mtcp_thread_context *ctxt)
{
#ifdef RX_IDLE_ENABLE
	struct dpdk_private_context *dpc;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;
	if (dpc->rx_idle > RX_IDLE_THRESH)
	{
		dpc->rx_idle = 0;
		usleep(RX_IDLE_TIMEOUT);
	}
#endif
	return 0;
}
/*----------------------------------------------------------------------------*/
void dpdk_destroy_handle(struct mtcp_thread_context *ctxt)
{
	struct dpdk_private_context *dpc;
	int i;

	dpc = (struct dpdk_private_context *)ctxt->io_private_context;

	/* free wmbufs */
	for (i = 0; i < num_devices_attached; i++)
		free_pkts(dpc->wmbufs[i].m_table, TX_QUEUE_NUM);

#ifdef ENABLE_STATS_IOCTL
	/* free fd */
	if (dpc->fd >= 0)
		close(dpc->fd);
#endif /* !ENABLE_STATS_IOCTL */

	/* free it all up */
	free(dpc);
}
/*----------------------------------------------------------------------------*/
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */

	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	printf("\nChecking link status");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++)
	{
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++)
		{
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1)
			{
				if (link.link_status)
					printf("Port %d Link Up - speed %u "
						   "Mbps - %s\n",
						   (uint8_t)portid,
						   (unsigned)link.link_speed,
						   (link.link_duplex == ETH_LINK_FULL_DUPLEX) ? ("full-duplex") : ("half-duplex\n"));
				else
					printf("Port %d Link Down\n",
						   (uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0)
			{
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0)
		{
			printf(".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
		{
			print_flag = 1;
			printf("done\n");
		}
	}
}
/*----------------------------------------------------------------------------*/
void dpdk_load_module(void)
{
	int portid, rxlcore_id, ret;
	/* for Ethernet flow control settings */
	struct rte_eth_fc_conf fc_conf;
	/* setting the rss key */
	// static uint8_t key[] = {
	// 	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 10 */
	// 	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 20 */
	// 	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 30 */
	// 	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 40 */
	// 	0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, /* 50 */
	// 	0x05, 0x05													/* 60 - 8 */
	// };

	static uint8_t key[] = {
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a, 0x6d, 0x5a,
		0x6d, 0x5a, 0x6d, 0x5a};
	port_conf.rx_adv_conf.rss_conf.rss_key = (uint8_t *)key;
	port_conf.rx_adv_conf.rss_conf.rss_key_len = sizeof(key);

	if (!CONFIG.multi_process || (CONFIG.multi_process && CONFIG.multi_process_is_master))
	{
		for (rxlcore_id = 0; rxlcore_id < CONFIG.num_cores; rxlcore_id++)
		{
			char name[RTE_MEMPOOL_NAMESIZE];
			uint32_t nb_mbuf;
			sprintf(name, "mbuf_pool-%d", rxlcore_id);
			nb_mbuf = NB_MBUF;
#ifdef IP_DEFRAG
			int max_flows;
			max_flows = CONFIG.max_concurrency / CONFIG.num_cores;

			/*
			 * At any given moment up to <max_flows * (MAX_FRAG_NUM)>
			 * mbufs could be stored int the fragment table.
			 * Plus, each TX queue can hold up to <max_flows> packets.
			 */

			nb_mbuf = RTE_MAX(max_flows, 2UL * RX_QUEUE_NUM) * MAX_FRAG_NUM;
			nb_mbuf *= (port_conf.rxmode.max_rx_pkt_len + BUF_SIZE - 1) / BUF_SIZE;
			nb_mbuf += RTE_TEST_RX_DESC_DEFAULT + RTE_TEST_TX_DESC_DEFAULT;

			nb_mbuf = RTE_MAX(nb_mbuf, (uint32_t)NB_MBUF);
#endif
			/* create the mbuf pools */
			pktmbuf_pool[rxlcore_id] =
				rte_mempool_create(name, nb_mbuf,
								   MBUF_SIZE * 4, 64,
								   sizeof(struct rte_pktmbuf_pool_private),
								   rte_pktmbuf_pool_init, NULL,
								   rte_pktmbuf_init, NULL,
								   SOCKET_ID_ANY, MEMPOOL_F_SP_PUT | MEMPOOL_F_SC_GET);

			if (pktmbuf_pool[rxlcore_id] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool, errno: %d\n",
						 rte_errno);
		}

		/* Initialise each port */
		int i;
		for (i = 0; i < num_devices_attached; ++i)
		{
			/* get portid form the index of attached devices */
			portid = devices_attached[i];

			/* check port capabilities */
			rte_eth_dev_info_get(portid, &dev_info[portid]);
			/* re-adjust rss_hf */
			port_conf.rx_adv_conf.rss_conf.rss_hf &= dev_info[portid].flow_type_rss_offloads;

			if (dev_info[portid].rx_offload_capa & DEV_RX_OFFLOAD_TCP_LRO)
			{
				printf("NIC supports LRO\n");
			}
			else
			{
				printf("NIC does not support LRO\n");
			}

			/* init port */
			printf("Initializing port %u... \n", (unsigned)portid);
			printf("Device name: %s\n", dev_info[portid].device->name);
			fflush(stdout);
			// if (!strncmp(dev_info[portid].driver_name, "net_mlx", 7))
			// 	port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;

			printf("try check driver type %s\n", dev_info[portid].driver_name);
			fflush(stdout);
			if (!strncmp(dev_info[portid].driver_name, "mlx5_pci", 8))
			{
				port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;
			}
			// !!! patch for enp3s0f0s0
			port_conf.rx_adv_conf.rss_conf.rss_key_len = 40;

			printf("try rte_eth_dev_configure\n");
			fflush(stdout);

			ret = rte_eth_dev_configure(portid, CONFIG.num_cores, CONFIG.num_cores, &port_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "Cannot configure device: err=%d, port=%u, cores: %d\n",
						 ret, (unsigned)portid, CONFIG.num_cores);

			/* init one RX queue per CPU */
			fflush(stdout);
#ifdef DEBUG
			rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
#endif
			printf("try rte_eth_rx_queue_setup q_num %d\n", CONFIG.num_cores);
			fflush(stdout);
			for (rxlcore_id = 0; rxlcore_id < CONFIG.num_cores; rxlcore_id++)
			{
				ret = rte_eth_rx_queue_setup(portid, rxlcore_id, nb_rxd,
											 rte_eth_dev_socket_id(portid), &rx_conf,
											 pktmbuf_pool[rxlcore_id]);
				if (ret < 0)
					rte_exit(EXIT_FAILURE,
							 "rte_eth_rx_queue_setup:err=%d, port=%u, queueid: %d\n",
							 ret, (unsigned)portid, rxlcore_id);
			}

			/* init one TX queue on each port per CPU (this is redundant for this app) */
			printf("try rte_eth_tx_queue_setup q_num %d\n", CONFIG.num_cores);
			fflush(stdout);
			for (rxlcore_id = 0; rxlcore_id < CONFIG.num_cores; rxlcore_id++)
			{
				ret = rte_eth_tx_queue_setup(portid, rxlcore_id, nb_txd,
											 rte_eth_dev_socket_id(portid), &tx_conf);
				if (ret < 0)
					rte_exit(EXIT_FAILURE,
							 "rte_eth_tx_queue_setup:err=%d, port=%u, queueid: %d\n",
							 ret, (unsigned)portid, rxlcore_id);
			}

			/* Start device */
			ret = rte_eth_dev_start(portid);
			if (ret < 0)
				rte_exit(EXIT_FAILURE, "rte_eth_dev_start:err=%d, port=%u\n",
						 ret, (unsigned)portid);

			printf("done: \n");
			rte_eth_promiscuous_enable(portid);

			/* retrieve current flow control settings per port */
			memset(&fc_conf, 0, sizeof(fc_conf));
			ret = rte_eth_dev_flow_ctrl_get(portid, &fc_conf);
			if (ret != 0)
				TRACE_INFO("Failed to get flow control info!\n");

			/* and just disable the rx/tx flow control */
			fc_conf.mode = RTE_FC_NONE;
			ret = rte_eth_dev_flow_ctrl_set(portid, &fc_conf);
			if (ret != 0)
				TRACE_INFO("Failed to set flow control info!: errno: %d\n",
						   ret);

#ifdef DEBUG
			printf("Port %u, MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
				   (unsigned)portid,
				   ports_eth_addr[portid].addr_bytes[0],
				   ports_eth_addr[portid].addr_bytes[1],
				   ports_eth_addr[portid].addr_bytes[2],
				   ports_eth_addr[portid].addr_bytes[3],
				   ports_eth_addr[portid].addr_bytes[4],
				   ports_eth_addr[portid].addr_bytes[5]);
#endif
		}
		/* only check for link status if the thread is master */
		check_all_ports_link_status(num_devices_attached, 0xFFFFFFFF);
	}
	else
	{ /* CONFIG.multi_process && !CONFIG.multi_process_is_master */
		for (rxlcore_id = 0; rxlcore_id < CONFIG.num_cores; rxlcore_id++)
		{
			char name[RTE_MEMPOOL_NAMESIZE];
			sprintf(name, "mbuf_pool-%d", rxlcore_id);
			/* initialize the mbuf pools */
			pktmbuf_pool[rxlcore_id] = rte_mempool_lookup(name);
			if (pktmbuf_pool[rxlcore_id] == NULL)
				rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");
		}

		int i;
		/* initializing dev_info struct */
		for (i = 0; i < num_devices_attached; i++)
		{
			/* get portid form the index of attached devices */
			portid = devices_attached[i];
			/* check port capabilities */
			rte_eth_dev_info_get(i, &dev_info[portid]);
		}
	}
}
/*----------------------------------------------------------------------------*/
int32_t
dpdk_dev_ioctl(struct mtcp_thread_context *ctx, int nif, int cmd, void *argp)
{
	struct dpdk_private_context *dpc;
	struct rte_mbuf *m;
	struct iphdr *iph;
	struct tcphdr *tcph;
	void **argpptr = (void **)argp;
	// printf("[+] in dpdk_dev_ioctl cmd(%#x)\n", cmd);
	if (cmd == DRV_NAME)
	{
		*argpptr = (void *)dev_info[nif].driver_name;
		return 0;
	}

	int eidx = CONFIG.nif_to_eidx[nif];

	iph = (struct iphdr *)argp;
	dpc = (struct dpdk_private_context *)ctx->io_private_context;
	int idx = (dpc->wmbufs[eidx].tail - 1 + TX_QUEUE_NUM) % TX_QUEUE_NUM;

	switch (cmd)
	{
	case PKT_TX_IP_CSUM:
		if ((dev_info[nif].tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) == 0)
		{
			printf("[+] ERROR:: don't support tx offload\n");
			goto dev_ioctl_err;
		}

		m = dpc->wmbufs[eidx].m_table[idx];
		m->ol_flags = RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
		m->l2_len = sizeof(struct rte_ether_hdr);

		m->l3_len = (iph->ihl << 2);
		// TODO!!!  iph->hdr_checksum = rte_ipv4_cksum(iph);
		break;
	case PKT_TX_TCP_CSUM:
		if ((dev_info[nif].tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) == 0)
			goto dev_ioctl_err;
		m = dpc->wmbufs[eidx].m_table[idx];
		tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl << 2));
		m->ol_flags |= RTE_MBUF_F_TX_TCP_CKSUM;

		// printf("[+] offload chsum\n");
		tcph->check = rte_ipv4_phdr_cksum((struct rte_ipv4_hdr *)iph, m->ol_flags);

		break;
	case PKT_TX_TCPIP_CSUM:
		if ((dev_info[nif].tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) == 0)
			goto dev_ioctl_err;
		if ((dev_info[nif].tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) == 0)
			goto dev_ioctl_err;
		m = dpc->wmbufs[eidx].m_table[idx];

		iph = rte_pktmbuf_mtod_offset(m, struct iphdr *, sizeof(struct rte_ether_hdr));
		tcph = (struct tcphdr *)((uint8_t *)iph + (iph->ihl << 2));
		m->l2_len = sizeof(struct rte_ether_hdr);
		m->l3_len = (iph->ihl << 2);
		m->l4_len = (tcph->doff << 2);
		m->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;

		tcph->check = rte_ipv4_phdr_cksum((struct rte_ipv4_hdr *)iph, m->ol_flags);
		break;
	case PKT_RX_IP_CSUM:
		if ((dev_info[nif].rx_offload_capa & DEV_RX_OFFLOAD_IPV4_CKSUM) == 0)
			goto dev_ioctl_err;
		break;
	case PKT_RX_TCP_CSUM:
		if ((dev_info[nif].rx_offload_capa & DEV_RX_OFFLOAD_TCP_CKSUM) == 0)
			goto dev_ioctl_err;
		break;
	case PKT_TX_TCPIP_CSUM_PEEK:
		if ((dev_info[nif].tx_offload_capa & DEV_TX_OFFLOAD_IPV4_CKSUM) == 0)
		{
			printf("[+] ERROR:: don't support tx offload DEV_TX_OFFLOAD_IPV4_CKSUM\n");
			goto dev_ioctl_err;
		}
		if ((dev_info[nif].tx_offload_capa & DEV_TX_OFFLOAD_TCP_CKSUM) == 0)
		{
			printf("[+] ERROR:: don't support tx offload DEV_TX_OFFLOAD_TCP_CKSUM\n");
			goto dev_ioctl_err;
		}
		break;
	default:
		goto dev_ioctl_err;
	}
	return 0;
dev_ioctl_err:
	return -1;
}

// PKT_TX_TCPIP_CSUM
int32_t
dpdk_dev_chk_offload(struct mtcp_thread_context *ctx, void *mbuf, uint16_t l4len)
{
	struct rte_mbuf *m = (struct rte_mbuf *)mbuf;
	struct iphdr *iph;
	struct tcphdr *tcph;
	iph = rte_pktmbuf_mtod_offset(m, struct iphdr *, sizeof(struct rte_ether_hdr));
	tcph = (struct tcphdr *)((uint8_t *)iph + IP_HEADER_LEN);
	m->l2_len = sizeof(struct rte_ether_hdr);
	m->l3_len = IP_HEADER_LEN;
	m->l4_len = l4len;
	m->ol_flags = RTE_MBUF_F_TX_TCP_CKSUM | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_IPV4;
	tcph->check = rte_ipv4_phdr_cksum((struct rte_ipv4_hdr *)iph, m->ol_flags);
	return 0;
}
/*----------------------------------------------------------------------------*/
io_module_func dpdk_module_func = {
	.load_module = dpdk_load_module,
	.init_handle = dpdk_init_handle,
	.link_devices = dpdk_link_devices,
	.release_pkt = dpdk_release_pkt,
	.send_pkts = dpdk_send_pkts,
	.get_wptr = dpdk_get_wptr,
	.put_wptr = dpdk_put_wptr,
	.recv_pkts = dpdk_recv_pkts,
	.get_rptr = dpdk_get_rptr,
	.select = dpdk_select,
	.destroy_handle = dpdk_destroy_handle,
	.dev_ioctl = dpdk_dev_ioctl,
	.dev_chk_offload = dpdk_dev_chk_offload};
/*----------------------------------------------------------------------------*/
#else
io_module_func dpdk_module_func = {
	.load_module = NULL,
	.init_handle = NULL,
	.link_devices = NULL,
	.release_pkt = NULL,
	.send_pkts = NULL,
	.get_wptr = NULL,
	.put_wptr = NULL,
	.recv_pkts = NULL,
	.get_rptr = NULL,
	.select = NULL,
	.destroy_handle = NULL,
	.dev_ioctl = NULL};
/*----------------------------------------------------------------------------*/
#endif /* !DISABLE_DPDK */
