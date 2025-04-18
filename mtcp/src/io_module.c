/* for I/O module def'ns */
#include "io_module.h"
/* for num_devices decl */
#include "config.h"
/* std lib funcs */
#include <stdlib.h>
/* std io funcs */
#include <stdio.h>
/* strcmp func etc. */
#include <string.h>
/* for ifreq struct */
#include <net/if.h>
/* for ioctl */
#include <sys/ioctl.h>
#ifndef DISABLE_DPDK

#define RTE_ARGC_MAX (HL_MAX_ETHPORTS << 1) + 9
/* for dpdk ethernet functions (get mac addresses) */
#include <rte_ethdev.h>
/* for ceil func */
#include <math.h>
/* for retrieving rte version(s) */
#include <rte_version.h>
#endif /* DISABLE_DPDK */
/* for TRACE_* */
#include "debug.h"
/* for inet_* */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
/* for getopt() */
#include <unistd.h>
/* for getifaddrs */
#include <sys/types.h>
#include <ifaddrs.h>
/* for file opening */
#include <sys/stat.h>
#include <fcntl.h>

/*----------------------------------------------------------------------------*/
io_module_func *current_iomodule_func = &dpdk_module_func;
#ifndef DISABLE_DPDK
enum rte_proc_type_t rte_eal_process_type(void);
/**
 * DPDK's RTE consumes some huge pages for internal bookkeeping.
 * Therefore, it is not always safe to reserve the exact amount
 * of pages for our stack (e.g. dividing requested mem, in MB, by
 * (1<<20) would be insufficient). Hence, the following value.
 */
#define RTE_SOCKET_MEM_SHIFT ((1 << 19) | (1 << 18))
#endif
/*----------------------------------------------------------------------------*/
#define ALL_STRING "all"
#define MAX_PROCLINE_LEN 1024
#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))
/*----------------------------------------------------------------------------*/

/* onvm struct for port info lookup */
extern struct port_info *ports;

#ifndef DISABLE_PSIO
static int
GetNumQueues()
{
	FILE *fp;
	char buf[MAX_PROCLINE_LEN];
	int queue_cnt;

	fp = fopen("/proc/interrupts", "r");
	if (!fp)
	{
		TRACE_CONFIG("Failed to read data from /proc/interrupts!\n");
		return -1;
	}

	/* count number of NIC queues from /proc/interrupts */
	queue_cnt = 0;
	while (!feof(fp))
	{
		if (fgets(buf, MAX_PROCLINE_LEN, fp) == NULL)
			break;

		/* "xge0-rx" is the keyword for counting queues */
		if (strstr(buf, "xge0-rx"))
		{
			queue_cnt++;
		}
	}
	fclose(fp);

	return queue_cnt;
}
#endif /* !PSIO */



int SetNetEnv(char *dev_name_list, char *port_stat_list)
{
	int eidx = 0;
	int i, j;

	int set_all_inf = (strncmp(dev_name_list, ALL_STRING, sizeof(ALL_STRING)) == 0);

	TRACE_CONFIG("Loading interface setting\n");

	CONFIG.eths = (struct eth_table *)calloc(MAX_DEVICES, sizeof(struct eth_table));
	if (!CONFIG.eths)
	{
		TRACE_ERROR("Can't allocate space for CONFIG.eths\n");
		exit(EXIT_FAILURE);
	}
	if (current_iomodule_func == &dpdk_module_func)
	{
#ifndef DISABLE_DPDK
		int cpu = CONFIG.num_cores;
		mpz_t _cpumask;
		char cpumaskbuf[32] = "";
		char mem_channels[8] = "";
		char socket_mem_str[32] = "";
		// int i;
		int ret, socket_mem;
		static struct rte_ether_addr ports_eth_addr[HL_MAX_ETHPORTS];


		/* STEP 1: first determine CPU mask */
		mpz_init(_cpumask);

		if (!mpz_cmp(_cpumask, CONFIG._cpumask))
		{
			/* get the cpu mask */
			for (ret = 0; ret < cpu; ret++)
				mpz_setbit(_cpumask, ret);

			gmp_sprintf(cpumaskbuf, "%ZX", _cpumask);
		}
		else
			gmp_sprintf(cpumaskbuf, "%ZX", CONFIG._cpumask);

		mpz_clear(_cpumask);

		/* STEP 2: determine memory channels per socket */
		/* get the mem channels per socket */
		if (CONFIG.num_mem_ch == 0)
		{
			TRACE_ERROR("DPDK module requires # of memory channels "
						"per socket parameter!\n");
			exit(EXIT_FAILURE);
		}
		sprintf(mem_channels, "%d", CONFIG.num_mem_ch);

		/* STEP 3: determine socket memory */
		/* get socket memory threshold (in MB) */
		socket_mem =
			RTE_ALIGN_CEIL((unsigned long)ceil((CONFIG.num_cores *
												(CONFIG.rcvbuf_size +
												 CONFIG.sndbuf_size +
												 sizeof(struct tcp_stream) +
												 sizeof(struct tcp_recv_vars) +
												 sizeof(struct tcp_send_vars) +
												 sizeof(struct fragment_ctx)) *
												CONFIG.max_concurrency) /
											   RTE_SOCKET_MEM_SHIFT),
						   RTE_CACHE_LINE_SIZE);

		/* initialize the rte env, what a waste of implementation effort! */
		int argc = 6; // 8;
		char *argv[RTE_ARGC_MAX] = {"",
									"-c",
									cpumaskbuf,
									"-n",
									mem_channels,
#if 0
					    "--socket-mem",
					    socket_mem_str,
#endif
									"--proc-type=auto"};
		// ret = probe_all_rte_devices(argv, &argc, dev_name_list);

		/* STEP 4: build up socket mem parameter */
		sprintf(socket_mem_str, "%d", socket_mem);
#if 0
		char *smsptr = socket_mem_str + strlen(socket_mem_str);
		for (i = 1; i < ret + 1; i++) {
			sprintf(smsptr, ",%d", socket_mem);
			smsptr += strlen(smsptr);
		}
		TRACE_DBG("socket_mem: %s\n", socket_mem_str);
#endif
		/*
		 * re-set getopt extern variable optind.
		 * this issue was a bitch to debug
		 * rte_eal_init() internally uses getopt() syscall
		 * mtcp applications that also use an `external' getopt
		 * will cause a violent crash if optind is not reset to zero
		 * prior to calling the func below...
		 * see man getopt(3) for more details
		 */
		optind = 0;

#ifdef DEBUG
		/* print argv's */
		for (i = 0; i < argc; i++)
			TRACE_INFO("argv[%d]: %s\n", i, argv[i]);
#endif
		/* initialize the dpdk eal env */
		ret = rte_eal_init(argc, argv);
		if (ret < 0)
		{
			TRACE_ERROR("Invalid EAL args!\n");
			exit(EXIT_FAILURE);
		}
		/* give me the count of 'detected' ethernet ports */

		num_devices = rte_eth_dev_count_avail();
		if (num_devices == 0)
		{
			TRACE_ERROR("No Ethernet port!\n");
			exit(EXIT_FAILURE);
		}

		/* get mac addr entries of 'detected' dpdk ports */
		for (ret = 0; ret < num_devices; ret++){
			rte_eth_macaddr_get(ret, &ports_eth_addr[ret]);
			char buf[RTE_ETHER_ADDR_FMT_SIZE];
			rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, &ports_eth_addr[ret]);
			printf("idx %d: %s\n",ret, buf);
		}

		num_queues = MIN(CONFIG.num_cores, MAX_CPUS);

		struct ifaddrs *ifap;
		struct ifaddrs *iter_if;
		char *seek;

		if (getifaddrs(&ifap) != 0)
		{
			perror("getifaddrs: ");
			exit(EXIT_FAILURE);
		}

		iter_if = ifap;
		do
		{
			if (iter_if->ifa_addr && iter_if->ifa_addr->sa_family == AF_INET &&
				!set_all_inf &&
				(seek = strstr(dev_name_list, iter_if->ifa_name)) != NULL &&
				/* check if the interface was not aliased */
				*(seek + strlen(iter_if->ifa_name)) != ':')
			{
				struct ifreq ifr;

				/* Setting informations */
				eidx = CONFIG.eths_num++;
				strcpy(CONFIG.eths[eidx].dev_name, iter_if->ifa_name);
				strcpy(ifr.ifr_name, iter_if->ifa_name);

				/* Create socket */
				int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
				if (sock == -1)
				{
					perror("socket");
					exit(EXIT_FAILURE);
				}

				/* getting address */
				if (ioctl(sock, SIOCGIFADDR, &ifr) == 0)
				{
					struct in_addr sin = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
					CONFIG.eths[eidx].ip_addr = *(uint32_t *)&sin;
				}

				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0)
				{
					for (j = 0; j < ETH_ALEN; j++)
					{
						CONFIG.eths[eidx].haddr[j] = ifr.ifr_addr.sa_data[j];
					}
				}

				/* Net MASK */
				if (ioctl(sock, SIOCGIFNETMASK, &ifr) == 0)
				{
					struct in_addr sin = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr;
					CONFIG.eths[eidx].netmask = *(uint32_t *)&sin;
				}
				close(sock);

				for (j = 0; j < num_devices; j++)
				{
					if (!memcmp(&CONFIG.eths[eidx].haddr[0], &ports_eth_addr[j],
								ETH_ALEN))
						CONFIG.eths[eidx].ifindex = j;
				}

				/* add to attached devices */
				for (j = 0; j < num_devices_attached; j++)
				{
					if (devices_attached[j] == CONFIG.eths[eidx].ifindex)
					{
						break;
					}
				}
				devices_attached[num_devices_attached] = CONFIG.eths[eidx].ifindex;
				num_devices_attached++;

				fprintf(stderr, "Total number of attached devices: %d\n",
						num_devices_attached);
				fprintf(stderr, "Interface name: %s portid %d\n",
						iter_if->ifa_name, CONFIG.eths[eidx].ifindex);
			}
			iter_if = iter_if->ifa_next;
		} while (iter_if != NULL);

		freeifaddrs(ifap);
#if 0
		/*
		 * XXX: It seems that there is a bug in the RTE SDK.
		 * The dynamically allocated rte_argv params are left 
		 * as dangling pointers. Freeing them causes program
		 * to crash.
		 */
		
		/* free up all resources */
		for (; rte_argc >= 9; rte_argc--) {
			if (rte_argv[rte_argc] != NULL) {
				fprintf(stderr, "Cleaning up rte_argv[%d]: %s (%p)\n",
					rte_argc, rte_argv[rte_argc], rte_argv[rte_argc]);
				free(rte_argv[rte_argc]);
				rte_argv[rte_argc] = NULL;
			}
		}
#endif
		/* check if process is primary or secondary */
		CONFIG.multi_process_is_master = (rte_eal_process_type() == RTE_PROC_PRIMARY) ? 1 : 0;

#endif /* !DISABLE_DPDK */
	}
	CONFIG.nif_to_eidx = (int *)calloc(MAX_DEVICES, sizeof(int));

	if (!CONFIG.nif_to_eidx)
	{
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < MAX_DEVICES; ++i)
	{
		CONFIG.nif_to_eidx[i] = -1;
	}

	for (i = 0; i < CONFIG.eths_num; ++i)
	{

		j = CONFIG.eths[i].ifindex;
		if (j >= MAX_DEVICES)
		{
			TRACE_ERROR("ifindex of eths_%d exceed the limit: %d\n", i, j);
			exit(EXIT_FAILURE);
		}

		/* the physic port index of the i-th port listed in the config file is j*/
		CONFIG.nif_to_eidx[j] = i;

		/* finally set the port stats option `on' */
		if (strstr(port_stat_list, CONFIG.eths[i].dev_name) != 0)
			CONFIG.eths[i].stat_print = TRUE;
	}

	return 0;
}
/*----------------------------------------------------------------------------*/
int FetchEndianType()
{
#ifndef DISABLE_DPDK
	char *argv;
	char **argp = &argv;
	/* dpdk_module_func/onvm_module_func logic down below */
	if (current_iomodule_func == &dpdk_module_func)
	{
		(*current_iomodule_func).dev_ioctl(NULL, CONFIG.eths[0].ifindex, DRV_NAME, (void *)argp);
		if (!strcmp(*argp, "net_i40e"))
			return 1;
	}
#endif
	return 0;
}