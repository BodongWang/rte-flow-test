/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2021 Nvidia
 */

#include <sys/resource.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/cdefs.h>
#include <stdio.h>
#include <signal.h>
#include <malloc.h>

#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_mbuf.h>
#include <rte_flow.h>
#include <rte_hash.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ring_elem.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define RTE_PORT_ALL	(~(uint16_t)0x0)

#define RX_RING_SIZE	1024
#define TX_RING_SIZE	1024
#define BURST_SIZE	32

#define MAX_LCORES	(16u)
#define MAX_DPDK_PORT	(4u)
#define NUM_PHY_PORT	(2u)
#define NUM_VF_PORT	(2u)

#define MAX_PATTERN_NUM	(2u)
#define MAX_ACTION_NUM	(3u)

#define NUM_REGULAR_Q	(1)
#define NUM_HP_Q	(1)

static struct rte_flow_item eth_item = {
	RTE_FLOW_ITEM_TYPE_ETH,
	0, 0, 0
};

static struct rte_flow_item end_item = {
	RTE_FLOW_ITEM_TYPE_END,
	0, 0, 0
};

struct rte_flow_action_jump nic_rx_group = {
	.group = 2,
};

static struct rte_flow_action jump_action = {
	RTE_FLOW_ACTION_TYPE_JUMP,
	&nic_rx_group
};

static struct rte_flow_action drop_action = {
	RTE_FLOW_ACTION_TYPE_DROP,
};

static struct rte_flow_action end_action = {
	RTE_FLOW_ACTION_TYPE_END,
	0
};

static struct rte_flow_item_ipv4 ipv4_mask = {
	.hdr.next_proto_id = 0xFF,
	.hdr.src_addr = 0xFFFFFFFF,
	.hdr.dst_addr = 0xFFFFFFFF,
};

static struct rte_flow_item_tcp tcp_mask = {
	.hdr.src_port = 0xFFFF,
	.hdr.dst_port = 0xFFFF,
	.hdr.tcp_flags = 0
};

int offload_flow_test(uint16_t port_id, uint32_t num);
int port_init(uint16_t pid, struct rte_mempool *mbuf_pool);

int port_init(uint16_t pid, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		},
	};
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_dev *eth_dev;
	struct rte_port *port;
	int retval;
	uint16_t q;
	int nb_rxq = 1, nb_hpq = 0, nb_txq = 1;
	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;

	if (!rte_eth_dev_is_valid_port(pid))
		return -EINVAL;

	eth_dev = &rte_eth_devices[pid];

	rte_eth_dev_info_get(pid, &dev_info);
	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(pid, nb_rxq + nb_hpq,
				       nb_txq + nb_hpq, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(pid, &nb_rxd,
						  &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet pid. */
	for (q = 0; q < nb_rxq; q++) {
		retval = rte_eth_rx_queue_setup(pid, q, nb_rxd,
				rte_eth_dev_socket_id(pid), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet pid. */
	for (q = 0; q < nb_txq; q++) {
		retval = rte_eth_tx_queue_setup(pid, q, nb_txd,
				rte_eth_dev_socket_id(pid), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Start the Ethernet pid. */
	retval = rte_eth_dev_start(pid);
	if (retval < 0) {
		printf("Can't start eth dev %d\n", pid);
		return retval;
	}

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(pid);
	if (retval != 0)
		return retval;

	return 0;
}

int offload_flow_test(uint16_t port_id, uint32_t num)
{
#define MAX_FLOW_ITEM (6)
#define MAX_ACTION_ITEM (6)
	struct rte_flow_item flow_pattern[MAX_FLOW_ITEM];
	struct rte_flow_action actions[MAX_ACTION_ITEM];
	struct rte_flow_action_age age = {};
	struct rte_flow_item_ipv4 ipv4_spec;
	struct rte_flow_item ip_item;
	struct rte_flow_item_tcp tcp_spec;
	struct rte_flow_item tcp_item;
	enum rte_flow_item_type ip_type;
	void *ip_spec, *ip_mask;
	int i = 0, flow_index = 0;
	struct rte_flow **flows;

	struct rte_flow_attr attr = {
		.ingress = 1,
		.transfer = 1,
		.group = 1
	};

	struct rte_flow_action age_action = {
		RTE_FLOW_ACTION_TYPE_AGE,
		&age
	};

	memset(&flow_pattern, 0, sizeof(flow_pattern));

	/* Eth item*/
	flow_pattern[flow_index++] = eth_item;

	/* IP item */
	ip_type = RTE_FLOW_ITEM_TYPE_IPV4;
	memset(&ipv4_spec, 0, sizeof(ipv4_spec));
	ipv4_spec.hdr.next_proto_id = IPPROTO_TCP;
	ipv4_spec.hdr.src_addr = 0xc3010102;
	ipv4_spec.hdr.dst_addr = 0xc3010103;
	ip_spec = &ipv4_spec;
	ip_mask = &ipv4_mask;

	ip_item.type = ip_type;
	ip_item.spec = ip_spec;
	ip_item.mask = ip_mask;
	ip_item.last = NULL;
	flow_pattern[flow_index++] = ip_item;

	/* TCP item */
	memset(&tcp_spec, 0, sizeof(tcp_spec));
	tcp_spec.hdr.src_port = 6002;
	tcp_spec.hdr.dst_port = 6003;
	tcp_spec.hdr.tcp_flags = 0;
	tcp_item.type = RTE_FLOW_ITEM_TYPE_TCP;
	tcp_item.spec = &tcp_spec;
	tcp_item.mask = &tcp_mask;
	tcp_item.last = NULL;
	flow_pattern[flow_index++] = tcp_item;

	flow_pattern[flow_index] = end_item;
	if (flow_index >= MAX_FLOW_ITEM)
		return -EINVAL;

	age.timeout = 300;
	actions[i++] = age_action;
	actions[i++] = jump_action;
	actions[i++] = end_action;

	flows = rte_zmalloc("flows",
			    sizeof(struct rte_flow*) * num,
			    RTE_CACHE_LINE_SIZE);

	for (i = 0; i < num; i++) {
		ipv4_spec.hdr.src_addr++;
		flows[i] = rte_flow_create(port_id, &attr,
					   flow_pattern,
					   actions, NULL);
		if (!flows[i])
			break;
	}

	for (--i; i >= 0; i--)
		if (flows[i] && rte_flow_destroy(port_id, flows[i], NULL))
			printf("Failed to destory flow %u\n", i);

	rte_free(flows);

	return 0;
}

int main(int argc, char *argv[])
{
	struct rte_mempool *mbuf_pool;
	struct rusage usage;
	unsigned nb_ports;
	uint16_t portid;
	int ret, i;
	int count = 5;
	int num_flows = 20000;
	int test_portid = 0;

	/* Initialize the Environment Abstraction Layer (EAL). */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports % 2)
		rte_exit(EXIT_FAILURE, "Need even ports\n");

	/* Creates a new mempool in memory to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
		rte_socket_id());

	if (!mbuf_pool)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initialize all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool))
			rte_exit(EXIT_FAILURE,
				 "Cannot init port %"PRIu16 "\n", portid);

	getrusage(RUSAGE_SELF, &usage);
	printf("Before test, mem_usage = %lu MB\n",
	       usage.ru_maxrss/1024);

	printf("Test begins: %d iterations, for each:\n"
	       "\tCreate %d flows to port %d then destroy\n",
	       count, num_flows, test_portid);

	for (i = 0 ; i < count; i++) {
		offload_flow_test(test_portid, num_flows);
		malloc_trim(0);
		getrusage(RUSAGE_SELF, &usage);
		printf("Iter (%d), mem_usage = %lu MB\n",
		       i, usage.ru_maxrss/1024);
		sleep(1);
	}

	RTE_ETH_FOREACH_DEV(portid) {
		rte_eth_dev_stop(portid);
		rte_flow_flush(portid, NULL);
		rte_eth_dev_close(portid);
	}

	printf("Done\n");
}
