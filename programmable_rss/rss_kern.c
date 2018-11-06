// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

#include <stdbool.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "jhash.h"
#include "rss_common.h"

struct pkt_meta {
	__be32 src;
	__be32 dst;
	__be32 srcv6[4];
	__be32 dstv6[4];
	union {
		__u32 ports;
		__u16 port16[2];
	};
	__u8 protocol;
};

struct bpf_map_def SEC("maps") ctrl_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct queue_select_ctrl),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") indirect_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(struct indirect_queue),
	.max_entries = MAX_RSS_QUEUES,
};

static __always_inline __u32 hash_tuples(struct pkt_meta *pkt, bool is_ip6)
{
	__u32 a;
	__u32 b;

	/* hash packet ip and ports to obtain a key for rss indirection tbl */
	if (is_ip6) {
		a = jhash2(pkt->srcv6, 4, 0xc55);
		b = jhash2(pkt->dstv6, 4, 0x1234);
		return jhash_3words(a, b, pkt->ports, 0xeb0f);
	} else {
		return jhash_3words(pkt->src, pkt->dst, pkt->ports, 0xeb0f);
	}
}

static __always_inline bool parse_udp(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct udphdr *udp;

	udp = data + off;
	if (udp + 1 > data_end)
		return false;

	pkt->port16[0] = udp->source;
	pkt->port16[1] = udp->dest;

	return true;
}

static __always_inline bool parse_tcp(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct tcphdr *tcp;

	tcp = data + off;
	if (tcp + 1 > data_end)
		return false;

	pkt->port16[0] = tcp->source;
	pkt->port16[1] = tcp->dest;

	return true;
}

static __always_inline bool parse_ip4(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct iphdr *iph;

	iph = data + off;
	if (iph + 1 > data_end)
		return false;

	if (iph->ihl != 5)
		return false;

	pkt->src = iph->saddr;
	pkt->dst = iph->daddr;
	pkt->protocol = iph->protocol;

	return true;
}

static __always_inline bool parse_ip6(void *data, __u64 off, void *data_end,
				      struct pkt_meta *pkt)
{
	struct ipv6hdr *ip6h;

	ip6h = data + off;
	if (ip6h + 1 > data_end)
		return false;

	memcpy(pkt->srcv6, ip6h->saddr.s6_addr32, 16);
	memcpy(pkt->dstv6, ip6h->daddr.s6_addr32, 16);
	pkt->protocol = ip6h->nexthdr;

	return true;
}

static __always_inline void sort_tuple(struct pkt_meta *pkt, bool is_ip6)
{
	__be32 temp_ipv6[4];
	__be32 temp_ip;
	__u16 temp_port;
	__u64 tot_dst;
	__u64 tot_src;

	/* sort tuple to ensure consistency for both flow directions */
	if (is_ip6) {
		tot_src = pkt->srcv6[0] + pkt->srcv6[1]
			   + pkt->srcv6[2] + pkt->srcv6[3];
		tot_dst = pkt->dstv6[0] + pkt->dstv6[1]
			   + pkt->dstv6[2] + pkt->dstv6[3];

		if (tot_src < tot_dst) {
			memcpy(temp_ipv6, pkt->srcv6, 16);
			memcpy(pkt->srcv6, pkt->dstv6, 16);
			memcpy(pkt->dstv6, temp_ipv6, 16);
		}
	} else {
		if (pkt->src < pkt->dst) {
			temp_ip = pkt->src;
			pkt->src = pkt->dst;
			pkt->dst = temp_ip;
		}
	}

	if (pkt->port16[0] < pkt->port16[1]) {
		temp_port = pkt->port16[0];
		pkt->port16[0] = pkt->port16[1];
		pkt->port16[1] = temp_port;
	}
}

SEC("xdp")
int process_packet(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct queue_select_ctrl *queue_ctrl;
	struct indirect_queue *dest_q;
	struct ethhdr *eth = data;
	struct pkt_meta pkt = {};
	bool symmetric = false;
	bool use_encap = false;
	bool is_ip6 = false;
	bool jhash = false;
	__u32 eth_proto;
	__u32 hash;
	__u32 key;
	__u32 off;

	/* determine hashing mode using map lookup */
	key = 0;

	queue_ctrl = bpf_map_lookup_elem(&ctrl_map, &key);
	if (!queue_ctrl)
		return XDP_PASS;

	switch (queue_ctrl->select_mode) {
	case QUEUE_STATIC:
		jhash = false;
		key = queue_ctrl->queue_static;
		break;
	case QUEUE_HASH:
		jhash = true;
		break;
	case QUEUE_SYMMETRIC:
		jhash = true;
		symmetric = true;
		break;
	case QUEUE_ENCAP:
		jhash = true;
		use_encap = true;
		break;
	default:
		return XDP_PASS;
	}

	/* parse packet for IP Addresses and Ports */
	off = sizeof(struct ethhdr);
	if (data + off > data_end)
		return XDP_PASS;

	eth_proto = eth->h_proto;

	if (eth_proto == bpf_htons(ETH_P_IP)) {
		if (!parse_ip4(data, off, data_end, &pkt))
			return XDP_PASS;
		off += sizeof(struct iphdr);
	} else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
		if (!parse_ip6(data, off, data_end, &pkt))
			return XDP_PASS;
		is_ip6 = true;
		off += sizeof(struct ipv6hdr);
	} else {
		return XDP_PASS;
	}

	/* if IPinIP packet allow for second IP header */
	if (pkt.protocol == IPPROTO_IPIP) {
		if (use_encap) {
			if (!parse_ip4(data, off, data_end, &pkt))
				return XDP_PASS;
			is_ip6 = false;
		}
		off += sizeof(struct iphdr);
	} else if (pkt.protocol == IPPROTO_IPV6) {
		if (use_encap) {
			if (!parse_ip6(data, off, data_end, &pkt))
				return XDP_PASS;
			is_ip6 = true;
		}
		off += sizeof(struct ipv6hdr);
	}

	if (data + off > data_end)
		return XDP_PASS;

	/* obtain port numbers for UDP and TCP traffic */
	if (pkt.protocol == IPPROTO_TCP) {
		if (!parse_tcp(data, off, data_end, &pkt))
			return XDP_PASS;
	} else if (pkt.protocol == IPPROTO_UDP) {
		if (!parse_udp(data, off, data_end, &pkt))
			return XDP_PASS;
	} else {
		pkt.ports = 0;
	}

	if (symmetric)
		sort_tuple(&pkt, is_ip6);

	if (jhash) {
		/* set map lookup key using 4 tuple hash */
		hash = hash_tuples(&pkt, is_ip6);
		key = hash % MAX_RSS_QUEUES;
	}

	/* HW cannot perform modulus on varying values so use indirection tbl */
	dest_q = bpf_map_lookup_elem(&indirect_map, &key);
	if (!dest_q)
		return XDP_PASS;

	ctx->rx_queue_index = dest_q->queue_num;
	/* increment queue packet counter */
	__sync_fetch_and_add(&dest_q->packet_cnt, 1);

	return XDP_PASS;
}
