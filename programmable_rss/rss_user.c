// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

#include <libgen.h>
#include <locale.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/ethtool.h>
#include <linux/if_link.h>
#include <linux/in.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include "rss_common.h"

static int ifindex;
static __u32 xdp_flags;

static void unload_prog(int sig)
{
	bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	printf("unloading xdp program...\n");
	exit(0);
}

static int get_interface_rx_channels(int ifindex)
{
	struct ethtool_channels cmd;
	struct ifreq req;
	int socketfd;

	socketfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (socketfd == -1)
		return -1;

	/* get interface name */
	req.ifr_ifindex = ifindex;
	if (ioctl(socketfd, SIOCGIFNAME, &req) == -1)
		return -1;

	/* get ethtool channels */
	req.ifr_data = (void *)&cmd;
	cmd.cmd = ETHTOOL_GCHANNELS;

	if (ioctl(socketfd, SIOCETHTOOL, &req) == -1)
		return -1;

	return cmd.combined_count + cmd.rx_count;
}

static int poll_stats(int indirect_map_fd, int queues_enabled, int poll_secs)
{
	struct indirect_queue indirect_lookup;
	int values[queues_enabled];
	int prev[queues_enabled];
	struct timespec t1, t2;
	double time_taken;
	long queue_rate;
	int queue;
	int i;

	/* initialize arrays */
	memset(prev, 0, sizeof(prev));
	memset(values, 0, sizeof(prev));
	/* use thousand separators in printf */
	setlocale(LC_NUMERIC, "en_US");

	clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

	while (true) {
		printf("-------------------------------------------------\n\n");
		for (i = 0; i < MAX_RSS_QUEUES; i++) {
			if (bpf_map_lookup_elem(indirect_map_fd, &i,
						&indirect_lookup) != 0) {
				printf("Err lookup failed\n");
				return 0;
			}
			queue = indirect_lookup.queue_num;
			values[queue] += indirect_lookup.packet_cnt;
		}

		clock_gettime(CLOCK_MONOTONIC_RAW, &t2);
		/* calc sample period to allow rate to be obtained */
		time_taken = (t2.tv_sec + 1.0e-9 * t2.tv_nsec) -
			     (t1.tv_sec + 1.0e-9 * t1.tv_nsec);

		for (i = 0; i < queues_enabled; i++) {
			queue_rate = (values[i] - prev[i]) / time_taken;
			printf("RSS Queue %d: %'ld\n", i, queue_rate);
			prev[i] = values[i];
			values[i] = 0;
		}
		t1 = t2;
		usleep(poll_secs * 1000 * 1000);
	}
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"%s -i interface [OPTS]\n\n"
		"OPTS:\n"
		" -q  QUEUE send all traffic to single queue\n"
		" -j        jhash incoming IP and ports\n"
		" -s        jhash with Symmetric RSS\n"
		" -e        jhash Encapsulated IPinIP headers\n"
		" -m QUEUES set maximum number of queues for jhash\n",
		prog);
}

int main(int argc, char **argv)
{
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = "rss_kern.o",
	};
	struct indirect_queue indirect_rec = {};
	struct queue_select_ctrl mapctrl;
	struct bpf_map *indirect_map;
	struct bpf_map *ctrl_map;
	struct bpf_object *obj;
	int queues_enabled = 0;
	int indirect_map_fd;
	int ethtool_queues;
	int ctrl_map_fd;
	int prog_fd;
	int key;
	int opt;
	int i;

	mapctrl.select_mode = QUEUE_HASH;
	xdp_flags = XDP_FLAGS_HW_MODE;   /* set HW offload flag */

	if (optind == argc) {
		usage(basename(argv[0]));
		return -1;
	}

	while ((opt = getopt(argc, argv, "hi:q:jsem:")) != -1) {
		switch (opt) {
		case 'h':
			usage(basename(argv[0]));
			return 0;
		case 'i':
			ifindex = if_nametoindex(optarg);
			break;
		case 'q':
			mapctrl.select_mode = QUEUE_STATIC;
			mapctrl.queue_static = atoi(optarg);
			break;
		case 'j':
			mapctrl.select_mode = QUEUE_HASH;
			break;
		case 's':
			mapctrl.select_mode = QUEUE_SYMMETRIC;
			break;
		case 'e':
			mapctrl.select_mode = QUEUE_ENCAP;
			break;
		case 'm':
			queues_enabled = atoi(optarg);
			break;
		default:
			printf("incorrect usage\n");
			usage(basename(argv[0]));
			return -1;
		}
	}

	if (ifindex == 0) {
		printf("Err: Invalid interface\n");
		return -1;
	}
	prog_load_attr.ifindex = ifindex; /* set offload dev ifindex */

	ethtool_queues = get_interface_rx_channels(ifindex);
	if (ethtool_queues < 1) {
		printf("Err: Cannot obtain number of NIC channels\n");
		return -1;
	}

	if (queues_enabled == 0) /* if no user defined max queue limit */
		queues_enabled = ethtool_queues;

	if (queues_enabled > ethtool_queues) {
		printf("Err: Queues enabled exceeds netdev queues\n");
		printf("Ethtool queues: %d\n", ethtool_queues);
		return -1;
	}

	if (mapctrl.select_mode == QUEUE_STATIC) {
		if (mapctrl.queue_static >= queues_enabled) {
			printf("Err: Queue selected exceeds queues enabled\n");
			printf("Netdev queues enabled: %d\n", queues_enabled);
			return -1;
		}
	}

	/* use libbpf to load program */
	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd)) {
		printf("Err: Cannot load file\n");
		return -1;
	}

	if (prog_fd < 1) {
		printf("Error creating prog_fd\n");
		return -1;
	}

	signal(SIGINT, unload_prog);
	signal(SIGTERM, unload_prog);

	/* use libbpf to link program to interface with corresponding flags */
	if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0) {
		printf("Error linking fd to xdp with offload flags\n");
		return -1;
	}

	ctrl_map = bpf_object__find_map_by_name(obj, "ctrl_map");
	ctrl_map_fd = bpf_map__fd(ctrl_map);
	indirect_map = bpf_object__find_map_by_name(obj, "indirect_map");
	indirect_map_fd = bpf_map__fd(indirect_map);

	if (!(ctrl_map_fd >= 0 && indirect_map_fd >= 0)) {
		printf("Err: Cannot find maps\n");
		return -1;
	}

	/* fill ctrl map with hash mode queues */
	key = 0;
	if (bpf_map_update_elem(ctrl_map_fd, &key, &mapctrl, BPF_ANY) != 0) {
		printf("Err: Map update\n");
		return -1;
	}

	/* fill indirection map round robin using modulus */
	for (i = 0; i < MAX_RSS_QUEUES; i++) {
		indirect_rec.queue_num = i % queues_enabled;

		if (bpf_map_update_elem(indirect_map_fd, &i, &indirect_rec,
					BPF_ANY) != 0) {
			printf("Err: Map update failed\n");
			return -1;
		}
	}
	poll_stats(indirect_map_fd, queues_enabled, 1);
	return 0;
}
