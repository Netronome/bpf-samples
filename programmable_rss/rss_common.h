// SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
// Copyright (c) 2018 Netronome Systems, Inc.

#define MAX_RSS_QUEUES 64

enum {
	QUEUE_STATIC = 0,
	QUEUE_HASH,
	QUEUE_SYMMETRIC,
	QUEUE_ENCAP,
};

struct queue_select_ctrl {
	__u8 select_mode;
	__u8 queue_static;
};

struct indirect_queue {
	__u32 packet_cnt;
	__u8 queue_num;
};
