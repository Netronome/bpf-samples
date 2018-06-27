#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Copyright (c) 2018 Netronome Systems, Inc.

import argparse
import json
import os
import subprocess
import sys
import time
from bpftool_utils import *

parser = argparse.ArgumentParser(description="Display load balancer statistics")
parser.add_argument('-i', '--interface', action='store', required=True,
                    help='xdp network interface')
args = parser.parse_args()
interface = args.interface

prev = {}

while True:
    n = 1
    pkt_tot = 0
    bit_tot = 0
    values = {}
    clock = time.time()

    # obtain map values
    try:
        map_id = get_map_ids(interface)[0]
        map_vals = dump_map(map_id)
        xdp_type = get_map_dev(map_id)
    except:
        print("Error accessing eBPF map")
        time.sleep(1)
        continue

    # get totals for each destination ip
    for record in map_vals:
        # obtain values from map from positions defined by struct iptnl_info
        dest_ip = [int(byte, 16) for byte in record['value'][4:8]]
        bw = hex_list_to_int(record['value'][8:16])
        pkt = hex_list_to_int(record['value'][16:24])

        ip = '%s.%s.%s.%s' % (dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3])

        if ip in values:
            values[ip][0] += pkt
            values[ip][1] += bw
        else:
            values[ip] = [pkt, bw]

    os.system("clear")
    pr = ("== Load balancer outbound statistics [%s] ==\n\n" % xdp_type)

    # Calculate network rate using diff from previous sample
    for key in sorted(values):
        bitrate = 0
        pktrate = 0

        if key in prev:
            sample_period = clock - prev[key][2]
            pktrate = int((values[key][0] - prev[key][0]) / sample_period)
            bitrate = int((values[key][1] - prev[key][1]) / sample_period) * 8

        prev[key] = [values[key][0], values[key][1], clock]

        if pktrate >= 0: # on map refill stats are reset causes neg stats
            pr += ("{:4d}\t{:15s}\t{:12,} pkts/s\t{:15,} bits/s\n"
                  .format(n, key, pktrate, bitrate))
            pkt_tot += pktrate
            bit_tot += bitrate
            n += 1

    pr += "\n[Totals]\t\t{:12,} pkts/s\t{:15,} bits/s".format(pkt_tot, bit_tot)
    print(pr)

    time.sleep(max(0, 1 - (time.time() - clock)))
