#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Copyright (c) 2018 Netronome Systems, Inc.

import argparse
import csv
import json
import os
import subprocess
from bpftool_utils import *

parser = argparse.ArgumentParser(description="Initialize load balancer map")
parser.add_argument('-i', '--interface', action='store', required=True,
                    help='xdp network interface')
parser.add_argument('-f', '--file', action='store', required=True,
                    help='Input file containing destination data')
parser.add_argument('-s', '--saddr', action='store', required=False, type=str,
                    default='10.0.0.1', help='source ip for outgoing packets')
args = parser.parse_args()

tmpfile = 'tmp_bpftool.txt' # batch map updates into a file for bpftool
stats_zero = '00 00 00 00 00 00 00 00' # initialize stats to (u64) zero

interface = args.interface

try:
    map_id = str(get_map_ids(interface)[0])
    max_dest = get_map_entries(map_id) # map size as defined by xdp program
except:
    print("Error finding map for dev: %s" % interface)
    sys.exit(1)

try:
    dest_file = open(args.file, 'r')
    dest_hosts = list(csv.reader(dest_file))
    dest_count = len(dest_hosts)
except:
    print("Error reading file")
    sys.exit(1)

if dest_count > max_dest:
    print("Warning: only the first %d destinations will be used" % max_dest)
else:
    print("Loading file with %d destinations" % dest_count)

batchfile = open(tmpfile, 'w')

# iterate through data in input file, if it contains less values than max_dest
# map will be filled as round robin
for key in range (0, max_dest):
    target_id = key % dest_count

    # bpftool requires data as individual bytes
    keyval1 = str(key & 0xFF)
    keyval2 = str(key >> 8)

    saddr = args.saddr.split('.') # source IP for egress packets
    daddr = dest_hosts[target_id][0].split('.') # IP of the target server

    dmac_hex = dest_hosts[target_id][1].split(':') # MAC of the target server
    dmac = [str(int(byte, 16)) for byte in dmac_hex] # convert hex to integers

    # Fill in map using struct iptnl_info arrangement as specified in l4lb_xdp.c
    COMMAND = (['map update id', map_id,
                'key', keyval1, keyval2, '00 00',
                'value', saddr[0], saddr[1], saddr[2], saddr[3],
                         daddr[0], daddr[1], daddr[2], daddr[3],
                         stats_zero, stats_zero,
                         dmac[0], dmac[1], dmac[2], dmac[3], dmac[4], dmac[5],
                         '00 00 \n'])
    COMMAND = ' '.join(COMMAND)
    batchfile.write(COMMAND)

batchfile.close()
subprocess.check_output('bpftool batch file %s' % tmpfile, shell=True)
