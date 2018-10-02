#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Copyright (c) 2018 Netronome Systems, Inc.

import json
import subprocess
import struct
import sys

def check_output_json(cmd):
    return json.loads(subprocess.check_output(cmd, shell=True).decode("utf-8"))

def get_xdp_prog(interface):
    cmd_iplink = 'ip -j link show %s' % interface
    iplink = check_output_json(cmd_iplink)
    return iplink[0]['xdp']['prog']['id']

def get_map_ids(interface):
    prog_id = get_xdp_prog(interface)
    cmd_progshow = 'bpftool prog show id %d -p' % prog_id
    prog_info = check_output_json(cmd_progshow)

    maps = check_output_json('bpftool map -p')
    map_ids = []

    for m in maps:
            if m['id'] in prog_info['map_ids']:
                    map_ids.append(m['id'])
    return map_ids

def get_map_entries(map_id):
    cmd_mapshow = 'bpftool map show id %s -p' % map_id
    map_info = check_output_json(cmd_mapshow)
    return map_info['max_entries']

def get_map_dev(map_id):
    cmd_mapshow = 'bpftool map show id %s -p' % map_id
    map_info = check_output_json(cmd_mapshow)

    if "dev" in map_info:
        return "Offload"
    else:
        return "Driver"

def dump_map(map_id):
    cmd_map = 'bpftool map dump id %s -p' % map_id
    return check_output_json(cmd_map)

def hex_list_to_int(hex_list):
    hex_str = ''.join([byte.replace('0x', '') for byte in hex_list])
    return (int.from_bytes(bytes.fromhex(hex_str), byteorder='little'))
