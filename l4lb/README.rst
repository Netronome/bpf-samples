Layer 4 Load Balancer Demo
==========================

This program will demonstrate how a XDP load balancer can be used to distribute
incoming traffic by hashing the layer 3 and layer 4 headers.

The XDP program, will process incoming network packets and compute a hash
based on the sender IP address, along with the TCP or UDP network ports.
This hash value is subsequently used as the key for a eBPF map.

The eBPF map is filled with the available servers to which the XDP program can
redirect the packet to. The XDP program will extend and insert an outer IP
header with this map data. After processing, the program will subsequently
send the packet back out of the network interface to the destination server.

The map fill and stats scripts are written in python and utilize bpftool to
showcase how a program can be deployed using iproute2 and bpftool utilities.

Minimum Requirements for Demo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Linux kernel 4.17
- iproute2 v4.16.0 (a.k.a ss180402)
- clang / LLVM 4.0
- bpftool
- Python 3
- Agilio® eBPF firmware (only for HW offload) - July 2018
  (available from `Netronome's support website`_)

.. _Netronome's support website: https://help.netronome.com/

Loading the Demo
~~~~~~~~~~~~~~~~

To compile the XDP program ::

 $ make

The program can be loaded using iproute2 using the following commands

XDP driver mode ::

 # ip link set dev { DEV } xdpdrv obj l4lb_xdp.o sec xdp

XDP offload ::

 # ip link set dev { DEV } xdpoffload obj l4lb_xdp.o sec xdp

The load balancer map can be filled with the l4lb_map.py script. Note that
sample files with lists of destinations are provided under
`destination_samples/`_ ::

 # ./l4lb_map.py -i { DEV } -f { file containing destinations }

Traffic statistics may be seen using the l4lb_stats.py script ::

 # ./l4lb_stats.py -i { DEV }

.. _destination_samples/: destination_samples/

Traffic Generation
~~~~~~~~~~~~~~~~~~

Traffic can be generated using a variety of tools. A command is shown below
which utilises the hping3 utility to generate the traffic. The command should
be run on a different host connected to the server running the eBPF l4lb
program. In this example the traffic generator uses interface ens0 and is
transmitting traffic to IP address 10.0.0.4 ::

 hping3 10.0.0.4 --rand-source -i ens0 --flood

Example
~~~~~~~

To demo the program on offload mode on interface ens4np0, with 32 destinations ::

 # ip link set dev ens4np0 xdpoffload obj l4lb_xdp.o sec xdp
  Note: 12 bytes struct bpf_elf_map fixup performed due to size mismatch!

 # ./l4lb_map.py -i ens4np0 -f destination_samples/32_destinations.csv
  Loading file with 32 destinations

 # ./l4lb_stats.py -i ens4np0
  == Load balancer outbound statistics [Offload] ==

     1	10.0.0.57      	   1,029,744 pkts/s	  1,186,266,224 bits/s
     2	10.0.125.19    	   1,031,841 pkts/s	  1,188,681,760 bits/s
     3	10.0.129.60    	   1,033,649 pkts/s	  1,190,763,984 bits/s
     4	10.0.14.88     	   1,031,274 pkts/s	  1,188,028,704 bits/s
     5	10.0.143.99    	   1,032,110 pkts/s	  1,188,991,816 bits/s
     6	10.0.159.176   	   1,031,466 pkts/s	  1,188,249,616 bits/s
     7	10.0.16.109    	   1,031,213 pkts/s	  1,187,957,968 bits/s
     8	10.0.161.129   	   1,031,025 pkts/s	  1,187,740,928 bits/s
     9	10.0.175.130   	   1,032,664 pkts/s	  1,189,629,368 bits/s
    10	10.0.178.75    	   1,032,625 pkts/s	  1,189,584,800 bits/s
    11	10.0.181.34    	   1,031,332 pkts/s	  1,188,094,584 bits/s
    12	10.0.185.52    	   1,033,361 pkts/s	  1,190,432,608 bits/s
    13	10.0.192.32    	   1,032,855 pkts/s	  1,189,849,312 bits/s
    14	10.0.199.54    	   1,032,126 pkts/s	  1,189,009,256 bits/s
    15	10.0.214.65    	   1,032,921 pkts/s	  1,189,925,864 bits/s
    16	10.0.23.41     	   1,033,084 pkts/s	  1,190,112,864 bits/s
    17	10.0.234.48    	   1,031,888 pkts/s	  1,188,735,048 bits/s
    18	10.0.24.77     	   1,031,594 pkts/s	  1,188,396,896 bits/s
    19	10.0.244.158   	   1,031,127 pkts/s	  1,187,859,136 bits/s
    20	10.0.31.144    	   1,032,068 pkts/s	  1,188,942,400 bits/s
    21	10.0.32.134    	   1,031,787 pkts/s	  1,188,619,744 bits/s
    22	10.0.32.35     	   1,031,222 pkts/s	  1,187,968,624 bits/s
    23	10.0.50.179    	   1,031,597 pkts/s	  1,188,400,768 bits/s
    24	10.0.56.49     	   1,032,840 pkts/s	  1,189,831,872 bits/s
    25	10.0.63.10     	   1,031,564 pkts/s	  1,188,362,008 bits/s
    26	10.0.75.126    	   1,032,512 pkts/s	  1,189,454,960 bits/s
    27	10.0.75.197    	   1,030,993 pkts/s	  1,187,705,080 bits/s
    28	10.0.75.209    	   1,033,445 pkts/s	  1,190,529,504 bits/s
    29	10.0.89.127    	   1,033,593 pkts/s	  1,190,700,032 bits/s
    30	10.0.90.135    	   1,031,819 pkts/s	  1,188,655,600 bits/s
    31	10.0.90.214    	   1,032,841 pkts/s	  1,189,832,848 bits/s
    32	10.0.92.11     	   1,032,581 pkts/s	  1,189,534,416 bits/s

  [Totals]		  33,026,761 pkts/s	 38,046,848,592 bits/s

Note: This example was produced with a high performance traffic generator,
lower rates are expected with hping3.

Removing the Demo
~~~~~~~~~~~~~~~~

XDP driver mode ::

# ip link set dev { DEV } xdpdrv off

XDP offload ::

# ip link set dev { DEV } xdpoffload off
