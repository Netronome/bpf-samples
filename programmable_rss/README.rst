Programmable RSS Demo
=====================

Overview of RSS
~~~~~~~~~~~~~~~

Receive Side Scaling (RSS) is utilised in modern network cards to distribute
network traffic between the host CPUs through the use of multiple queues [1]_.
A hash function is applied to the packet headers (commonly the 4 tuple) to
generate a hash for the flow. This hash value is subsequently used as the index
to an indirection table which designates the destination RSS queue.

Symmetric RSS is a RSS implementation where packets in both direction of a flow
map to the same queue, i.e. for a connection between hosts A and B, both packets
sent by A and by B will be placed on the same queue.
This is useful for IDS/Firewalls monitoring traffic flows, by ensuring CPU state
access locality across all packets of the flow one can minimise cache bouncing
and achieve higher performance.

Custom header RSS (or Encapsulated RSS) allows users to benefit from RSS even if
they are using custom headers or uncommon encapsulations. Default RSS
implementations are only able to parse common protocols. With programmable RSS
users can include any field of the headers in RSS calculation. Users can also
parse any encapsulation protocol they have in their networks. This is beneficial
to overlay and trunk networks, where the outer IP header is relatively static
resulting in a badly distributed RSS. The inner IP header addresses can have
more variance hence a better RSS distribution.

The RSS algorithms available on network cards are commonly closed source or
fixed in hardware. In Linux kernel 4.18, the capability of programming the
RX RSS through eBPF was introduced.

Demo App
~~~~~~~~

This program will demonstrate how XDP offload can be utilised to provide user
programmable RSS. As this is a demo, it showcases multiple RSS capabilities,
however a deployment would likely only implement one of these RSS options.

The demo allows for incoming packets to be distributed to

- a single queue, chosen by the user through a userspace utility
- distributed queues using a hash algorithm
- distributed queues using a Symmetric RSS hash algorithm
- distributed queues using a hash algorithm against the IPinIP inner headers

This demo shows support for simple IPinIP encapsulation because it's easy to set
up and test, but UDP encapsulations (VXLAN, Geneve, FOU, GUE, etc.), NSH, QUIC
or any other protocol can easily be implemented.

Minimum Requirements for Demo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This program requires a XDP offload compatible SmartNIC. It cannot be run in
driver mode.

- Linux kernel 4.18
- clang / LLVM 4.0
- libelf-dev (Ubuntu) / elfutils-devel (Fedora)
- Agilio® eBPF firmware for HW offload - July 2018
  (available from `Netronome's support website`_)

.. _Netronome's support website: https://help.netronome.com/

Loading the Demo
~~~~~~~~~~~~~~~~

The program is compiled using an included libbpf. To compile the user space and
XDP programs ::

 $ make

To load the program ::

 # ./rss -i INTERFACE

Traffic Generation
~~~~~~~~~~~~~~~~~~

Traffic can be generated using a variety of tools, but for ease of use a pcap
file has been supplied (traffic_IPIP.pcap). This traffic can be replayed
using the following instructions.

For the host running the eBPF program, ensure promiscuous mode is enabled to
allow for all packets to be received. This is required as the destination MAC
address set within the pcap file has been set for another host ::

 # ip link set dev ens4np0 promisc on

On the traffic generator, use tcpreplay to retransmit the test traffic ::

 # tcpreplay -i ens0 -l 500 traffic_IPIP.pcap

Examples
~~~~~~~~

The following examples will utilise the interface ens4np0 which has 8 queues
set within ethtool. All examples are run against the same IPinIP traffic ::

 # ethtool -L ens4np0 combined 8 rx 0 tx 0

Sending all traffic to queue 5 ::

 # ./rss -i ens4np0 -q 5
 -------------------------------------------------
 RSS Queue 0: 0
 RSS Queue 1: 0
 RSS Queue 2: 0
 RSS Queue 3: 0
 RSS Queue 4: 0
 RSS Queue 5: 804,081
 RSS Queue 6: 0
 RSS Queue 7: 0

Distributing traffic using jhash algorithm ::

 # ./rss -i ens4np0 -j
 -------------------------------------------------
 RSS Queue 0: 0
 RSS Queue 1: 0
 RSS Queue 2: 0
 RSS Queue 3: 0
 RSS Queue 4: 0
 RSS Queue 5: 402,400
 RSS Queue 6: 402,400
 RSS Queue 7: 0

Distributing traffic using jhash algorithm with Symmetric RSS ::

 # ./rss -i ens4np0 -j -s
 -------------------------------------------------
 RSS Queue 0: 0
 RSS Queue 1: 0
 RSS Queue 2: 0
 RSS Queue 3: 0
 RSS Queue 4: 0
 RSS Queue 5: 0
 RSS Queue 6: 804,797
 RSS Queue 7: 0

Distributing traffic using jhash algorithm with encapsulated IPs ::

 # ./rss -i ens4np0 -j -e
 -------------------------------------------------
 RSS Queue 0: 72,449
 RSS Queue 1: 104,648
 RSS Queue 2: 120,747
 RSS Queue 3: 128,797
 RSS Queue 4: 64,398
 RSS Queue 5: 128,792
 RSS Queue 6: 72,447
 RSS Queue 7: 112,693

Distributing traffic using jhash algorithm with encapsulated IPs on 4 queues ::

 # ./rss -i ens4np0 -j -e -m 4
 -------------------------------------------------
 RSS Queue 0: 136,820
 RSS Queue 1: 233,403
 RSS Queue 2: 193,158
 RSS Queue 3: 241,450

Removing the Demo
~~~~~~~~~~~~~~~~~

The XDP program will automatically be unloaded on exiting the rss program

.. [1] https://www.kernel.org/doc/Documentation/networking/scaling.txt
