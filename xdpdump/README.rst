.. SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

xdpdump Demo
============

Demo App
~~~~~~~~

This program demonstrates how a eBPF program may communicate with userspace
using the kernel's perf tracing events.

The demo's userspace program creates a perf ring buffer for each of the host's
CPUs. This ring buffer is assigned a File Descriptor, this is subsequently
written to the eBPF map, denoted by the CPU index.

When an ingress packet enters the XDP program, packet metadata is extracted and
stored into a data structure. The XDP program sends this metadata, along with
the packet contents to the ring buffer denoted in the eBPF perf event map using
the current CPU index as the key.

The userspace program polls the perf rings for events from the XDP program.
When an event is received, it prints the event's metadata to the terminal.
The user can also specify if the packet contents should be dumped in hexadecimal
format.

This demo program can currently only analyze IPv4 and IPv6 packets containing
TCP/UDP data, but could easily be expanded to cover a wider range of protocols.

Minimum Requirements for Demo
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- Linux kernel 4.18
- clang / LLVM 4.0
- libelf-dev (Ubuntu) / elfutils-devel (Fedora)
- Agilio® eBPF firmware for HW offload
  (available from `Netronome's support website`_)

.. _Netronome's support website: https://help.netronome.com/

Loading the Demo
~~~~~~~~~~~~~~~~

The program is compiled using an included libbpf. To compile the user space and
XDP programs ::

 $ make

To load the program ::

 # ./xdpdump -i INTERFACE

Examples
~~~~~~~~

The program may be started in driver mode using the following command ::

 # ./xdpdump -i eth4
 -----------------------------------------------------------------------
 28228.714182 IP 10.0.0.2:9203 > 10.0.0.1:0 TCP seq 437136853, length 6
 28233.714510 IP6 fe80::268a:7ff:fe3b:46:9 > 2001:db8:85a3::370:7334:9 UDP, length 16
 28234.040118 IP 10.0.0.2:1709 > 10.0.0.1:0 TCP seq 1723695364, length 30

Payload information can also be displayed with the payload option ::

 # ./xdpdump -i eth4 -x
 ---------------------------------------------------------
 28298.719497 IP 10.0.0.2:1697 > 10.0.0.1:0 TCP seq 1017625101, length 6
        0015 4d13 0880 248a 073b 0046 0800 4500
        0028 18fa 0000 4006 4dd4 0a00 0002 0a00
        0001 06a1 0000 3ca7 ba0d 558d d5a8 5000
        0200 7156 0000 0000 0000 0000

The program may be offloaded to the SmartNIC using the HW offload option ::

 # ./xdpdump -i eth4 -x -H
 ---------------------------------------------------------
 28357.729517 IP 10.0.0.2:54013 > 10.0.0.1:53 UDP, length 51
         0015 4d13 0880 248a 073b 0046 0800 4500
         004f cf83 0000 4011 9718 0a00 0002 0a00
         0001 d2fd 0035 003b bd51 cd62 0120 0001
         0000 0000 0001 0667 6f6f 676c 6503 636f
         6d00 0001 0001 0000 2910 0000 0000 0000
         0c00 0a00 08ce 1722 411e 4e95 8b

For systems without a compatible XDP driver, it can also be loaded in SKB mode ::

 # ./xdpdump -i eth4 -S

Removing the Demo
~~~~~~~~~~~~~~~~~

The XDP program will automatically be unloaded on exiting the xdpdump program
