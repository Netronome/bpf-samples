.. SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP Demo Apps
=============

Testing XDP, on software and on hardware
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This repository contains eBPF XDP demo applications.

Most demos can be run on XDP compatible drivers or hardware. Each subdirectory
provides instructions for loading the programs in “driver” and/or in “offload”
mode. “Driver mode” loads the XDP program into the kernel where the processing
is carried out by the host CPU, whilst “offloaded XDP” allows for the program
to be run on hardware, such as with the Netronome Agilio® CX SmartNIC.

To enable XDP offload on a Agilio CX, please refer to `Netronome eBPF user guides`_.

.. _Netronome eBPF user guides: https://help.netronome.com/support/solutions/folders/36000172266

List of available demos
~~~~~~~~~~~~~~~~~~~~~~~

The sources for each demo are located in a specific subdirectory.

======================== ===============
Application              Kernel Required
======================== ===============
`Layer 4 Load Balancer`_     4.17
`Programmable RSS`_          4.18
`xdpdump`_                   4.18
======================== ===============

.. _Layer 4 Load Balancer: l4lb/
.. _Programmable RSS: programmable_rss/
.. _xdpdump: xdpdump/

libbpf
~~~~~~

The ``libbpf`` directory is a git submodule and contains libraries required for
compiling the samples. To obtain the submodule content, the following git
clone command is required:

 git clone --recurse-submodules https://github.com/Netronome/bpf-samples.git

Notes
~~~~~

- These applications are prototypes and are not suitable for production use.
