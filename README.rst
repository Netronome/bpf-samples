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

======================== ===============
Application              Kernel Required
======================== ===============
`Layer 4 Load Balancer`_     4.17
`Programmable RSS`_          4.18
======================== ===============

.. _Layer 4 Load Balancer: l4lb/
.. _Programmable RSS: programmable_rss/

Notes
~~~~~

- These applications are prototypes and are not suitable for production use.
