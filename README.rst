XDP demo apps
=============

This repository contains eBPF XDP demo applications.
Most demos can be run on xdp compatible drivers or hardware.

Driver mode loads the XDP program into the kernel where the processing is
carried out by the host CPU, whilst offload XDP allows for the program to be run on
hardware, for example with the Netronome Agilio CX SmartNIC.

To enable XDP offload on a Agilio CX, please refer to `Netronome eBPF user guides`_

================ ===============
Demo Apps        Kernel Required
`Load Balancer`_     4.17
================ ===============

.. _Netronome eBPF user guides: https://help.netronome.com/support/solutions/folders/36000172266
.. _Load Balancer: l4lb/

Note: These applications are prototypes and are not suitable for production use.
