# Introduction
This utility provides crude and minimalistic support for the BFS, BOOTP, TFTP and BSD r-command (rsh, rcp, rlogin, etc.) protocols necessary to perform the network boot and installation of MIPS Computer Systems computers such as the RS2030 and RS3230 workstations. It was designed for and tested with the [MAME](https://www.mamedev.org) emulation of [these systems](https://wiki.mamedev.org/index.php/Driver:MIPS).

`mipsboot` was developed to address several problems:
1. The target systems do not support BOOTP/TFTP, and rely on BFS, an obselete MIPS-unique protocol to perform the same function.
2. BOOTP and TFTP themselves are largely obselete, and while some implementations are still available, they likely suffer from compatibility and security issues that make installation in a modern environment unnecessarily difficult or undesirable.
3. BSD r-commands as used by the MIPS installation software are both obselete and insecure, again making them unsuitable for installation in a modern environment.
4. Use of any of these protocols in a non-Unix environment such as Windows is awkward at best, and may require substantial troubleshooting.
5. The target systems construct network broadcast addresses with all zeros in the host portion, making them incompatible with standard TCP/IP networks.

`mipsboot` combines support for all of the required protocols into a single Python script, does not require any installation or system configuration, and addresses the broadcast address issue by dynamically patching certain MIPS operating system binaries on demand.

# Prerequisites
To use `mipsboot` successfully requires:
* a working installation of Python 2.7
* a copy of the file `riscos_4.52_netinstall.tar` or equivalent
* a network connection to the target MIPS system

The tar file must be located in the working directory, and is directly accessed by `mipsboot` to service BFS, TFTP and r-command file requests.

# Usage
Launch mipsboot as follows:

   `python mipsboot.py address`
   
where:

   `address` is the IP address to which the utility will bind and listen for BFS, BOOTP, TFTP and r-command connections and requests.

`mipsboot` requires read/write access to its working directory and produces some diagnostic output to the console.
