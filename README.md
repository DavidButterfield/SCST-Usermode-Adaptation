# SCST-Usermode-Adaptation
**SCST iSCSI Storage Server Usermode Adaptation**  
An adaptation of the iSCSI-SCST storage server software to run entirely in usermode on an unmodified Linux kernel  
*David A. Butterfield*

This project adapts the SCST iSCSI storage server software, normally resident
in the Linux kernel, to run entirely in usermode on an unmodified kernel.

The adaptation uses about 80,000 lines of SCST code, a subset supporting the
iSCSI transport type, and SCSI Block Commands backed by either a file or a
block device.

A paper describing the work in detail is
[here](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_Usermode.html
       "A paper describing the work in detail is here").

[Patches for SCST to run in usermode](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/index.html
				      "Patches for SCST to run in usermode")

**The SCST iSCSI Usermode Adaptation depends on**
 + [Usermode Compatibility Module](https://github.com/DavidButterfield/usermode_compat
				"Usermode Compatibility for Linux Kernel Code (UMC)")
    &mdash; A shim for running some Linux kernel code in usermode

 + [Multithreaded Event Engine](https://github.com/DavidButterfield/MTE "Multithreaded Engine (libmte)")
    &mdash; a high-performance multi-threaded event dispatching engine for usermode

#### Diagrams showing the relationship between UMC, MTE, and Usermode SCST
* * *
![SCST usermode service map](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_usermode_service_map.png
                             "SCST Usermode Service Map")
* * *
![SCST usermode header and library inclusions](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/SCST_usermode_includes.png
                                               "SCST Usermode Header and Library Inclusions")
* * *
