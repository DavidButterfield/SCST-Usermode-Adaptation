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
[here](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_Usermode.html
       "A paper describing the work in detail is here").

**The SCST iSCSI Usermode Adaptation depends on**
 + [Usermode Compatibility (UMC)](https://github.com/DavidButterfield/usermode_compat
				"Usermode Compatibility for Linux Kernel Code (UMC)")
    &mdash; a shim for running some Linux kernel code in usermode

 + [Multithreaded Event Engine (MTE)](https://github.com/DavidButterfield/MTE "Multithreaded Engine (libmte)")
    &mdash; a high-performance multi-threaded event dispatching engine for usermode

**Things to do to get started running Usermode SCST**

	sudo apt install subversion
	sudo apt install cscope
	sudo apt install exuberant-ctags
	sudo apt install libaio-dev
	sudo apt install libfuse-dev

	mkdir Usermode_SCST	# or whatever name you want
	cd    Usermode_SCST

	svn co https://github.com/DavidButterfield/MTE.git MTE
	svn co https://github.com/DavidButterfield/usermode_compat.git UMC
	svn co https://github.com/DavidButterfield/SCST-Usermode-Adaptation.git SCST

	pushd MTE/trunk/src
	make; sudo make install		# adds to /lib and /usr/include
	popd

	pushd SCST/trunk/usermode
	make
	popd

	# Patch scst_admin to know where /fuse/scst/proc is

	SCST/trunk/usermode/scst.out -f
	scstadmin -config /etc/scst.conf	XXXXX

#### Diagrams showing the relationship between UMC, MTE, and Usermode SCST
* * *
![SCST usermode service map](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_usermode_service_map.png
 "SCST Usermode Service Map")
* * *
![SCST usermode header and library inclusions](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_usermode_includes.png
"SCST Usermode Header and Library Inclusions")
* * *
