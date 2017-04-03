# SCST-Usermode-Adaptation
**SCST iSCSI Storage Server Usermode Adaptation**  
An adaptation of the iSCSI-SCST storage server software to run entirely in usermode on an unmodified Linux kernel  
*David A. Butterfield*

This project adapts the SCST iSCSI storage server software, normally resident
in the Linux kernel, to run entirely in usermode on an unmodified kernel.  The
resulting executable can run as a regular (non-super) user, as long as it has
permission to access the backing storage.  A paper describing the work in detail is
[here](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_Usermode.html
       "A paper describing the work in detail").

The adaptation uses about 80,000 lines of the SCST source code, a subset
supporting the iSCSI transport type (via socket calls), and SCSI Block Commands
(vdisk_fileio) backed by either a file or a block device.

**The SCST iSCSI Usermode Adaptation depends on**  
 + [Usermode Compatibility (UMC)](https://github.com/DavidButterfield/usermode_compat
				"Usermode Compatibility for Linux Kernel Code (UMC)")
    &mdash; a shim for running some Linux kernel code in usermode
 + [Multithreaded Engine (MTE)](https://github.com/DavidButterfield/MTE "Multithreaded Engine (libmte)")
    &mdash; a high-performance multi-threaded event dispatching engine for usermode
 + A little work would be required to run on architectures other than x86
 + Possibly even less work would be required to run on non-Linux POSIX systems with gcc and libraries
 + It shouldn't matter much, but I have only tested with these:
	- Linux 3.13.0-101-generic #148-Ubuntu SMP x86_64
	- Linux 4.4.0-70-generic    #91-Ubuntu SMP x86_64 GNU/Linux

**Hints to help get started running Usermode SCST**

	sudo apt install libaio-dev		# required
	sudo apt install libfuse-dev		# required
	sudo apt install subversion		# or git accessor of your choice
	sudo apt install cscope			# (optional with makefile edit)
	sudo apt install exuberant-ctags	# (optional with makefile edit)

	mkdir Usermode_SCST ; cd Usermode_SCST	# or use whatever name you want
	svn co https://github.com/DavidButterfield/MTE.git MTE   # simpler if use these names: MTE
	svn co https://github.com/DavidButterfield/usermode_compat.git UMC	             # UMC
	svn co https://github.com/DavidButterfield/SCST-Usermode-Adaptation.git SCST         # SCST

	pushd MTE/trunk/src	    # make the Multithreaded Engine library
	make
	sudo make install	    # needs permission for /lib, /usr/include
	popd

	cd SCST/trunk/usermode
	make			    # make the SCST iSCSI server binary
	ls -l scst.out		    # in SCST/trunk/usermode/

	# Patch SCST.pm (used by scstadmin) to know where /fuse/scst/proc is:
	# +++/usr/local/share/perl/*/SCST/SCST.pm
	# -my $_SCST_DIR_ =           '/proc/scsi_tgt';
	# +my $_SCST_DIR_ = '/fuse/scst/proc/scsi_tgt';

	[ gdb | valgrind ] scst.out -f  
In another terminal window

	scstadmin -config /etc/scst.conf
	ls -l `find /fuse -type f`
#### Diagrams showing the relationship between UMC, MTE, and Usermode SCST
* * *
![SCST usermode service map](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_usermode_service_map.png
 "SCST Usermode Service Map")
* * *
![SCST usermode header and library inclusions](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_usermode_includes.png
"SCST Usermode Header and Library Inclusions")
* * *

**Diagram showing the datapath of SCST configured with iSCSI and vdisk_fileio**  
(either usermode or kernel-resident)
* * *
![SCST datapath](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_iSCSI_datapath.png
 "SCST Usermode Service Map")
* * *

