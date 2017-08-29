# SCST-Usermode-Adaptation
**SCST iSCSI Storage Server Usermode Adaptation**  
An adaptation of the iSCSI-SCST storage server software to run entirely in usermode on an unmodified Linux kernel  
*David A. Butterfield*

<SMALL>
Branches:
 + scst_base  - unmodified source from SCST repository that the two branches below are based on
 + SCST_fixes - generic changes to SCST source (for both usermode and kernel-resident builds) [included in usermode]
 + usermode   - SCST Usermode supports tcmu-runner backstore handlers as well as local files and block devices

Old Branch:
 + master     - the original work described by the paper, supporting local files and block devices for backstore
</SMALL>

This project adapts the SCST iSCSI storage server software, which normally
resides in the Linux kernel, to run entirely in usermode on an unmodified
kernel.  The resulting executable can run as a regular (non-super) user, as long
as it has permission to access the backing storage.  A paper describing the work
and performance study is
[here](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_Usermode.html
       "A paper describing the work in detail").

The left side of the diagram below shows the original "in-kernel" configuration
alongside the adapted "usermode" configuration.

Additional work done since that report implements an "scst_tcmur" interface
module allowing SCST_Usermode to access backing storage using the same
interface used by the LIO tcmu-runner facility.  Through this backstore handler
interface, SCST_Usermode can utilize backing storage implemented by any of
Ceph/RBD, QEMU/qcow, Gluster/glfs, or Intel/SPDK.

The right side of the diagram below shows the Linux kernel-resident LIO
implementation alongside the SCST_Usermode implemention, both sharing a common
set of tcmu-runner backstore handlers.

* * *
![SCST Usermode Adaptation and tcmu-runner backend driver](https://github.com/DavidButterfield/SCST-Usermode-Adaptation/blob/usermode/usermode/scstu_tcmur.png
 "SCST Usermode Adaptation and tcmu-runner backend driver")
* * *

The adaptation uses about 80,000 lines of the SCST source code, a subset
supporting the iSCSI transport type (via socket calls), and SCSI Block Commands
(vdisk_fileio) backed by either a file or a block device.

**The SCST iSCSI Usermode Adaptation depends on**  
 + [Usermode Compatibility (UMC)](https://github.com/DavidButterfield/usermode_compat#user-content-usermode_compat
                                 "Usermode Compatibility for Linux Kernel Code (UMC)")
    &mdash; a shim for running some Linux kernel code in usermode
 + [Multithreaded Engine (MTE)](https://github.com/DavidButterfield/MTE#user-content-mte "Multithreaded Engine (libmte)")
    &mdash; a high-performance multi-threaded event dispatching engine for usermode
 + SCST files in the master branch of this repo began as a snapshot of
   [https://sourceforge.net/projects/scst](https://sourceforge.net/projects/scst "SCST svn -r7105")
   /scst and /iscsi-scst svn -r7105.
 + To support usermode, about 300 lines of changes were made to the SCST snapshot files (mostly under #ifdef)
 + Additional changes: AIO, optimizations for usermode (under #ifdef), and some fixes and XXX comments for SCST
 + A little more work would be required to run on architectures other than x86
 + Possibly less work would be needed to run on non-Linux POSIX systems having gcc and the libraries
 + It shouldn't matter much, but I have only tested with these:
    * Linux 3.13.0-101-generic #148-Ubuntu SMP x86_64
    * Linux 4.4.0-70-generic    #91-Ubuntu SMP x86_64 GNU/Linux
    * Linux 4.8.0-46-generic    #49-Ubuntu SMP x86_64 GNU/Linux

**Hints to help get started running iSCSI-SCST in usermode**  
<SMALL>(This is rather terse; some existing familiarity with SCST will be helpful)</SMALL>

      # apt install libaio-dev              # required
      # apt install libfuse-dev             # required
      # apt install subversion              # or github accessor of your choice
      # apt install cscope                  # (optional with makefile edit)
      # apt install exuberant-ctags         # (optional with makefile edit)
      # apt install valgrind                # (optional)

      $ mkdir Usermode_SCST ; cd Usermode_SCST   # or use whatever name you want for this one
      $ svn co https://github.com/DavidButterfield/MTE.git MTE   # Makefile expects these names
      $ svn co https://github.com/DavidButterfield/usermode_compat.git UMC
      $ svn co https://github.com/DavidButterfield/SCST-Usermode-Adaptation.git SCST

      $ more SCST/trunk/usermode/BUGS.txt   # ** MORE HINTS **

      $ pushd MTE/trunk/src                 # build the Multithreaded Engine library
      $ make
      $ sudo make install                   # needs permission for /lib, /usr/include
      $ popd

      $ cd SCST/trunk
      $ sudo make scstadm_install           # patched to know where /fuse/scst/proc is
      $ make enable_proc                    # configure so it can compile for usermode

      $ cd usermode
      $ make                                # build the SCST iSCSI server binary
      $ ls -l scst.out                      # in SCST/trunk/usermode/

      ### Manually create /etc/{iscsi-scst,scst_usermode}.conf in SCST /proc format (See *.sample)

      # mkdir -p  /var/lib/scst/vdev_mode_pages /var/lib/scst/pr
      # chmod 777 /var/lib/scst/vdev_mode_pages /var/lib/scst/pr   # or writable by SCST's UID

      # mkdir -p /fuse/scst/proc ; chmod 777 /fuse/scst/proc       # mount point for SCST's /proc
      ### Edit /etc/fuse.conf and uncomment the line with "user_allow_other"

      $ [ gdb | valgrind ] ./scst.out -f    # run as normal user, with or without accessories
In another terminal window

      # scstadmin -config /etc/scst_usermode.conf
      # ls -l `find /fuse -type f`
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
