David Butterfield began programming for usermode in 2008 after a prior
gigasecond or so working on software in various versions of the Unix and
Solaris kernels (or without any kernel). He holds an MSc in Computer
Science from UCLA, where his undergraduate degree was in Mathematics and
Computer Science.

One of the founders of Locus Computing Corporation, he designed the first
Virtual Machine Monitor for x86, to "Merge" MS-DOS and its applications
under Unix SVR2; and led an engineering team in its implementation. The
OS-Merge product was first marketed by AT&T under the name "Simultask" on
their 6300+ (IBM AT clone) model. [Sometime after his involvement that
evolved into two descendant products, NeTraverse Merge and Win4Lin]

He joined Sun Microsystems to establish and lead the first Solaris x86
device driver development team, later accepting an international
assignment to Dublin, Ireland to start a driver engineering team there.
After returning to the U.S. he was responsible for the software
architecture for Sun's Network Storage Division for several years.

At LeftHand Networks he contributed many performance improvements to the
SAN/iQ event-driven distributed storage application, introducing
application-transparent multi-threading into the existing single-threaded
event-driven framework and devising other optimizations amounting in total
to a 2.5x increase in throughput (IOPS) capability.

His most recent (independent) project relocates the iSCSI-SCST storage
server software from the Linux kernel to run entirely in usermode, with no
changes to the existing logic.  This reuses 80,000 lines of an existing,
very stable implementation of the iSCSI and SCSI (SPC and SBC) protocols,
in a way that preserves the maturity of the code.  This was done by
writing 10,000 lines of supporting code (in C, of course) to emulate the
necessary kernel functions utilized by the server software.

The server accesses local storage through the usual preadv/pwritev(2)
system calls or using the aio(7) facility.  Alternatively it can be used
to access sophisticated storage backend services such as Ceph, QEMU, or
Gluster through their usermode block-storage client interfaces and
tcmu-runner backstore handlers.

The code, diagrams, and a paper describing the work and performance study are
[here](https://github.com/DavidButterfield/SCST-Usermode-Adaptation "Code").
