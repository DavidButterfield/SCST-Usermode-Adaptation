# SCST/usermode/Makefile
#
# This file directs SCST Makefiles to produce an SCST_USERMODE build of an
# iSCSI/VDISK SCST server to run entirely in usermode on an unmodified kernel.
#
# This Makefile expects its make(1) to be invoked in the Makefile's directory.

# XXX These usemode Makefiles are all hacked junk that need to be replaced.

### Run DRBD utilities with these environment variables set:
### PROC_DRBD=/fuse/proc/drbd
### UMC_DRBD_PID=<pid of drbd process>

#############  Defines for using TCMU plugins  #############

# Note: default if none of these is selected is to use aio(7) to file or bdev

  # Define USERMODE_TCMU to build SCST usermode with BLOCKIO under a TCMU plugin
  # USERMODE_TCMU = defined
USERMODE_BIO_TCMU = defined

  # Define one of these to select a TCMU plugin (use with USERMODE_TCMU)
  # USERMODE_TCMU_RBD = defined	    # Ceph RBD
USERMODE_TCMU_RAM = defined	    # RAM disk
  # USERMODE_TCMU_QEMU = defined    # QEMU QCOW
  # USERMODE_TCMU_GLFS = defined    # Gluster GLFS
  # USERMODE_TCMU_SPDK = defined    # Intel SPDK

################################################################################

# Usermode SCST depends on UMC (Usermode Compat) and MTE (Multithreaded Engine).
# You can pass in alternative source directories to override these defaults.
#
# Default source tree layout assumption:
#   a directory with these subdirectories: SCST  MTE  UMC
#
# (MTE only needs to be there if not installed on the system (in /usr/include).

ifndef MY_SRC
# Make for this Makefile should be running in SCST/usermode
MY_SRC = $(CURDIR)/../..
endif

# If libmte (Multithreaded Engine) is installed on the system, the sys_service
# API header files should be in /usr/include.  Otherwise SYS_SERVICE_INCL
# specifies where they are:
ifndef SYS_SERVICE_INCL
export SYS_SERVICE_INCL = $(shell if [ -d $(MY_SRC)/MTE/include ]; \
				  then echo -I$(MY_SRC)/MTE/include; \
				  fi)
endif

# If libmte (Multithreaded Engine) is not installed on the system, this is
# where its source code is.
ifndef MTE_SRC
export MTE_SRC = $(MY_SRC)/MTE/src
endif

# Path to the "emulated Linux KPI" usermode compatibility library
ifndef USERMODE_LIB_SRC
USERMODE_LIB_SRC = $(MY_SRC)/UMC/src
endif

# Path to the SCST source tree (which we are assumed at a location within)
ifndef SCST_SRC
export SCST_SRC = $(CURDIR)/..
endif

# Path to the DRBD source tree
ifndef DRBD_SRC
export DRBD_SRC = $(CURDIR)/..
endif

# Path to the DRBD utilities source tree
ifndef DRBD_UTIL_SRC
export DRBD_UTIL_SRC = $(CURDIR)/../../drbd-utils
endif

################################################################################

# LOCAL_CFLAGS are used when compiling linux usermode code -- it comprises other FLAGS below
# EXTRA_CFLAGS are used when compiling linux kernel code for usermode -- similar

# MY_CFLAGS are used when compiling anything: -O -DDEBUG -g -fPIC -D_GNU_SOURCE -DVALGRIND etc.
# EXTRA_WFLAGS are gcc -W options used when compiling anything

# SCSTU_CFLAGS passed as EXTRA_CFLAGS to Makefiles when compiling SCST kernel code for usermode
# DRBDU_CFLAGS passed as EXTRA_CFLAGS to Makefiles when compiling DRBD kernel code for usermode
# TCMU_CFLAGS used when compiling TCMU usermode code

# Explicit -O0 overrides other -O settings in subordinate Makefiles
MY_CFLAGS += -O0
# MY_CFLAGS += -Og
# MY_CFLAGS += -O1
# MY_CFLAGS += -O2
# MY_CFLAGS += -O3

# Enable assert/expect and some other checking and/or tracing
MY_CFLAGS += -DDEBUG
# MY_CFLAGS += -DNDEBUG

# MY_CFLAGS += -DTRACE_TRACE
# MY_CFLAGS += -DTRACE_VERBOSE
# MY_CFLAGS += -fprofile-arcs

# Disable most of the memory checks remaining when !DEBUG
# MY_CFLAGS += -DOPTIMIZED

# VALGRIND enables zeroing of allocated buffers; NVALGRIND elides all valgrind hooks
# MY_CFLAGS += -DVALGRIND
# MY_CFLAGS += -DNVALGRIND

################################################################################

SCSTU_CFLAGS += -DSCST_USERMODE			# Tell C source files to use SCST_USERMODE adaptations
# SCSTU_CFLAGS += -DSCST_USERMODE_AIO		# Prototype implemention of blockio using AIO
SCSTU_CFLAGS += -DCONFIG_SCST_TEST_IO_IN_SIRQ	# Allow I/O from soft-interrupt handlers
SCSTU_CFLAGS += -DCONN_LOCAL_READ		# Attempt conn read from pp_done handler
SCSTU_CFLAGS += -DCONN_SIRQ_READ		# Drive read directly off data_ready callback
# SCSTU_CFLAGS += -DADAPTIVE_NAGLE		# Experimental Adaptive Nagle optimization
						# (increase IOPS for CPU-bound workloads)
ifdef USERMODE_TCMU
SCSTU_CFLAGS += -DSCST_USERMODE_TCMU		# blockio using tcmu-runner backstore handlers
endif

# Directory containing header files for usermode compatibility for kernel code
SCSTU_CFLAGS += -I$(USERMODE_LIB_SRC)
DRBDU_CFLAGS += -I$(USERMODE_LIB_SRC)
TCMU_CFLAGS += -I$(USERMODE_LIB_SRC)

SCSTU_CFLAGS += $(SYS_SERVICE_INCL)	#XXX ?
DRBDU_CFLAGS += $(SYS_SERVICE_INCL)	#XXX ?

# Fiddle around with #include searching to get some from kernel and some from /usr/include;
# kinclude contains empty surrogate header files, and a few symlinks to real kernel headers;
# kinclude is created by the Makefile in USERMODE_LIB_SRC
SCSTU_CFLAGS += -isystem $(USERMODE_LIB_SRC)/kinclude
SCSTU_CFLAGS += -isystem /usr/include	#XXX ?
DRBDU_CFLAGS += -isystem $(USERMODE_LIB_SRC)/kinclude
# DRBDU_CFLAGS += -isystem /usr/include	#XXX ?

#######################  Enable most compiler warnings  ########################

# NOTES:
#   "-Wno-*" options negate noisy subsets of the first "-W" option seen on the same line.
#   counts mentioned below are of "distinct" warnings -- multiple warnings at the same file/line count as one

### SCST compiles clean (without warning messages) with these warnings enabled.
#	"-Wformat" warnings are entirely due to conflation of "long" and "long long" in format specifiers.
WFLAGS_WARN += -Wall	    -Wno-pointer-sign -Wno-format
WFLAGS_WARN += -Wextra	    -Wno-sign-compare -Wno-unused-parameter -Wimplicit-fallthrough=2
WFLAGS_WARN += -Wundef
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wold-style-definition
WFLAGS_WARN += -Wmissing-include-dirs
WFLAGS_WARN += -Wfloat-conversion
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wmissing-prototypes

WFLAGS_WARN += -Wunsafe-loop-optimizations
WFLAGS_WARN += -Wbad-function-cast
WFLAGS_WARN += -Wnested-externs
# WFLAGS_WARN += -Wswitch-enum
# WFLAGS_WARN += -fstrict-aliasing -Wstrict-aliasing

WFLAGS_WARN += -fsanitize=undefined

# DRBD does this to avoid uninitialized warnings!  XXX
#WFLAGS_WARN += -Winit-self

### These give varying numbers of warnings, probably not worth any effort
# WFLAGS_WARN += -Wshadow
# WFLAGS_WARN += -Wconversion  -Wno-sign-conversion
# WFLAGS_WARN += -Wswitch-default
# WFLAGS_WARN += -Wredundant-decls
# WFLAGS_WARN += -Wformat=2
# WFLAGS_WARN += -Wcast-qual
# WFLAGS_WARN += -Wwrite-strings
# WFLAGS_WARN += -Wpointer-arith

### DRBD
WFLAGS_WARN += -Wno-unused-variable         #XXX
WFLAGS_WARN += -Wno-unused-but-set-variable #XXX
WFLAGS_WARN += -Wno-unused-function         #XXX

export EXTRA_WFLAGS := $(WFLAGS_WARN) 

################################################################################

SHELL=/bin/bash

MY_CFLAGS += -g -fPIC -D_GNU_SOURCE
SCSTU_CFLAGS += $(MY_CFLAGS) $(EXTRA_WFLAGS)
DRBDU_CFLAGS += $(MY_CFLAGS) $(EXTRA_WFLAGS)
TCMU_CFLAGS += $(MY_CFLAGS) $(EXTRA_WFLAGS)

# Force scst_compat.h to be #included at the start of every SCST kernel.c file, for usermode shims
SCSTU_CFLAGS += -include $(SCST_SRC)/usermode/scst_compat.h

# Force drbd_compat.h to be #included at the start of every DRBD kernel.c file, for usermode shims
DRBDU_CFLAGS += -include $(DRBD_SRC)/usermode/drbd_compat.h

TCMU_CFLAGS += -I$(CURDIR)

# LOCAL_CFLAGS appears to be used instead of EXTRA_CFLAGS in real usermode makefiles
export LOCAL_CFLAGS += $(MY_CFLAGS) $(EXTRA_WFLAGS) -DSCST_USERMODE
export LOCAL_LIBS += -L/usr/local/lib -L/usr/lib/x86_64-linux-gnu -lubsan

export INFINIBAND_ENABLED := false
SCST_INC_DIR := $(CURDIR)/../scst/include
export src := .
export KVER = __NONE__

GCCLDFLAGS = -Wl,-z,now -Wl,-O1 -Wl,-L/usr/lib -Wl,-L/usr/lib/x86_64-linux-gnu/

ifdef USERMODE_TCMU_RBD
TCMU_LIBS = rbd.o
BACKEND_LIBS = -lrbd -lrados
endif

ifdef USERMODE_TCMU_RAM
TCMU_LIBS = ram.o
endif

ifdef USERMODE_TCMU_GLFS
TCMU_LIBS = glfs.o
BACKEND_LIBS = -lgfapi
endif

ifdef USERMODE_TCMU_QEMU
TCMU_LIBS = qcow.o
BACKEND_LIBS = -lz
endif

ifdef USERMODE_TCMU_SPDK
TCMU_LIBS = spdk.o
# BACKEND_LIBS = -lspdk_event -lspdk_conf -lspdk_trace		    # for DPDK event loop
BACKEND_LIBS = -lspdk_nvme -lspdk_nvmf -lspdk_env_dpdk -lspdk_log -lspdk_sock -lspdk_util
BACKEND_LIBS += -lrte_eal -lrte_mempool -lrte_bus_pci -lrte_pci -lrte_ring -lspdk_util -lrte_kvargs
BACKEND_LIBS += -lrte_cfgfile -lrte_cmdline -lrte_mbuf
BACKEND_LIBS += -luuid -lnuma -lrt
# BACKEND_LIBS += -lspdk_iscsi
endif

ifdef USERMODE_BIO_TCMU
TCMU_LIBS += bio_tcmu.o
endif

export SCST_USERMODE = 1		    # Tell sub-makefiles to do SCST_USERMODE build

usermode all:	cscope check_mte
	$(MAKE) -C $(USERMODE_LIB_SRC) all							    # UMC library
	EXTRA_CFLAGS="$(SCSTU_CFLAGS)" $(MAKE) -C $(SCST_SRC)/scst all				    # SCST CORE
	EXTRA_CFLAGS="$(SCSTU_CFLAGS)" $(MAKE) -C $(SCST_SRC)/scst/src/dev_handlers scst_vdisk.o    # SCST-VDISK
	EXTRA_CFLAGS="$(SCSTU_CFLAGS)" $(MAKE) -C $(SCST_SRC)/iscsi-scst all			    # iSCSI-SCST
	$(MAKE) drbd
	$(MAKE) scst.out
	# $(MAKE) drbd-utils

drbd-utils:
	EXTRA_CFLAGS="$(MY_CFLAGS) -DDO_NODE_PREEXISTS_CHECK=0 -DPROC_PREFIX=\\\"/fuse/scst\\\"" $(MAKE) -C $(DRBD_UTIL_SRC) all

drbd:	cscope
	EXTRA_CFLAGS="$(DRBDU_CFLAGS)" $(MAKE) -C $(DRBD_SRC)/drbd -f Makefile.usermode all

COMPONENTS := $(SCST_SRC)/scst/src/scst.o $(SCST_SRC)/scst/src/dev_handlers/scst_vdisk.o \
	      $(SCST_SRC)/iscsi-scst/kernel/iscsi-scst.o $(SCST_SRC)/iscsi-scst/usr/iscsi-scstlib.o \
	      $(DRBD_SRC)/drbd/drbd.o

USERMODE_LIB := $(USERMODE_LIB_SRC)/usermode_lib.o $(USERMODE_LIB_SRC)/UMC_fuse.o $(USERMODE_LIB_SRC)/UMC_genl.o

scst.out:   $(TCMU_LIBS) UMC_app.o drbd_compat.o #XXX $(COMPONENTS) made by 'all' target
	# Gather up all the objects we need from SCST kernel and daemon code;
	# Link SCST with the usermode compatibility module, libmte, and other libraries;
	$(CC) -o scst.out $(GCCLDFLAGS) \
		    $(COMPONENTS) \
		    UMC_app.o drbd_compat.o $(TCMU_LIBS) \
		    $(LOCAL_LIBS) $(BACKEND_LIBS) $(USERMODE_LIB) \
		    -lmte -lfuse -lpthread -laio -ldl -lc

check_mte:
	@# The libmte.so module should have been installed in /lib or somewhere .so files can be found
	@if [[ ! -f /lib/libmte.so ]] ; then $(MAKE) -C $(MTE_SRC) install; fi

%.o: %.c
	$(CC) -c -o $(@) $(TCMU_CFLAGS) $(<)

drbd_compat.o:	drbd_compat.c
	$(CC) -c -o $(@) $(DRBDU_CFLAGS) $(<)

# XXX Do dependencies right

bio_tcmu.o: bio_tcmu.c
	$(CC) -c -o $(@) $(TCMU_CFLAGS) -I$(USERMODE_LIB_SRC)/kinclude $(<)

ram.o:	scsi_defs.h bio_tcmu.h scstu_tcmu.h ram.c tcmu-runner.h libtcmu.h

rbd.o:	scsi_defs.h bio_tcmu.h scstu_tcmu.h rbd.c tcmu-runner.h libtcmu.h

glfs.o:	scsi_defs.h bio_tcmu.h scstu_tcmu.h darray.h glfs.c tcmu-runner.h libtcmu.h

qcow.o:	scsi_defs.h bio_tcmu.h scstu_tcmu.h qcow.c qcow.h qcow2.h tcmu-runner.h libtcmu.h

spdk.o: spdk.c spdk/stdinc.h spdk/nvme.h spdk/env.h tcmu-runner.h libtcmu.h

# XXX Add 2perf/2debug stuff

################################################################################

VALGRIND_OPTS = --leak-check=full --show-leak-kinds=all --num-callers=30 --track-fds=yes --sim-hints=no-nptl-pthread-stackcache --track-origins=yes
valgrind:
	PROC_PREFIX=/fuse/scst UMC_DRBD_PID=17 valgrind $(VALGRIND_OPTS) ./scst.out -f

clean:
	rm -rf *.o scst.out
	$(MAKE) -C .. $@
	$(MAKE) -C $(USERMODE_LIB_SRC) $@
	$(MAKE) -C $(DRBD_SRC)/drbd -f Makefile.usermode $@
	$(MAKE) -C $(DRBD_UTIL_SRC) $@

extraclean:
	rm -rf *.o scst.out
	rm -rf tags cscope.out
	$(MAKE) -C $(USERMODE_LIB_SRC) $@
	$(MAKE) -C $(DRBD_SRC)/drbd -f Makefile.usermode $@
	$(MAKE) -C $(DRBD_UTIL_SRC) distclean
	$(MAKE) -C .. $@

cscope:
	@cscope -b -c -R -s$(USERMODE_LIB_SRC) -s$(SCST_SRC) -s$(MTE_SRC)
	@ctags        -R   $(USERMODE_LIB_SRC)   $(SCST_SRC)   $(MTE_SRC)

ls:
	@ls     -ad Make* `find -L $(USERMODE_LIB_SRC) $(SCST_SRC) -type f | egrep "Make|\.[ch]$$" | egrep -v "\.mod\.c$$"`

l:
	@ls -lsrtad Make* `find -L $(USERMODE_LIB_SRC) $(SCST_SRC) -type f | egrep "Make|\.[ch]$$" | egrep -v "\.mod\.c$$"`

.PHONY:	all components check_mte valgrind clean extraclean cscope ls l

##### Copied from drbd/Kbuild #####
# for some reason some of the commands below only work correctly in bash,
# and not in e.g. dash. I'm too lazy to fix it to be compatible.
SHELL=/bin/bash
$(obj)/drbd_buildtag.c: $(addprefix $(obj)/,$(filter-out drbd_buildtag.o,$(drbd-y)))
	@$(kecho) '  GEN     $@ $(echo-why)'
	@set -e; exec > $@.new;							\
	echo -e "/* automatically generated. DO NOT EDIT. */";			\
	echo -e "#include <linux/drbd.h>";					\
	echo -e "#include <linux/drbd_config.h>";				\
	echo -e "const char *drbd_buildtag(void)\n{";				\
	if test -e $(src)/../.git &&						\
	   GITHEAD=$$(cd $(src) && git rev-parse HEAD); then			\
		GITDIFF=$$(cd $(src)/.. && git diff --name-only HEAD |		\
			tr -s '\t\n' '  ' |					\
			sed -e 's/^/ /;s/ *$$//');				\
		echo -e "\treturn \"GIT-hash: $$GITHEAD$$GITDIFF\"";		\
	elif test -e $(src)/.drbd_git_revision ; then				\
		echo -e "\treturn \"$$(cat $(src)/.drbd_git_revision)\"";	\
	elif test -e $@ ; then							\
		grep return $@ ;						\
	else									\
		echo >&2 "Your DRBD source tree is broken. Unpack again.";      \
		exit 1;								\
	fi ;									\
	if [ -z "${WANT_DRBD_REPRODUCIBLE_BUILD}" ] || [ -z "${SOURCE_DATE_EPOCH}" ] ; then	\
		buildinfo="build by $$USER@$$HOSTNAME, `date "+%F %T"`" ;			\
	else 											\
		buildinfo="reproducible build, `date -u -d@${SOURCE_DATE_EPOCH} "+%F %T"`" ; 	\
	fi ; 											\
	echo -e "\t\t\" $$buildinfo\";\n}";							\
	mv -f $@.new $@
