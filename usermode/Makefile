# SCST/trunk/usermode/Makefile
#
# This file directs SCST Makefiles to produce an SCST_USERMODE build of an
# iSCSI/VDISK SCST server to run entirely in usermode on an unmodified kernel.
#
# This Makefile expects its make(1) to be invoked in the Makefile's directory.

# Usermode SCST depends on UMC (Usermode Compat) and MTE (Multithreaded Engine).
# You can pass in alternative source directories to override these defaults.
#
# Default source tree layout assumption:
#   a directory with these subdirectories: SCST/trunk  MTE/trunk  UMC/trunk
#
# (MTE only needs to be there if not installed on the system (in /usr/include).

ifndef MY_SRC
# Make for this Makefile should be running in SCST/trunk/usermode
MY_SRC = $(CURDIR)/../../..
endif

# If libmte (Multithreaded Engine) is installed on the system, the sys_service
# API header files should be in /usr/include.  Otherwise SYS_SERVICE_INCL
# specifies where they are:
ifndef SYS_SERVICE_INCL
export SYS_SERVICE_INCL = $(shell if [ -d $(MY_SRC)/MTE/trunk/include ]; \
				  then echo -I$(MY_SRC)/MTE/trunk/include; \
				  fi)
endif

# If libmte (Multithreaded Engine) is not installed on the system, this is
# where its source code is.
ifndef MTE_SRC
export MTE_SRC = $(MY_SRC)/MTE/trunk/src
endif

# Path to the "emulated Linux KPI 2.6.24" usermode compatibility library
ifndef USERMODE_LIB_SRC
USERMODE_LIB_SRC = $(MY_SRC)/UMC/trunk/src
endif

# Path to the SCST source tree (which we are assumed at a location within)
ifndef SCST_SRC
export SCST_SRC = $(CURDIR)/..
endif

# MY_CFLAGS are used when compiling the kernel code or daemon code
# EXTRA_CFLAGS are used when compiling the kernel code

MY_CFLAGS += -O3
# MY_CFLAGS += -O2
# MY_CFLAGS += -O1

# Enable assert/expect and some other checking and/or tracing
# MY_CFLAGS += -DDEBUG
# MY_CFLAGS += -DTRACE_TRACE
# MY_CFLAGS += -DTRACE_VERBOSE

# Disable most of the memory checks remaining when !DEBUG
# MY_CFLAGS += -DOPTIMIZED

# VALGRIND enables zeroing of allocated buffers; NVALGRIND elides all valgrind hooks
# MY_CFLAGS += -DVALGRIND
# MY_CFLAGS += -DNVALGRIND

################################################################################

MY_CFLAGS += -DSCST_USERMODE			# Tell C source files to use SCST_USERMODE adaptations
MY_CFLAGS += $(SYS_SERVICE_INCL)

EXTRA_CFLAGS += -DCONFIG_SCST_TEST_IO_IN_SIRQ	# Allow I/O from soft-interrupt handlers
EXTRA_CFLAGS += -DCONN_LOCAL_READ		# Attempt conn read from pp_done handler
EXTRA_CFLAGS += -DCONN_SIRQ_READ		# Drive read directly off data_ready callback
EXTRA_CFLAGS += -DSCST_USERMODE_AIO		# Prototype implemention of blockio using AIO
# EXTRA_CFLAGS += -DADAPTIVE_NAGLE		# Experimental Adaptive Nagle optimization

# Force scst_compat.h to be #included at the start of every kernel.c file, for usermode shims
EXTRA_CFLAGS += -include $(SCST_SRC)/usermode/scst_compat.h

# Directory containing header files for usermode compatibility for kernel code
EXTRA_CFLAGS += -I$(USERMODE_LIB_SRC)

# Fiddle around with #include searching to get some from kernel and some from /usr/include;
# kinclude contains empty surrogate header files, and a few symlinks to real kernel headers;
# kinclude is created by the Makefile in USERMODE_LIB_SRC
EXTRA_CFLAGS += -isystem $(USERMODE_LIB_SRC)/kinclude
EXTRA_CFLAGS += -isystem /usr/include

# XXXXX bletch
EXTRA_CFLAGS += -isystem /usr/lib/gcc/x86_64-linux-gnu/5/include-fixed

#######################  Enable most compiler warnings  ########################

WFLAGS_WARN += -Wall
WFLAGS_WARN += -Wextra
WFLAGS_WARN += -Wundef
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wmissing-prototypes
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Winit-self
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wbad-function-cast
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wnested-externs
WFLAGS_WARN += -Wold-style-definition 
WFLAGS_WARN += -Wmissing-include-dirs
WFLAGS_WARN += -Wfloat-conversion

### Inhibit (or leave unenabled) some warnings for now because they are too noisy today
                                                # Number of Warnings
# WFLAGS_WARN += -Wunsafe-loop-optimizations	#    1
# WFLAGS_WARN += -Wredundant-decls		#    3
# WFLAGS_WARN += -Wswitch-enum			#   39

### These format warnings all have to do with using a long value with a long long specifier
# WFLAGS_WARN += -Wformat=2			#   68, all %ll[dux] with [unsigned] long
WFLAGS_INHIBIT += -Wno-format			#     	(all)

### These are probably not worth much effort, but maybe a check that the code looks OK
# WFLAGS_WARN += -Wcast-qual			#   71
# WFLAGS_WARN += -Wswitch-default		#   59
# WFLAGS_WARN += -Wshadow			#   21

### These are probably not worth any effort
# WFLAGS_WARN += -Wwrite-strings		#   27	gives strings a "const"
						#	leading to "discarded-qualifiers"
WFLAGS_INHIBIT += -Wno-pointer-sign             #   48  (all)
WFLAGS_INHIBIT += -Wno-sign-compare             #   64	(extra)
# WFLAGS_WARN += -Wpointer-arith		#   67	(pedandic)
WFLAGS_INHIBIT += -Wno-unused-parameter		#   73	(extra)
# WFLAGS_WARN += -Wconversion			#  746
# WFLAGS_INHIBIT += -Wno-sign-conversion        # 1960	(conversion)

export EXTRA_WFLAGS := $(WFLAGS_WARN) $(WFLAGS_INHIBIT)
export EXTRA_CFLAGS := $(EXTRA_CFLAGS) $(EXTRA_WFLAGS)

################################################################################

SHELL=/bin/bash

MY_CFLAGS += -g -fPIC -D_GNU_SOURCE $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

# EXTRA_CFLAGS is used in kernel makefiles
export EXTRA_CFLAGS += $(MY_CFLAGS)

# LOCAL_CFLAGS appears to be used instead of EXTRA_CFLAGS in real usermode makefiles
export LOCAL_CFLAGS += $(MY_CFLAGS)

export INFINIBAND_ENABLED := false
export SCST_INC_DIR := $(CURDIR)/../scst/include
export src := .
export KVER = __NONE__

GCCLDFLAGS = -Wl,-z,now -Wl,-O1

export SCST_USERMODE = 1		    # Tell sub-makefiles to do SCST_USERMODE build

usermode all:	cscope check_mte
	$(MAKE) -C $(USERMODE_LIB_SRC) all				# UMC library
	$(MAKE) -C $(SCST_SRC)/scst all					# SCST CORE
	$(MAKE) -C $(SCST_SRC)/scst/src/dev_handlers scst_vdisk.o	# SCST-VDISK
	$(MAKE) -C $(SCST_SRC)/iscsi-scst all				# iSCSI-SCST
	$(MAKE) scst.out

COMPONENTS := $(SCST_SRC)/scst/src/scst.o $(SCST_SRC)/scst/src/dev_handlers/scst_vdisk.o \
	      $(SCST_SRC)/iscsi-scst/kernel/iscsi-scst.o $(SCST_SRC)/iscsi-scst/usr/iscsi-scstlib.o

scst.out:   $(COMPONENTS)
	# Gather up all the objects we need from SCST kernel and daemon code;
	# Link SCST with the usermode compatibility module, libmte, and other libraries;
	$(CC) -o scst.out $(GCCLDFLAGS) $(COMPONENTS) $(USERMODE_LIB) -lmte -lpthread -laio -ldl -lfuse -lc

USERMODE_LIB := $(USERMODE_LIB_SRC)/usermode_lib.o $(USERMODE_LIB_SRC)/pde_fuse.o

check_mte:
	# The libmte.so module should have been installed in /lib or somewhere .so files can be found
	if [[ ! -f /lib/libmte.so ]] ; then $(MAKE) -C $(MTE_SRC) install; fi

# XXX Add 2perf/2debug stuff

################################################################################

VALGRIND_OPTS = --leak-check=full --show-leak-kinds=all --num-callers=30 --track-fds=yes --sim-hints=no-nptl-pthread-stackcache --track-origins=yes
valgrind:
	valgrind $(VALGRIND_OPTS) ./scst.out -f

clean:
	rm -rf scst.out
	make -C .. $@

extraclean:
	rm -rf scst.out
	rm -rf tags cscope.out
	make -C .. $@

cscope:
	@cscope -b -c -R -s$(USERMODE_LIB_SRC) -s$(SCST_SRC)
	@ctags        -R   $(USERMODE_LIB_SRC)   $(SCST_SRC)   $(SYS_SERVICE_INCL)

ls:
	@ls     -ad Make* `find -L $(USERMODE_LIB_SRC) $(SCST_SRC) -type f | egrep "Make|\.[ch]$$" | egrep -v "\.mod\.c$$"`

l:
	@ls -lsrtad Make* `find -L $(USERMODE_LIB_SRC) $(SCST_SRC) -type f | egrep "Make|\.[ch]$$" | egrep -v "\.mod\.c$$"`

.PHONY:	all components check_mte valgrind clean extraclean cscope ls l
