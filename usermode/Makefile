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
export SYS_SERVICE_INCL = $(MY_SRC)/MTE/trunk/include
endif

# Path to the "emulated Linux KPI 2.6.24" usermode compatibility library
ifndef USERMODE_LIB_SRC
USERMODE_LIB_SRC = $(MY_SRC)/UMC/trunk/src
endif

# Path to the SCST source tree (which we are assumed at a location within)
ifndef SCST_SRC
export SCST_SRC = $(CURDIR)/..
endif

# MY_CFLAGS += -O3
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

MY_CFLAGS += -DSCST_USERMODE		    # Tell C source files to use SCST_USERMODE adaptations
MY_CFLAGS += -DCONFIG_SCST_TEST_IO_IN_SIRQ  # Allow I/O from soft-interrupt handlers
MY_CFLAGS += -DCONN_LOCAL_READ		    # Attempt conn read from pp_done handler
MY_CFLAGS += -DCONN_SIRQ_READ		    # Drive read directly off data_ready callback
# MY_CFLAGS += -DSCST_USERMODE_AIO	    # Prototype implemention of blockio using AIO

# Select /proc model rather than /sys model (simulating 2.6.24, which has no sysfs)
MY_CFLAGS += -DCONFIG_SCST_PROC

ifdef SYS_SERVICE_INCL
MY_CFLAGS += -I$(SYS_SERVICE_INCL)
endif

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
WFLAGS_WARN += -Winit-self
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wold-style-definition 
WFLAGS_WARN += -Wredundant-decls
WFLAGS_WARN += -Wbad-function-cast
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wmissing-prototypes
WFLAGS_WARN += -Wnested-externs
WFLAGS_WARN += -Wswitch-enum

### Inhibit (or leave unenabled) some warnings for now because they are too noisy today
						# Number of Warnings
# WFLAGS_WARN += -Wmissing-include-dirs		#  2
# WFLAGS_WARN += -Wunsafe-loop-optimizations	#  1

# WFLAGS_WARN += -Wcast-qual			# 75 (60 of those are "container_of")
# WFLAGS_WARN += -Wwrite-strings		# 75 (same ones as -Wcast-qual)

WFLAGS_INHIBIT += -Wno-redundant-decls		# 37

### These format warnings all have to do with using a long value with a long long specifier
# WFLAGS_WARN += -Wformat=2			# 44, all %ll[dux] with [unsigned] long
WFLAGS_INHIBIT += -Wno-format			# all these warnings occur also with -Wformat[=1]

### These are probably not worth much effort, but maybe a check that the code looks OK
# WFLAGS_WARN += -Wpointer-arith		# 38			(XXX half mine)
# WFLAGS_WARN += -Wshadow			# 25
# WFLAGS_WARN += -Wswitch-default		# 56 

### These are probably not worth any effort
# WFLAGS_WARN += -Wconversion			# 500+
# WFLAGS_WARN += -Wsign-conversion		# 500+
WFLAGS_INHIBIT += -Wno-sign-compare		# 29
WFLAGS_INHIBIT += -Wno-pointer-sign		# 37

WFLAGS_INHIBIT += -Wno-unused-parameter		# silly

################################################################################

MY_CFLAGS += -g -D_GNU_SOURCE $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

# EXTRA_CFLAGS is used in kernel makefiles
export EXTRA_CFLAGS += $(MY_CFLAGS)

# LOCAL_CFLAGS appears to be used instead of EXTRA_CFLAGS in real usermode makefiles
export LOCAL_CFLAGS += $(MY_CFLAGS)

export SCST_USERMODE = 1		    # Tell sub-makefiles to do SCST_USERMODE build
export INFINIBAND_ENABLED := false
export SCST_INC_DIR := $(CURDIR)/../scst/include
export src := .
export KVER = __NONE__

USERMODELIB = $(USERMODE_LIB_SRC)/usermode_lib.o $(USERMODE_LIB_SRC)/pde_fuse.o
GCCLDFLAGS = -Wl,-z,now -Wl,-O1

all:
	$(MAKE) cscope
	# The libmte.so module should have been installed in /lib or somewhere .so files can be found
	bash -c "if [[ ! -f /lib/libmte.so ]] ; then $(MAKE) -C $(MTE_SRC) all; fi"
	$(MAKE) -C $(USERMODE_LIB_SRC) all
	$(MAKE) -C $(SCST_SRC)/scst all
	$(MAKE) -C $(SCST_SRC)/scst/src/dev_handlers scst_vdisk.o
	$(MAKE) -C $(SCST_SRC)/iscsi-scst all
	#
	# Gather up all the objects we need from SCST kernel and daemon code;
	# Link SCST with the usermode compatibility module, libmte, and other libraries;
	$(CC) -o scst.out $(GCCLDFLAGS) \
		$(SCST_SRC)/scst/src/scst.o $(SCST_SRC)/scst/src/dev_handlers/scst_vdisk.o \
		$(SCST_SRC)/iscsi-scst/kernel/iscsi-scst.o $(SCST_SRC)/iscsi-scst/usr/iscsi-scstlib.o \
		$(USERMODELIB) -lmte -lpthread -laio -ldl -lfuse -lc

################################################################################

VALGRIND_OPTS = --leak-check=full --show-leak-kinds=all --num-callers=30 --track-fds=yes --sim-hints=no-nptl-pthread-stackcache --track-origins=yes
valgrind:
	valgrind $(VALGRIND_OPTS) ./scst.out -f

clean:
	rm -rf scst.out scst_usermode.o

extraclean: clean
	rm -rf tags cscope.out

cscope:
	@$(MAKE) -j1 -C . _cscope

_cscope:
	@cscope -b -c -R -s$(USERMODE_LIB_SRC) -s$(SCST_SRC) -s$(SYS_SERVICE_INCL)
	@ctags        -R   $(USERMODE_LIB_SRC)   $(SCST_SRC)   $(SYS_SERVICE_INCL)

ls:
	@ls     -ad Make* `find -L $(USERMODE_LIB_SRC) $(SCST_SRC) $(SYS_SERVICE_INCL) -type f | egrep "Make|\.[ch]$$" | egrep -v "\.mod\.c$$"`

l:
	@ls -lsrtad Make* `find -L $(USERMODE_LIB_SRC) $(SCST_SRC) $(SYS_SERVICE_INCL) -type f | egrep "Make|\.[ch]$$" | egrep -v "\.mod\.c$$"`

