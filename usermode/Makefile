# SCST/usermode/Makefile
#
# This file directs SCST Makefiles to produce an SCST_USERMODE build of an
# iSCSI/VDISK SCST server to run entirely in usermode on an unmodified kernel.
# This Makefile expects its make(1) to be invoked in the Makefile's directory.
#
# DRBD is also now also built into the same usermode binary as SCST.
#
#   ## Run server and DRBD utilities with environment variable set, e.g.:
#   ##		export UMC_FS_ROOT=/UMCfuse
#
# Backend storage is provided by loadable tcmu-runner handlers.  Each backend
# device has a node in a mounted FUSE filesystem available for read/write/mount.
#
# XXX These usermode Makefiles are all hacked junk that need to be replaced.

# The usermode server depends on UMC (Usermode Compat), MTE (Multithreaded
# Engine), tcmu-runner, and a reference kernel.  You can pass in alternative
# source directories to override these defaults.
#
# Default source tree layout assumption --
# A directory with these subdirectories (containing git clones):
#   MTE		    (only needed if MTE headers not installed in /usr/include)
#   usermode_compat
#   SCST-Usermode-Adaptation 
#   drbd-9.0
#   drbd-utils
#   tcmu-runner
#   linux-2.6.32.27

ifndef MY_SRC
# Make for this Makefile should be running in SCST/usermode
MY_SRC = $(CURDIR)/../..
endif

# If libmte (Multithreaded Engine) is installed on the system, the sys_service
# API header files should be in /usr/include.  Otherwise SYS_SERVICE_INCL
# specifies where they are:
ifndef SYS_SERVICE_INCL
export SYS_SERVICE_INCL = $(shell if [ -d $(MY_SRC)/MTE/include ]; \
				  then echo $(MY_SRC)/MTE/include; \
				  fi)
endif

# If libmte (Multithreaded Engine) is not installed on the system, this is
# where its source code is.
ifndef MTE_SRC
export MTE_SRC = $(MY_SRC)/MTE/src
endif

# Path to the "emulated Linux KPI" usermode compatibility library
ifndef USERMODE_LIB_SRC
export USERMODE_LIB_SRC = $(MY_SRC)/usermode_compat/src
endif

# Path to the SCST source tree (which we are assumed at a location within)
ifndef SCST_SRC
export SCST_SRC = $(MY_SRC)/SCST-Usermode-Adaptation
endif

# Path to the DRBD source tree
ifndef DRBD_SRC
export DRBD_SRC = $(MY_SRC)/drbd-9.0
endif

# Path to the DRBD utilities source tree
ifndef DRBD_UTIL_SRC
export DRBD_UTIL_SRC = $(MY_SRC)/drbd-utils
endif

# Path to the tcmu-runner source tree
ifndef TCMUR_SRC
export TCMUR_SRC = $(MY_SRC)/tcmu-runner
endif

# Path to the reference kernel source
ifndef REF_KERNEL
export REF_KERNEL = $(MY_SRC)/linux-2.6.32.27
endif

################################################################################

# Target: x86_64-linux-gnu gcc version 8.3.0 (Ubuntu 8.3.0-6ubuntu1) 
# XXX Dynamic builds break addr2line stacktraces
# XXX Static builds break memory initialization for valgrind
BUILD_STATIC=defined	    # XXX

# Enable assert/expect and some other checking and/or tracing
MY_CFLAGS += -DDEBUG

# -fsanitize catches runtime errors but makes disassembly virtually useless
MY_CFLAGS += -fsanitize=undefined
# MY_CFLAGS += -DNDEBUG

# MY_CFLAGS += -DTRACE_TRACE
# MY_CFLAGS += -DTRACE_VERBOSE
# MY_CFLAGS += -fprofile-arcs

MY_CFLAGS += -O0
# MY_CFLAGS += -Og	# -Og interferes with debugging with "<optimized out>"
# MY_CFLAGS += -O1
# MY_CFLAGS += -O2 -fno-strict-aliasing
# MY_CFLAGS += -O3 -fno-strict-aliasing

# Disable most of the memory checks remaining when !DEBUG
# MY_CFLAGS += -DOPTIMIZED

# VALGRIND enables zeroing of allocated buffers; NVALGRIND elides all valgrind hooks
# MY_CFLAGS += -DVALGRIND -DARENA_DISABLE=1
# MY_CFLAGS += -DNVALGRIND

################################################################################

# LOCAL_CFLAGS are used when compiling linux usermode code -- it comprises other FLAGS below
# EXTRA_CFLAGS are used when compiling linux kernel code for usermode -- similar

# MY_CFLAGS are used when compiling anything: -O -DDEBUG -g -fPIC -DVALGRIND etc.
# EXTRA_WFLAGS are gcc -W options used when compiling anything

# SCSTU_CFLAGS passed as EXTRA_CFLAGS to Makefiles when compiling SCST kernel code for usermode
# DRBDU_CFLAGS passed as EXTRA_CFLAGS to Makefiles when compiling DRBD kernel code for usermode

SCSTU_CFLAGS += -DSCST_USERMODE			# Tell C source files to use SCST_USERMODE adaptations
SCSTU_CFLAGS += -DCONFIG_SCST_TEST_IO_IN_SIRQ	# Allow I/O from soft-interrupt handlers
SCSTU_CFLAGS += -DCONN_LOCAL_READ		# Attempt conn read from pp_done handler
SCSTU_CFLAGS += -DCONN_SIRQ_READ		# Drive read directly off data_ready callback

# SCSTU_CFLAGS += -DADAPTIVE_NAGLE		# Experimental Adaptive Nagle optimization
						# (increase IOPS for CPU-bound workloads)

DRBDU_CFLAGS += -DDRBD_USERMODE			# Tell C source files to use DRBD_USERMODE adaptations

# Directory containing header files for usermode compatibility for kernel code
SCSTU_CFLAGS += -I$(USERMODE_LIB_SRC)
DRBDU_CFLAGS += -I$(USERMODE_LIB_SRC)

SCSTU_CFLAGS += -I$(SYS_SERVICE_INCL)
DRBDU_CFLAGS += -I$(SYS_SERVICE_INCL)

# Fiddle around with #include searching to get some from kernel and some from /usr/include;
# include contains empty surrogate header files, and copies of a few real kernel headers;
# include is created by the Makefile in USERMODE_LIB_SRC
SCSTU_CFLAGS += -I$(USERMODE_LIB_SRC)/arch/x86/include -I$(USERMODE_LIB_SRC)/include
DRBDU_CFLAGS += -I$(USERMODE_LIB_SRC)/arch/x86/include -I$(USERMODE_LIB_SRC)/include

#######################  Enable most compiler warnings  #######################

# Warnings enabled by a real kernel build
WFLAGS_WARN += -Wall
WFLAGS_WARN += -Wmissing-prototypes
WFLAGS_WARN += -Wstrict-prototypes
WFLAGS_WARN += -Wundef
WFLAGS_INHIBIT += -Wno-pointer-sign			# in SCST and DRBD

# Warnings passed by all components
WFLAGS_WARN += -Wextra
WFLAGS_WARN += -Wjump-misses-init
WFLAGS_WARN += -Wlogical-op
WFLAGS_WARN += -Wcast-align
WFLAGS_WARN += -Wold-style-definition 
WFLAGS_WARN += -Wmissing-include-dirs
WFLAGS_WARN += -Wfloat-conversion
WFLAGS_WARN += -Wmissing-declarations
WFLAGS_WARN += -Wnested-externs
WFLAGS_WARN += -Wunsafe-loop-optimizations

### Some of each of these in DRBD and/or SCST code (at least when compiled for usermode)
# WFLAGS_WARN += -Winit-self				# DRBD
# WFLAGS_WARN += -Wswitch-enum
# WFLAGS_WARN += -Wredundant-decls			# SCST and DRBD

WFLAGS_INHIBIT += -Wno-format		# kernel conflation of "long" and "long long" in format specifiers

WFLAGS_INHIBIT += -Wno-shift-negative-value		# one in drbd_main.c
WFLAGS_INHIBIT += -Wno-logical-op			# one in drbd_receiver.c

# This only warns if -fstrict-aliasing is enabled (e.g. by -O2), in which case the warning is important
WFLAGS_WARN += -Wstrict-aliasing			# DRBD

WFLAGS_INHIBIT += -Wno-unused-function			#XXX artifact of usermode port
WFLAGS_INHIBIT += -Wno-unused-variable			#XXX artifact of usermode port

### Some of each of these in MTE or UMC code
# WFLAGS_WARN += -Wconversion
# WFLAGS_WARN += -Wsign-conversion
# WFLAGS_WARN += -Wpointer-arith
# WFLAGS_WARN += -Wwrite-strings

### Some of each of these in code included from reference kernel 2.6.32
# WFLAGS_WARN += -Wswitch-default			# 1 in lib/bitmap.c
# WFLAGS_WARN += -Wcast-qual				# several in reference kernel files
# WFLAGS_WARN += -Wbad-function-cast			# 1 in linux/kernel.h
# WFLAGS_WARN += -Wshadow				# kernel.h, bitops.h
WFLAGS_INHIBIT += -Wno-sign-compare			# 3 in net/netlink.h, 1 in linux/skbuff.h
WFLAGS_INHIBIT += -Wno-implicit-fallthrough		# 1 in lib/nlattr.c
WFLAGS_INHIBIT += -Wno-missing-field-initializers	# 1 in linux/ratelimit.h
WFLAGS_INHIBIT += -Wno-attributes			# 1 in linux/log2.h

### silly
WFLAGS_INHIBIT += -Wno-unused-parameter

export EXTRA_WFLAGS := $(WFLAGS_WARN) $(WFLAGS_INHIBIT)

###############################################################################

SHELL=/bin/bash

GCCLDFLAGS = $(BUILD_TYPE) -Wl,-z,now	    # -Wl,-O1
export LOCAL_LD_FLAGS = $(GCCLDFLAGS)
export LOCAL_LIBS = -lubsan -lfuse -laio -lrt -lpthread -ldl

LIBTCMUR = $(TCMUR_SRC)/libtcmur
MY_CFLAGS += -I$(TCMUR_SRC) -I$(TCMUR_SRC)/ccan -I$(LIBTCMUR)

MY_CFLAGS += -g -ggdb -fno-omit-frame-pointer -fPIC
SCSTU_CFLAGS += $(MY_CFLAGS) $(EXTRA_WFLAGS)
DRBDU_CFLAGS += $(MY_CFLAGS) $(EXTRA_WFLAGS)

# Force scst_compat.h to be #included at the start of every SCST kernel.c file, for usermode shims
SCSTU_CFLAGS += -include $(SCST_SRC)/usermode/scst_compat.h

# Force drbd_compat.h to be #included at the start of every DRBD kernel.c file, for usermode shims
DRBDU_CFLAGS += -include $(SCST_SRC)/usermode/drbd_compat.h

# LOCAL_CFLAGS appears to be used instead of EXTRA_CFLAGS in real usermode makefiles
export LOCAL_CFLAGS += $(MY_CFLAGS) $(EXTRA_WFLAGS) -DSCST_USERMODE -DDRBD_USERMODE

export INFINIBAND_ENABLED := false
SCST_INC_DIR := $(CURDIR)/../scst/include
export src := .
export KVER = __NONE__

export SCST_USERMODE = 1	    # Tell sub-makefiles to do SCST_USERMODE build
export DRBD_USERMODE = 1	    # Tell sub-makefiles to do DRBD_USERMODE build

ifdef BUILD_STATIC
LIB_SUFFIX="a"
BUILD_TYPE=-static
else
LIB_SUFFIX="so"
BUILD_TYPE=
endif

LIBMTE := $(shell if [ -f /lib/libmte.$(LIB_SUFFIX) ] ; \
		    then /bin/echo "-lmte" ; \
		    else /bin/echo "$(MTE_SRC)/libmte.$(LIB_SUFFIX)" ; \
		 fi)

usermode all:	cscope check_mte
	EXTRA_CFLAGS="$(MY_CFLAGS)"    $(MAKE) -C $(USERMODE_LIB_SRC) all			    # UMC library
	EXTRA_CFLAGS="$(SCSTU_CFLAGS)" $(MAKE) -C $(SCST_SRC)/scst all				    # SCST CORE
	EXTRA_CFLAGS="$(SCSTU_CFLAGS)" $(MAKE) -C $(SCST_SRC)/scst/src/dev_handlers scst_vdisk.o    # SCST-VDISK
	EXTRA_CFLAGS="$(SCSTU_CFLAGS)" $(MAKE) -C $(SCST_SRC)/iscsi-scst all			    # iSCSI-SCST
	EXTRA_CFLAGS="$(DRBDU_CFLAGS)" $(MAKE) -C $(DRBD_SRC)/drbd -f Makefile.usermode all
	$(MAKE) scst.out

drbd-utils:
	EXTRA_CFLAGS="$(MY_CFLAGS) -DDRBD_USERMODE" $(MAKE) -C $(DRBD_UTIL_SRC)

COMPONENTS := $(SCST_SRC)/scst/src/scst.o $(SCST_SRC)/scst/src/dev_handlers/scst_vdisk.o \
	      $(SCST_SRC)/iscsi-scst/kernel/iscsi-scst.o $(SCST_SRC)/iscsi-scst/usr/iscsi-scstlib.o \
	      $(DRBD_SRC)/drbd/drbd.o

USERMODE_LIB := $(USERMODE_LIB_SRC)/usermode_lib.a

scst.out:   UMC_app.o drbd_compat.o $(COMPONENTS) $(USERMODE_LIB)
	# Gather up all the objects we need from DRBD and SCST kernel and daemon code
	# Link with the usermode compatibility module, libmte, and other libraries
	$(CC) -o scst.out $(GCCLDFLAGS) UMC_app.o drbd_compat.o \
		    $(COMPONENTS) $(USERMODE_LIB) $(LIBMTE) $(LOCAL_LIBS) -lc

check_mte:
	@if [[ ! -f /lib/libmte.$(LIB_SUFFIX) ]] ; then $(MAKE) -C $(MTE_SRC) ; fi

# %.o: %.c
# 	$(CC) -c -o $(@) $(MY_CFLAGS) $(EXTRA_WFLAGS) $(<)

drbd_compat.o:	drbd_compat.c
	$(CC) -c -o $(@) $(DRBDU_CFLAGS) $(<)

UMC_app.o: UMC_app.c
	$(CC) -c -o $(@) $(MY_CFLAGS) $(EXTRA_WFLAGS) -I$(USERMODE_LIB_SRC) UMC_app.c

################################################################################

VALGRIND_OPTS = --leak-check=full --show-leak-kinds=all --num-callers=30 --track-fds=yes --sim-hints=no-nptl-pthread-stackcache --track-origins=yes
valgrind:
	valgrind $(VALGRIND_OPTS) --vgdb=yes ./scst.out -f

valgdb:
	valgrind $(VALGRIND_OPTS) --vgdb=full --vgdb-error=0 ./scst.out -f

clean:
	rm -rf *.o scst.out
	rm -rf tags cscope.out
	$(MAKE) -C .. $@
	$(MAKE) -C $(USERMODE_LIB_SRC) $@
	$(MAKE) -C $(DRBD_SRC)/drbd -f Makefile.usermode $@
	$(MAKE) -C $(TCMUR_SRC)/libtcmur $@

extraclean:
	rm -rf *.o scst.out
	rm -rf tags cscope.out
	$(MAKE) -C .. $@
	$(MAKE) -C $(USERMODE_LIB_SRC) $@
	$(MAKE) -C $(DRBD_SRC)/drbd -f Makefile.usermode $@
	$(MAKE) -C $(TCMUR_SRC)/libtcmur $@

cscope:
	cscope -b -c -R `find -L $(USERMODE_LIB_SRC) $(TCMUR_SRC) $(SCST_SRC) $(MTE_SRC) $(DRBD_SRC)/drbd $(DRBD_SRC)/drbd/drbd-headers -name \*.c -o -name \*.h`
	@ctags       -R		 $(USERMODE_LIB_SRC) $(TCMUR_SRC) $(SCST_SRC) $(MTE_SRC) $(DRBD_SRC)/drbd $(DRBD_SRC)/drbd/drbd-headers

.PHONY:	all usermode drbd drbd-utils check_mte valgrind clean extraclean cscope tcmur

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
