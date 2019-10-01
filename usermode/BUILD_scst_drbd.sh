#!/bin/bash
#
# To download the repositories and build the usermode SCST/DRBD server:
# make an empty directory and cd into it, then run this script.
#
# Script updated: Mon 26 Aug 2019 01:12:21 PM MDT

### Some of the makefiles require various build tools -- here are package names
### I added to a fresh installation of Ubuntu 18.04 LTS to complete the build:
###
###    build-essential  g++  gcc  git  make  gdb  valgrind  cscope  exuberant-ctags
###    libfuse-dev  libaio-dev  libglib2.0-dev  libkmod-dev  libnl-3-dev  libnl-genl-3-dev
###    librbd-dev  autoconf  automake  flex  coccinelle  cmake

echo Getting sudo password at start of script rather than sometime later
sudo echo Got sudo password

# Start in an empty directory and clone these repositories into it:
git clone https://github.com/DavidButterfield/MTE.git
git clone https://github.com/DavidButterfield/tcmu-runner.git
git clone https://github.com/DavidButterfield/usermode_compat.git
git clone https://github.com/DavidButterfield/SCST-Usermode-Adaptation.git
git clone https://github.com/DavidButterfield/drbd-9.0.git
git clone https://github.com/DavidButterfield/drbd-utils.git

# Checkout the right branches:
(cd usermode_compat; \
    git checkout drbd)

(cd tcmu-runner; \
    git checkout libtcmur)

(cd SCST-Usermode-Adaptation; \
    git checkout drbd)

# Also get our reference kernel into the same directory.
wget https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.27.tar.gz
gunzip linux-2.6.32.27.tar.gz
tar xf linux-2.6.32.27.tar
rm linux-2.6.32.27.tar		# for space if FS is only 1GB

# In the tcmu-runner source directory:
(cd tcmu-runner; \
    cmake -Dwith-glfs=false .; \
    make; \
    if [ ! -e /usr/local/lib/tcmu-runner/handler_ram.sh ]; then sudo make install; fi; \
    cd libtcmur; \
    make)

# In the drbd-utils source directory:
    ## If you omit --without-manual, it will take a long time for the make to complete.
(cd drbd-utils; \
    ./autogen.sh; \
    ./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc --without-manual; \
    make; \
    sudo make install)

# In the drbd-9.0 source directory:
    ## You should not need to "make" in the drbd-9.0 directory.  The make for usermode DRBD is
    ## done from SCST-Usermode-Adaptation/usermode/Makefile passing in the appropriate flags
    ## to drbd-9.0/drbd/Makefile.usermode
    ## 
    ## However, it is necessary to download some headers and compatibility code external
    ## to the drbd-9.0 repository:
(cd drbd-9.0; \
    make check-submods)

# For now SCST has to use emulated /proc (not /sys).  This is enabled by:
(cd SCST-Usermode-Adaptation; \
    make enable_proc)

# Install the usermode version of scstadmin and SCST.pm
    ## (this must be done AFTER running the "make enable_proc" above):
(cd SCST-Usermode-Adaptation; \
    sudo make scstadm; \
    sudo make scstadm_install)

# SCST needs these directories created:
sudo mkdir -p /var/lib/scst/pr
sudo mkdir -p /var/lib/scst/vdev_mode_pages

echo "Full build output will appear in SCST-Usermode-Adaptation/usermode/build.out"
echo "Summary of warnings:"

# If everything is right, it should now successfully build in SCST-Usermode-Adaptation/usermode.
    ## BUT... the dependencies are not computed correctly in the Makefiles, so for now I always
    ## do a clean make:
(cd SCST-Usermode-Adaptation/usermode; \
    make clean > /dev/null; \
    make |& tee build.out | egrep -i "error:|warning:|undefined reference" | sort -uk2)

# That should produce the SCST/DRBD usermode server as scst_drbd.out.  There should be no compile
# errors, but there will be a few warnings; these can be ignored for now:
echo "" 
echo "These warnings can be ignored for now:"
echo "  " "arch_wb_cache_pmem redefined"
echo "  " "comparison of distinct pointer types lacks a cast [uint64_t long vs long long]"
echo "  " "pr_fmt redefined"
echo "  " "#warning BDI_CAP_STABLE_WRITES not available"
echo "  " "#warning In the PROCFS build EXTENDED COPY not supported"

echo ""
echo "Executable:  " `ls -l SCST-Usermode-Adaptation/usermode/scst_drbd.out`

if [ ! -e "/tmp/cfg1" ]; then
    echo ""
    echo "Create the backing files at whatever size you want, e.g. 1 GiB:"
    echo "        dd if=/dev/zero of=/tmp/cfg0 bs=4096 count=262144"
    echo "        dd if=/dev/zero of=/tmp/cfg1 bs=4096 count=262144"
fi

if [ ! -e "/etc/scst.conf" ]; then
    echo ""
    echo "Install configuration files in /etc/scst.conf, /etc/iscsi-scstd.conf, /etc/drbd.d/xxx.res"
fi

if [ -z "$UMC_FS_ROOT" ]; then
    echo ""
    echo "To run drbd usermode server or utilities for drbd usermode server:"
    echo "    export UMC_FS_ROOT=/UMCfuse"
    echo ""
    echo "Use sudo -E to pass the environment variable from your shell through sudo"
fi
