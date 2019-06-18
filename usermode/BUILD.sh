#!/bin/bash
#
# To download the repositories and build the usermode SCST/DRBD server:
# make an empty directory and cd into it, then run this script.

git clone https://github.com/DavidButterfield/MTE.git
git clone https://github.com/DavidButterfield/usermode_compat.git
git clone https://github.com/DavidButterfield/SCST-Usermode-Adaptation.git
git clone https://github.com/DavidButterfield/drbd-9.0.git
git clone https://github.com/DavidButterfield/drbd-utils.git

(cd usermode_compat; git checkout drbd)
(cd SCST-Usermode-Adaptation; git checkout drbd)

wget https://cdn.kernel.org/pub/linux/kernel/v2.6/linux-2.6.32.27.tar.gz
gunzip linux-2.6.32.27.tar.gz
tar xvf linux-2.6.32.27.tar
rm linux-2.6.32.27.tar

(cd drbd-utils; ./autogen.sh; \
    ./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc --with-build-usermode --without-manual;
    make; sudo make install)

(cd drbd-9.0; make check-submods)

(cd drbd-9.0/drbd/drbd-kernel-compat; patch -p1 < ../../PATCH.drbd-kernel-compat)

(cd SCST-Usermode-Adaptation; make enable_proc)

(cd SCST-Usermode-Adaptation; sudo make scstadm; sudo make scstadm_install)

(cd SCST-Usermode-Adaptation/usermode; make clean; make)

sudo mkdir -p /var/lib/scst/pr
sudo mkdir -p /var/lib/scst/vdev_mode_pages

echo ""
echo "Executable:  " `ls -l SCST-Usermode-Adaptation/usermode/scst.out`
echo ""
echo "Create the backing files at whatever size you want, e.g."
echo "        dd if=/dev/zero of=/tmp/cfg1 bs=4096 count=262144"
echo "        dd if=/dev/zero of=/tmp/cfg2 bs=4096 count=262144"
echo ""
echo "Install configuration files in /etc/scst.conf, /etc/iscsi-scstd.conf, /etc/drbd.d/xxx.res"

if [ -z "$PROC_PREFIX" ]; then
    echo ""
    echo "To run drbd utilities, be sure to export PROC_PREFIX=/fuse/scst"
fi
