# SCST-Usermode-Adaptation
**SCST iSCSI Storage Server Usermode Adaptation**  
An adaptation of the iSCSI-SCST storage server software to run entirely in usermode on an unmodified Linux kernel  
*David A. Butterfield*

This project adapts the SCST iSCSI storage server software, which normally
resides in the Linux kernel, to run entirely in usermode on an unmodified
kernel.  The resulting executable can run as a regular (non-super) user, as long
as it has permission to access the backing storage.  A paper describing the work
and performance study is
[here](https://davidbutterfield.github.io/SCST-Usermode-Adaptation/docs/SCST_Usermode.html
       "A paper describing the work in detail").

***The ceph_rbd and scstu_tcmu branches are obsolete.***  The functionality is now
integrated into the usermode branch.

Branches:
 + master     - the original work described by the paper
 + usermode   - updated work supporting tcmu-runner backstore handlers in addition to local files and block devices
