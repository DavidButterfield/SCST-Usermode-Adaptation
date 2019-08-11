/* drbd_compat.h
 * Compatibility for DRBD running in usermode
 * Copyright 2019 David A. Butterfield
 *
 * This file is forced by the Makefile to be #included at the start of the DRBD kernel .c files
 *
 * Most of the shim code is in usermode_lib.[ch], providing "generic Linux kernel"
 * compatibility; whereas this file addresses compatibility related specifically to DRBD.
 */
#ifndef DRBD_COMPAT_H
#define DRBD_COMPAT_H
#define _GNU_SOURCE

extern struct module UMC_DRBD_module;
#define THIS_MODULE (&UMC_DRBD_module)

#define KBUILD_MODNAME			"DRBD"

#define LINUX_VERSION_CODE		KERNEL_VERSION(2, 6, 32)
#include "usermode_lib.h"		/* kernel emulated interfaces */
#include <linux/rbtree.h>		/* rb_parent, rb_next for drbd_wrappers.h */

/* Called from APP_init() at gcc process constructor time (before main()) */
extern void DRBD_init(void);
extern void DRBD_exit(void);

/* These are implemented in drbd-kernel-compat but lack the "previous prototype" declaration
                                                                      [-Wmissing-prototypes] */
extern unsigned long nsecs_to_jiffies(u64);
extern int
    blkdev_issue_zeroout(struct block_device *, sector_t sector, sector_t nr_sects, gfp_t);

/* kstrtoull is used by DRBD but does not exist in kernel 2.6.32 */
#define kstrtoull(str, base, var)	strict_strtoull((str), (base), (var))

#define drbd_protocol_version uint  //XXX dodgy hacking away of a module_param type

#define __LINUX_MUTEX_H	    /* inhibit include of <linux/mutex.h> in drbd_int.h */

#endif /* DRBD_COMPAT_H */
