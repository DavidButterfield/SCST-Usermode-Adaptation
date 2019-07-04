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

extern struct module UMC_DRBD_module;
#define THIS_MODULE (&UMC_DRBD_module)

#define KBUILD_MODNAME			"DRBD"
#include "usermode_lib.h"		/* kernel emulated interfaces */

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

/* These affect DRBD's backport behavior */
#define COMPAT_DRBD_RELEASE_RETURNS_VOID
#define COMPAT_HAVE_BIOSET_CREATE_FRONT_PAD
#define COMPAT_HAVE_FILE_INODE
#define COMPAT_HAVE_OPEN_BDEV_EXCLUSIVE
#define COMPAT_HLIST_FOR_EACH_ENTRY_HAS_THREE_PARAMETERS
#define COMPAT_IB_ALLOC_PD_HAS_2_PARAMS
#define CONFIG_DRBD_FAULT_INJECTION 0
#define IDR_GET_NEXT_EXPORTED
#define __LINUX_MUTEX_H

#endif /* DRBD_COMPAT_H */
