/* drbd_compat.h
 * Compatibility for DRBD running in usermode
 * Copyright 2019 David A. Butterfield
 *
 * This file is forced by the Makefile to be #included at the start of the DRBD kernel .c files
 *
 * Most of the shim code is in usermode_lib.h, providing "generic kernel" compatibility;
 * whereas this file addresses compatibility related specifically to DRBD.
 */
#ifndef DRBD_COMPAT_H
#define DRBD_COMPAT_H
#define __LINUX_CPUMASK_H	/* set so SCST's backport.h will give us a few more things */

#define KBUILD_MODNAME			"DRBD"

//XXX kstrtoull is used by DRBD but does not exist in kernel 2.6.32
#define kstrtoull(str, base, var)       strict_strtoull((str), (base), (var))

#include "usermode_lib.h"

/* Called from APP_init() at gcc process constructor time (before main()) */
extern void DRBD_init(void);
extern void DRBD_exit(void);

/* Setting these to affect DRBD's backport behavior */
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
