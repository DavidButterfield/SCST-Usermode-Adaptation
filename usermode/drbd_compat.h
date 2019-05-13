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

#include "UMC_kernel.h"
#define LINUX_VERSION_CODE              KERNEL_VERSION(2, 6, 32)
#include "usermode_lib.h"

#include "../scst/include/backport.h"	//XXX steal some backport from scst

/* Called from APP_init() at gcc process constructor time (before main()) */
extern void DRBD_init(void);
extern void DRBD_exit(void);

/* Called from daemon code to issue an "ioctl" to the "kernel" code */
extern int  DRBD_ctldev_ioctl(int fd_arg, unsigned int cmd, unsigned long arg);

/* Called at program start to open a socket to receive events from "kernel" code */
extern int DRBD_nl_open(void);

//#define MS_RDONLY			1

/* Setting these to affect DRBD's backport behavior */
#define COMPAT_HAVE_BIOSET_CREATE_FRONT_PAD
#define COMPAT_HLIST_FOR_EACH_ENTRY_HAS_THREE_PARAMETERS
#define COMPAT_HAVE_FILE_INODE
#define COMPAT_DRBD_RELEASE_RETURNS_VOID

#define COMPAT_HAVE_IDR_ALLOC
#define IDR_GET_NEXT_EXPORTED

#define CONFIG_DRBD_FAULT_INJECTION 0
#define __LINUX_MUTEX_H


#endif /* DRBD_COMPAT_H */
