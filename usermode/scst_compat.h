/* scst_compat.h
 * Compatibility for SCST running in usermode
 * Copyright 2016 David A. Butterfield
 *
 * This file is forced by the Makefile to be #included at the start of the SCST kernel .c files
 *
 * Most of the shim code is in usermode_lib.h, providing "generic kernel" compatibility;
 * whereas this file addresses compatibility related specifically to SCST or SCSI.
 */
#ifndef SCST_COMPAT_H
#define SCST_COMPAT_H
#define __LINUX_CPUMASK_H   /* set so SCST's backport.h will give us a few more things */

#define KBUILD_MODNAME			"SCST"

#define LINUX_VERSION_CODE		KERNEL_VERSION(2, 6, 24)
#include "usermode_lib.h"

#define SCST_USERMODE_NOT() \
	    sys_panic("SCST_USERMODE should never reach here -- ", "%s()", __func__)

extern void SCST_init(void);
extern void SCST_exit(void);

/* Called from ctldev.c daemon code to issue an "ioctl" to the "kernel" code */
extern int SCST_ctldev_ioctl(int fd_arg, unsigned int cmd, unsigned long arg);

/* Called from iscsi_scstd.c:main() to open a socket to receive events from "kernel" code */
extern int SCST_nl_open(void);

/* A few things missing from the usermode SCSI headers */
#define MAINTENANCE_IN					0xa3
#define MAINTENANCE_OUT					0xa4
#define MI_REPORT_SUPPORTED_OPERATION_CODES		0x0c
#define MI_REPORT_SUPPORTED_TASK_MANAGEMENT_FUNCTIONS	0x0d
#define MI_REPORT_TARGET_PGS				0x0a
#define MO_SET_TARGET_PGS				0x0a

/* iSCSI "between" includes the endpoints */
#define between(seq1, seq2, seq3)			((seq3) - (seq2) >= (seq1) - (seq2))
#define before(seq1, seq2)				((int)((seq1) - (seq2)) < 0)

#define BLK_MAX_CDB			16

/*** UNUSED ***/

struct Scsi_Host;
struct scsi_driver;

struct hostt {
    char * name;
};

struct host {
    int host_no;
    int sg_tablesize;
    int unchecked_isa_dma;
    int use_clustering;
    struct hostt * hostt;
};

struct scsi_device {
	void * parent;
	struct host * host;
	int channel;
	int id;
	int lun;
	int scsi_level;
	struct device sdev_dev;
	struct device sdev_gendev;
	int type, was_reset;
	struct request_queue * request_queue;
	unsigned int sector_size;
};

#define scsi_register_interface(interface)      (_USE(interface), E_OK)
#define scsi_unregister_interface(interface)    DO_NOTHING()
#define to_scsi_device(device)			UMC_STUB(to_scsi_device, NULL)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
#define scsi_execute(dev, cdb, direction, buf, bufsize, sense, timeout, x, y, z) UMC_STUB(scsi_execute, 0)
#else
#define scsi_execute(dev, cdb, direction, buf, bufsize, sense, timeout, x, y) UMC_STUB(scsi_execute, 0)
#endif

int scsi_reset_provider(struct scsi_device * sdev, int flags);
#define SCSI_TRY_RESET_DEVICE		IGNORED
#define SCSI_TRY_RESET_BUS		IGNORED
#define SCSI_TRY_RESET_TARGET		IGNORED
#define QUEUE_FLAG_BIDI			IGNORED

#endif /* SCST_COMPAT_H */
