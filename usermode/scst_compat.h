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
#define __LINUX_CPUMASK_H	/* set so SCST's backport.h will give us a few more things */

#ifdef SCST_USERMODE_AIO
#define USERMODE_AIO 1
#endif

#include "usermode_lib.h"

#define __compiler_offsetof(TYPE, MEMBER) __builtin_offsetof(TYPE, MEMBER) /* misc.h */

/* Invoked by iscsi_scstd.c:main() via kernel_open() / create_and_open_dev() */
/* Whatever we return from SCST_init gets passed back to us in SCST_ctldev_ioctl(fd_arg) */
extern int  SCST_init(const char *dev, int readonly);

/* Called from ctldev.c daemon code to issue an "ioctl" to the "kernel" code */
extern int  SCST_ctldev_ioctl(int fd_arg, unsigned int cmd, unsigned long arg);

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

/* XXX crypto_hash not yet translated to usermode */
struct hash_desc {
    struct crypto_hash    * tfm;
    uint32_t		    flags;
};

#define CRYPTO_ALG_ASYNC				0x00000080
#define crypto_has_alg(name_str, x, flag)		false
#define crypto_alloc_hash(type_str, x, alg)		NULL
#define crypto_hash_init(hash)				E_OK
#define crypto_hash_update(hash, sg, nbytes)		E_OK
#define crypto_hash_final(hash, id)			E_OK
#define crypto_free_hash(tfm)				DO_NOTHING()

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

#define ENABLE_CLUSTERING 1	/* nonzero */

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

#define queue_max_hw_sectors(rq)	0xffff //XXX OK?
#define to_scsi_device(device)		FATAL(to_scsi_device)
#define generic_unplug_device(rq)	DO_NOTHING()
#define QUEUE_FLAG_BIDI			IGNORED

#define ip_compute_csum(data, len)	FATAL(ip_compute_csum)
#define dlm_new_lockspace(name, namelen, lockspace, flags, lvblen) \
					FATAL(dlm_new_lockspace)
#define scsi_execute(dev, cdb, direction, buf, bufsize, sense, timeout, x, y) \
					FATAL(scsi_execute)

int scsi_reset_provider(struct scsi_device * sdev, int flags);
#define SCSI_TRY_RESET_DEVICE		IGNORED
#define SCSI_TRY_RESET_BUS		IGNORED

#define BLK_MAX_CDB 16

struct ib_device {
};

#define ib_alloc_pd(device)             FATAL(ib_alloc_pd)

/* Include a few real kernel files */
#include "UMC/scsi/scsi_proto.h"
#include "UMC/scsi/scsi_common.h"
#include "UMC/scsi/scsi.h"
#include "UMC/scsi/scsi_cmnd.h"
#include "UMC/scsi/scsi_eh.h"

#endif /* SCST_COMPAT_H */
