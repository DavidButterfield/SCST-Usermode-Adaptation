/* tcmur_spdk.c -- tcmu-runner/scstu_tcmu backstore using Intel SPDK calls
 * Copyright 2017 David A. Butterfield
 * Licensed under MIT License [SPDX:MIT https://opensource.org/licenses/MIT]
 *
 * This module facilitates use of the Intel Storage Performance Development Kit
 * (SPDK) as a backstore handler either with LIO/tcmu-runner or with the
 * SCST_Usermode Linux iSCSI server using its tcmu-runner compatible interface.
 *
 * XXXXX NOTE: Support for tcmu_runner is incomplete -- USE_SPDK_EVENT_LOOP TBD
 */

//XXXXX USE_SPDK_EVENT_LOOP functionality is incomplete
// #define USE_SPDK_EVENT_LOOP 1 /* undefined uses MTE event loop (SCST only, not TCMU) */

#define _GNU_SOURCE 1
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "tcmu-runner.h"
#include "libtcmu.h"

#include "spdk/stdinc.h"
#include "spdk/nvme.h"
#include "spdk/env.h"
#include "spdk/log.h"

#ifdef USE_SPDK_EVENT_LOOP
#include "spdk_internal/event.h"    //XXX
#undef spin_lock_init
#define spin_lock_init(lock)	    //XXXXX
#define spin_lock(lock)		    //XXXXX
#define spin_unlock(lock)	    //XXXXX
#endif

/* Hack up some locks and atomics to use */
typedef pthread_mutex_t spinlock_t;
#undef spin_lock_init
#define spin_lock_init(lock)		pthread_mutex_init(lock, NULL)
#define spin_lock(lock)			do { } while (pthread_mutex_trylock(lock))
#define spin_unlock(lock)		pthread_mutex_unlock(lock)

#define __barrier()                     __sync_synchronize()

typedef struct { int32_t volatile i; }  atomic_t;   /* must be signed */

#define ATOMIC_INIT(n)                  ((atomic_t){ .i = (n) })
					//XXX Figure out which of these barriers isn't needed
#define atomic_get(ptr)                 ({ __barrier(); int32_t __ret = (ptr)->i; __barrier(); __ret; })

#define atomic_add_return(n, ptr)       __sync_add_and_fetch(&(ptr)->i, (n))
#define atomic_sub_return(n, ptr)       __sync_sub_and_fetch(&(ptr)->i, (n))
#define atomic_inc_return(ptr)          atomic_add(1, (ptr))
#define atomic_dec_return(ptr)          atomic_sub(1, (ptr))

#define atomic_add(n, ptr)              atomic_add_return((n), (ptr))
#define atomic_sub(n, ptr)              atomic_sub_return((n), (ptr))
#define atomic_inc(ptr)                 atomic_inc_return(ptr)
#define atomic_dec(ptr)                 atomic_dec_return(ptr)

#endif

/* Each NVMe controller has a set of namespaces */
struct ctrlr_entry {
    struct spdk_nvme_ctrlr        * ctrlr;	/* SPDK controller data */
    struct ctrlr_entry	          * next;	/* next entry in g_controllers list */
    struct spdk_nvme_transport_id   trid;	/* controller transport ID */
    char			    name[1024];	/* controller name */
};

/* Each namespace represents a volume */
struct ns_entry {
    atomic_t			    refcount;	/* opens minus closes */
    atomic_t			    ops_active;	/* submits minus completions */
    atomic_t			    scheduled;	/* a poll is currently scheduled */
    spinlock_t			    lock;	/* qpair thread exclusion */
    struct spdk_nvme_ns	          * ns;		/* SPDK namespace data */
    struct spdk_nvme_qpair        * qpair;	/* SPDK queue-pair */
    struct ctrlr_entry            * ctrlr_entry;/* entry for parent controller */
    struct ns_entry	          * next;	/* next entry in g_namespaces list */
    size_t			    block_size;	/* volume block sizes */
    size_t			    nblock;	/* number of logical blocks */
};

#define ctrlr_conf_name(entry)	((entry)->trid.traddr)

#define ns_ctrlr(ns_entry)	((ns_entry)->ctrlr_entry->ctrlr)
#define ns_name(ns_entry)	((ns_entry)->ctrlr_entry->name)
#define ns_conf_name(ns_entry)	((ns_entry)->ctrlr_entry->trid.traddr)

#define ns_num(ns_entry)	spdk_nvme_ns_get_id((ns_entry)->ns)

#define ns_ref_take(ns_entry)	atomic_inc_return(&(ns_entry)->refcount) 
#define ns_ref_drop(ns_entry)	atomic_dec_return(&(ns_entry)->refcount) 

static struct ctrlr_entry     * g_controllers = NULL;	/* list of controllers */
static struct ns_entry	      * g_namespaces = NULL;	/* list of namespaces */

static struct ctrlr_entry *
ctrlr_entry_find(const char * nvme_name)
{
    struct ctrlr_entry * ctrlr_entry;
    for (ctrlr_entry = g_controllers; ctrlr_entry; ctrlr_entry = ctrlr_entry->next) {
	if (!strcmp(nvme_name, ctrlr_conf_name(ctrlr_entry))) {
	    tcmu_info("ctrlr_entry_find: '%s' == '%s'\n",
		      nvme_name, ctrlr_conf_name(ctrlr_entry));
	    return ctrlr_entry;
	}
	tcmu_dbg("ctrlr_entry_find: '%s' != '%s'\n",
		   nvme_name, ctrlr_conf_name(ctrlr_entry));
    }
    return NULL;
}

static struct ns_entry *
ns_entry_find(const char * nvme_name, uint32_t ns_id)
{
    struct ns_entry * ns_entry;
    for (ns_entry = g_namespaces; ns_entry; ns_entry = ns_entry->next) {
	if (!strcmp(nvme_name, ns_conf_name(ns_entry))) {
	    if (ns_id == ns_num(ns_entry)) {
		return ns_entry;
	    }
	}
    }
    return NULL;
}

/* A Read, Write, or Flush operation */
struct spdk_op {
    char		      *	bounce_buffer;	/* SPDK requires its own special memory */
    struct tcmulib_cmd	      *	cmd;		/* OP state of our client */
    struct tcmu_device	      *	dev;		/* device state of our client */
    bool			is_read;	/* data to be bounced on completion */
    size_t			nbyte;		/* total number of bytes to read or write */
    size_t			niov;		/* number of entries in iov array */
    struct iovec	      * iov;		/* scatter/gather list {addr, len} */
};

static void poll_schedule(struct tcmu_device *);

/* Poll for completions on dev */
static void
_tcmu_spdk_poll(struct tcmu_device * dev)
{
    int max_completions_to_process = 0;	    /* 0 --> all */
    struct ns_entry * ns_entry = tcmu_get_dev_private(dev);
    assert(ns_entry);

    atomic_dec(&ns_entry->scheduled);

    /* Process all ready completions */
    spin_lock(&ns_entry->lock);
    spdk_nvme_qpair_process_completions(ns_entry->qpair, max_completions_to_process);
    spin_unlock(&ns_entry->lock);

    /* Keep polling as long as there are ops outstanding */
    if (atomic_get(&ns_entry->ops_active)) {
	poll_schedule(dev);
    }
}

#ifndef USE_SPDK_EVENT_LOOP

/* Receive a poll callback from MTE (after sys_callback_schedule) */
static void
SCST_tcmu_spdk_poll(void * env, uintptr_t arg, errno_t err)
{
    struct tcmu_device * dev = env;
    assert(arg == 0);
    assert(err == 0);
    _tcmu_spdk_poll(dev);
}

#else

/* Receive a poll callback from DPDK (after spdk_event_call) */
static void
DPDK_tcmu_spdk_poll(void * arg1, void * arg2)
{
    struct tcmu_device * dev = arg1;;
    assert(arg2 == NULL);
    _tcmu_spdk_poll(dev);
}

#endif

/* Schedule _tcmu_spdk_poll() to run ASAP */ 
static void
poll_schedule(struct tcmu_device * dev)
{
    struct ns_entry * ns_entry = tcmu_get_dev_private(dev);
    if (atomic_inc_return(&ns_entry->scheduled) > 1) {
	/* _tcmu_spdk_poll() has already been scheduled */
	atomic_dec(&ns_entry->scheduled);
	return;
    }

#ifndef USE_SPDK_EVENT_LOOP
    sys_callback_schedule(sys_event_task_current(), SCST_tcmu_spdk_poll, dev,
			  0/*arg*/, 0/*errno*/, "SPDK_poll");
#else
    spdk_event_call(spdk_event_allocate(spdk_env_get_current_core(),
					DPDK_tcmu_spdk_poll, dev, NULL));
#endif
}

/* Called upon completion of a Read, Write, or Flush operation */
static void
aio_complete(void * op_v, const struct spdk_nvme_cpl * cpl)
{
    struct spdk_op * op = op_v;
    int tcmu_r = SAM_STAT_GOOD;
    struct ns_entry * ns_entry = tcmu_get_dev_private(op->dev);

    if (spdk_nvme_cpl_is_error(cpl)) {
	int scsi_err = op->is_read ? ASC_READ_ERROR : ASC_WRITE_ERROR;
	tcmu_r = tcmu_set_sense_data(op->cmd->sense_buf, MEDIUM_ERROR, scsi_err, NULL);
    } else if (op->is_read) {
	//XXX Get rid of this copy -- Need missing API to pin client's memory for DMA
	tcmu_memcpy_into_iovec(op->iov, op->niov, op->bounce_buffer, op->nbyte);
    }

    op->cmd->done(op->dev, op->cmd, tcmu_r);

    if (op->bounce_buffer) spdk_dma_free(op->bounce_buffer);

    free(op);

    atomic_dec(&ns_entry->ops_active);
}

/* Initiate Read or Write operation */
static int
aio_start(struct tcmu_device * dev, struct tcmulib_cmd * cmd,
	  struct iovec * iov, size_t niov, size_t length, off_t offset, bool is_read)
{
    struct ns_entry * ns_entry = tcmu_get_dev_private(dev);
    assert(ns_entry);
    assert(offset % ns_entry->block_size == 0);
    assert(length % ns_entry->block_size == 0);
    uint64_t lba = offset / ns_entry->block_size;
    uint64_t nblock = length / ns_entry->block_size;
    uint32_t io_flags = 0;

    struct spdk_op * op = calloc(1, sizeof(*op));	//XXX use a cache
    if (!op) {
	tcmu_dev_err(dev, "Cannot allocate SPDK OP\n");
	goto out;
    }

    //XXX Get rid of this bounce_buffer -- Need missing API to pin client's memory for DMA
    op->bounce_buffer = spdk_dma_malloc(length, 64, NULL);
    if (!op->bounce_buffer) {
	tcmu_dev_err(dev, "Cannot allocate SPDK bounce_buffer\n");
	goto out_free_op;
    }

    op->cmd = cmd;
    op->dev = dev;
    op->is_read = is_read;
    op->nbyte = length;
    op->niov = niov;
    op->iov = iov;

    atomic_inc(&ns_entry->ops_active);

    int rc;
    if (is_read) {
	spin_lock(&ns_entry->lock);
	rc = spdk_nvme_ns_cmd_read(ns_entry->ns, ns_entry->qpair, op->bounce_buffer,
				   lba, nblock, aio_complete, op, io_flags);
	spin_unlock(&ns_entry->lock);
    } else {
	//XXX Get rid of this copy -- Need missing API to pin client's memory for DMA
	tcmu_memcpy_from_iovec(op->bounce_buffer, op->nbyte, op->iov, op->niov);
	spin_lock(&ns_entry->lock);
	rc = spdk_nvme_ns_cmd_write(ns_entry->ns, ns_entry->qpair, op->bounce_buffer,
				   lba, nblock, aio_complete, op, io_flags);
	spin_unlock(&ns_entry->lock);
    }

    if (rc != 0) {
	tcmu_dev_warn(dev, "Failed to start %s(lba=%"PRIu64", nblock=%"PRIu64")\n",
			op->is_read?"Read":"Write", lba, nblock);
	goto out_free_buffer;
    }

    poll_schedule(dev);

    return 0;	/* OK */

out_free_buffer:
    spdk_dma_free(op->bounce_buffer);
out_free_op:
    free(op);
out:
    return SAM_STAT_TASK_SET_FULL;
}

static int
tcmu_spdk_read(struct tcmu_device * dev, struct tcmulib_cmd * cmd,
	       struct iovec * iov, size_t niov, size_t length, off_t offset)
{
    return aio_start(dev, cmd, iov, niov, length, offset, true);
}

static int
tcmu_spdk_write(struct tcmu_device * dev, struct tcmulib_cmd * cmd,
		struct iovec * iov, size_t niov, size_t length, off_t offset)
{
    return aio_start(dev, cmd, iov, niov, length, offset, false);
}

/* Initiate Flush operation */
static int
tcmu_spdk_flush(struct tcmu_device * dev, struct tcmulib_cmd * cmd)
{
    int rc;
    struct ns_entry * ns_entry = tcmu_get_dev_private(dev);
    assert(ns_entry);

    struct spdk_op * op = calloc(1, sizeof(*op));	//XXX use a cache
    if (!op) {
	tcmu_dev_err(dev, "Cannot allocate OP for flush\n");
	goto out;
    }

    op->cmd = cmd;
    op->dev = dev;

    atomic_inc(&ns_entry->ops_active);

    spin_lock(&ns_entry->lock);
    rc = spdk_nvme_ns_cmd_flush(ns_entry->ns, ns_entry->qpair, aio_complete, op);
    spin_unlock(&ns_entry->lock);
    if (rc != 0) {
	tcmu_dev_warn(dev, "Failed to start flush()\n");
	goto out_free_op;
    }

    poll_schedule(dev);

    return 0;	/* OK */

out_free_op:
    free(op);
out:
    return SAM_STAT_TASK_SET_FULL;
}

/* Find the namespace associated with cfgstring(dev) and hook it to the dev --
 * SCST/tcmu_runner config string for Intel SPDK NVMe looks like
 *			    '/NVMe_traddr/ns_id' e.g. '/0000:00:0e.0/1'
 */
static int
tcmu_spdk_open(struct tcmu_device * dev)
{
    char * config = tcmu_get_dev_cfgstring(dev);
    tcmu_dev_info(dev, "tcmu_spdk config string '%s'\n", config);
    if (!config || config[0] != '/') {
	tcmu_dev_err(dev, "No '/' starting SCST config string %s\n", config);
	return -EINVAL;
    }

    char * nvme_name = config + 1;  /* point at the start of the controller name */

    /* Find the separator between the controller name and the namespace ID */
    config = strchr(nvme_name, '/');
    if (!config) {
	tcmu_dev_err(dev, "No NVMe ns_id in SCST config string '%s'\n", config);
	return -EINVAL;
    }
    *config++ = '\0';	/* terminate the ctrlr name string and advance to ns_id string */

    /* Get the namespace ID number from the config string */
    long ns_id = strtol(config, NULL/*endptr*/, 0/*base*/);

    /* Find the controller entry */
    struct ctrlr_entry * ctrlr_entry = ctrlr_entry_find(nvme_name);
    if (!ctrlr_entry) {
	tcmu_dev_err(dev, "SPDK name '%s' not found\n", nvme_name);
	return -ENODEV;
    }

    /* Validate the namespace ID and find the namespace entry */
    long ns_id_max = spdk_nvme_ctrlr_get_num_ns(ctrlr_entry->ctrlr);
    if (ns_id < 1 || ns_id > ns_id_max) {
	tcmu_dev_err(dev, "Bad ns_id %d (max %d) in config string for %s\n",
		       ns_id, ns_id_max, nvme_name);
	/* Fall into the next check despite this error */
    }

    struct ns_entry * ns_entry = ns_entry_find(nvme_name, ns_id);
    if (!ns_entry) {
	tcmu_dev_err(dev, "ns_id %d not found for %s!\n", ns_id, nvme_name);
	return -ENOENT;
    }

    /* Check the block sizes between the config and the SPSK device report */
    uint32_t tcmu_block_size = tcmu_get_dev_block_size(dev);
    assert(tcmu_block_size >= 512);
    assert(tcmu_block_size%512 == 0);

    if (!tcmu_block_size) {
	tcmu_dev_err(dev, "SPDK %s_%d: No block size configured through tcmur/SCST\n",
			  ns_name(ns_entry), ns_num(ns_entry));
	return -EPERM;
    }

    if (tcmu_block_size % ns_entry->block_size != 0) {
	tcmu_dev_err(dev, "SPDK %s_%d: Block size mismatch tcmu %u, spdk %u\n",
		    ns_name(ns_entry), ns_num(ns_entry), tcmu_block_size, ns_entry->block_size);
	return -EPERM;
    }

    /* Get and check device sizes */
    uint64_t spdk_size = spdk_nvme_ns_get_size(ns_entry->ns);
    assert(spdk_size == ns_entry->nblock * ns_entry->block_size);
    assert(spdk_size > 0);

    uint64_t tcmu_size = tcmu_get_device_size(dev);
    if (tcmu_size == 0) {
	/* No size specified in config, set it from the device */
	tcmu_size = spdk_size;
	tcmu_set_dev_num_lbas(dev, tcmu_size / tcmu_block_size);
	tcmu_dev_info(dev, "%s: size determined from SPDK device as %lu\n", config, tcmu_size);
    }
    else if (tcmu_size > spdk_size) {
	tcmu_dev_err(dev, "SPDK %s_%d: SPDK device is smaller than tcmur config %lu < %lu\n",
			  ns_name(ns_entry), ns_num(ns_entry), spdk_size, tcmu_size);
	return -EFBIG;
    }
    else if (tcmu_size < spdk_size) {
	tcmu_dev_info(dev, "%s_%d space unused: tcmu_size %lld < spdk_size %lld",
			   ns_name(ns_entry), ns_num(ns_entry), tcmu_size, spdk_size);
    }

    assert(spdk_size >= tcmu_size);

    //XXXX I think this is presently ignored
    tcmu_set_dev_max_xfer_len(dev,
	    spdk_nvme_ns_get_max_io_xfer_size(ns_entry->ns) / tcmu_block_size);

    int32_t nref = ns_ref_take(ns_entry);
    assert(nref >= 1);

    tcmu_set_dev_private(dev, ns_entry);

    tcmu_dev_dbg(dev, "Config %s, size %lld\n", tcmu_get_dev_cfgstring(dev), spdk_size);
    return 0;	/* OK */
}

static void
tcmu_spdk_close(struct tcmu_device * dev)
{
    struct ns_entry * ns_entry = tcmu_get_dev_private(dev);
    assert(ns_entry);
    tcmu_dev_dbg(dev, "Close %s\n", tcmu_get_dev_cfgstring(dev));

    //XXXXX should flush and wait for completion here I think

    int32_t nref = ns_ref_drop(ns_entry);
    assert(nref >= 0);
	
    tcmu_set_dev_private(dev, NULL);
}

/* Module fini */
static int
tcmu_spdk_handler_fini(void)
{
    int ret = 0;    /* OK */
    struct ns_entry *ns_entry = g_namespaces;
    struct ctrlr_entry *ctrlr_entry = g_controllers;

    while (ns_entry) {
	struct ns_entry *next = ns_entry->next;

	if (atomic_get(&ns_entry->refcount)) {
	    tcmu_dbg("fini(%s_%d) waiting for refcount %d\n",
			      ns_name(ns_entry), ns_num(ns_entry), atomic_get(&ns_entry->refcount));
	    int maxloop = 1000000;
	    while (atomic_get(&ns_entry->refcount)) {
		if (!--maxloop) {
		    tcmu_err("fini(%s_%d) refcount did not reach zero%d\n",
				      ns_name(ns_entry), ns_num(ns_entry), atomic_get(&ns_entry->refcount));
		    ret = -EBUSY;
		}
	    }
	    tcmu_dbg("fini(%s_%d) done waiting for refcount %d\n",
			      ns_name(ns_entry), ns_num(ns_entry), atomic_get(&ns_entry->refcount));
	}

	if (atomic_get(&ns_entry->refcount) == 0) {
	    spdk_nvme_ctrlr_free_io_qpair(ns_entry->qpair);
	    free(ns_entry);
	}

	ns_entry = next;
    }

    if (ret) return ret;

#ifdef USE_SPDK_EVENT_LOOP
    spdk_reactors_stop();	/* shutdown spdk app services */

    //XXXXX Do I need to wait for _stop() to complete before doing _fini() ?
    sleep(1);	//XXXXX

    ret = spdk_subsystem_fini();
    if (ret) return ret;

    spdk_reactors_fini();
    spdk_log_close();
#endif

    while (ctrlr_entry) {
	struct ctrlr_entry *next = ctrlr_entry->next;
	spdk_nvme_detach(ctrlr_entry->ctrlr);
	free(ctrlr_entry);
	ctrlr_entry = next;
    }

    return ret;
}

/* One call from attach_cb() to here for each controller namespace */
static int
attach_namespace(struct ctrlr_entry * ctrlr_entry, struct spdk_nvme_ns *ns)
{
    if (!spdk_nvme_ns_is_active(ns)) {
	const struct spdk_nvme_ctrlr_data *cdata = spdk_nvme_ctrlr_get_data(ctrlr_entry->ctrlr);
	tcmu_dbg("Controller %-20.20s (%-20.20s): Skipping inactive NS %u\n",
			 cdata->mn, cdata->sn, spdk_nvme_ns_get_id(ns));
	return 0;   /* OK to skip non-active entry */
    }

    struct ns_entry * ns_entry = calloc(1, sizeof(struct ns_entry));
    if (ns_entry == NULL) {
	tcmu_err("malloc of ns_entry failed: %s\n", strerror(errno));
	return -ENOMEM;
    }

    struct spdk_nvme_qpair *qpair = spdk_nvme_ctrlr_alloc_io_qpair(ctrlr_entry->ctrlr, NULL, 0);
    if (qpair == NULL) {
	tcmu_err("spdk_nvme_ctrlr_alloc_io_qpair() failed\n");
	free(ns_entry);
	return -ENOMEM;
    }

    spin_lock_init(&ns_entry->lock);
    ns_entry->ns = ns;
    ns_entry->qpair = qpair;
    ns_entry->ctrlr_entry = ctrlr_entry;

    /* Get the block_size and device size from the SPDK */
    ns_entry->block_size = spdk_nvme_ns_get_sector_size(ns);
    assert(ns_entry->block_size >= 512);
    assert(ns_entry->block_size%512 == 0);
    if (!ns_entry->block_size) {
	tcmu_err("Spdk %s_%d: Cannot read block size\n", ns_name(ns_entry), ns_num(ns_entry));
	return -EIO;
    }

    ns_entry->nblock = spdk_nvme_ns_get_num_sectors(ns_entry->ns);
    if (ns_entry->nblock == 0) {
	tcmu_err("spdk_size = 0 for %s_%d\n", ns_name(ns_entry), ns_num(ns_entry));
    }

    /* Link the namespace into our list */
    ns_entry->next = g_namespaces;
    g_namespaces = ns_entry;

    tcmu_info("  Namespace ID: %d size: %luGB\n",
	    spdk_nvme_ns_get_id(ns),  ns_entry->nblock * ns_entry->block_size / 1000000000);
    return 0;	/* OK */
}

/* One callback from spdk_nvme_probe() to attach_cb() for each NVMe controller */
static void
attach_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
      struct spdk_nvme_ctrlr *ctrlr, const struct spdk_nvme_ctrlr_opts *opts)
{
    int nsid, num_ns;
    struct spdk_nvme_ns *ns;
    const struct spdk_nvme_ctrlr_data *cdata = spdk_nvme_ctrlr_get_data(ctrlr);
    struct ctrlr_entry *ctrlr_entry = calloc(1, sizeof(struct ctrlr_entry));
    if (ctrlr_entry == NULL) {
	tcmu_err("malloc of ctrlr_entry failed: %s\n", strerror(errno));
	return;
    }

    snprintf(ctrlr_entry->name, sizeof(ctrlr_entry->name)-1, "%-20.20s (%-20.20s)",
							     cdata->mn, cdata->sn);
    ctrlr_entry->ctrlr = ctrlr;
    ctrlr_entry->next = g_controllers;
    ctrlr_entry->trid = *trid;
    g_controllers = ctrlr_entry;

    tcmu_info("%s Attached to %s\n", ctrlr_entry->name, trid->traddr);

    num_ns = spdk_nvme_ctrlr_get_num_ns(ctrlr);
    tcmu_info("Using controller %s with %d namespaces\n", ctrlr_entry->name, num_ns);
    for (nsid = 1; nsid <= num_ns; nsid++) {
	ns = spdk_nvme_ctrlr_get_ns(ctrlr_entry->ctrlr, nsid);
	if (ns == NULL) {
	    tcmu_err("%s: Cannot find ns_entry for ns_id=%d\n",
			   ctrlr_entry->name, nsid);
	    continue;
	}
	attach_namespace(ctrlr_entry, ns);
    }
}

/* spdk_nvme_ctrlr_opts may be modified by this function */
static bool
probe_cb(void *cb_ctx, const struct spdk_nvme_transport_id *trid,
     struct spdk_nvme_ctrlr_opts *opts)
{
    tcmu_dbg("Probing %s\n", trid->traddr);
    return true;
}

#ifdef USE_SPDK_EVENT_LOOP
static void
start_fn(void * arg1, void * arg2)
{
    tcmu_dbg("tcmu_spdk start_fn()\n");
}
#endif

/* Module init */
static int
tcmu_spdk_handler_init(void)
{
    int rc;
    /* Setup logging */
#ifdef DEBUG
    struct rlimit core_limits;
    core_limits.rlim_cur = core_limits.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_CORE, &core_limits);
    spdk_log_set_level(SPDK_LOG_DEBUG);
    spdk_log_set_print_level(SPDK_LOG_DEBUG);
    spdk_log_set_trace_flag("all");
#else
    spdk_log_set_level(SPDK_LOG_INFO);
    spdk_log_set_print_level(SPDK_LOG_INFO);
#endif
    spdk_log_open();

    /* Setup SPDK options */
    struct spdk_env_opts opts = {};
    spdk_env_opts_init(&opts);
    opts.name = "tcmur_spdk";
    opts.no_pci = false;
    opts.mem_channel = -1;
    opts.master_core = -1;
    opts.mem_size = -1;
    opts.core_mask = "0x1";   //XXXXX
    spdk_env_init(&opts);

    /* Find and attach the controllers and namespaces */
    tcmu_info("Probing NVMe Controllers\n");

    rc = spdk_nvme_probe(NULL/*PCIe*/, NULL/*cb_ctx*/, probe_cb, attach_cb, NULL);
    if (rc != 0) {
	tcmu_err("spdk_nvme_probe() failed\n");
	tcmu_spdk_handler_fini();
	return -ENXIO;	//XXX
    }

    if (g_controllers == NULL) {
	tcmu_err("No NVMe controllers found\n");
	tcmu_spdk_handler_fini();
	return -ENODEV;
    }

#ifdef USE_SPDK_EVENT_LOOP
    /* Setup the event thread */
    tcmu_info("Starting Reactor event thread\n");

    rc = spdk_reactors_init(0);
    if (rc) {
	SPDK_ERRLOG("spdk_reactors_init() failed %d\n", rc);
	return -1;  /* FAILURE */
    }

    /* start_fn(arg1, arg2) will run on the event thread (Reactor) */
    uint32_t my_core = spdk_env_get_current_core();
    struct spdk_event * start_event = spdk_event_allocate(my_core, start_fn, NULL, NULL);
    spdk_event_call(spdk_event_allocate(my_core, spdk_subsystem_init, start_event, NULL));

    spdk_reactors_start();  /* blocks until spdk_app_stop() called */	//XXXXXX Needs to move!
#endif

    tcmu_info("Initialization complete\n");
    return 0;	/* OK */
}

/* tcmu-runner interfaces */

static const char tcmu_spdk_cfg_desc[] =
    "SCST/tcmu_runner config string for Intel SPDK NVMe looks like"
		    " '/NVMe_traddr/ns_id' e.g. '/0000:00:0e.0/1\n'";

static struct tcmur_handler tcmu_spdk_handler = {
    .name	= "Intel SPDK handler",
    .subtype    = "spdk",
    .cfg_desc	= tcmu_spdk_cfg_desc,
    .open	= tcmu_spdk_open,
    .close	= tcmu_spdk_close,
    .read	= tcmu_spdk_read,
    .write	= tcmu_spdk_write,
    .flush	= tcmu_spdk_flush,
};

/* Called at SCST startup */
int
handler_init(void)
{
    int ret = tcmur_register_handler(&tcmu_spdk_handler);
    if (ret == 0) {
	ret = tcmu_spdk_handler_init();
	if (ret != 0) {
	    (void) tcmur_unregister_handler(&tcmu_spdk_handler);
	}
    }
    return ret;
}

#if 0
int
handler_fini(void)
{
    int ret = tcmu_spdk_handler_fini();
    if (ret == 0) {
	ret = tcmur_unregister_handler(&tcmu_spdk_handler);
    }
    return ret;
}
#endif

/******************************************************************************* 
 * MIT License  [SPDX:MIT https://opensource.org/licenses/MIT]
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 ******************************************************************************/
