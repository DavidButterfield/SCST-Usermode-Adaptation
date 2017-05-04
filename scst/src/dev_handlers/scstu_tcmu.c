/* scstu_tcmu.c
 * Shim to run tcmu-runner handlers under an SCST_USERMODE build
 * Copyright 2017 David A. Butterfield
 *
 * Supports connection of a single tcmu-runner handler plugin.
 * This supports Read/Write/Flush only -- the handler will receive NO callbacks to handle_cmd()
 */
#ifdef SCST_USERMODE
#ifdef SCST_USERMODE_TCMU
#include "../../usermode/scstu_tcmu.h"

#define LOGID "scstu_tcmu"
#define trace_tcmu(fmtargs...)	sys_notice("TRACE: "fmtargs)

static struct kmem_cache * op_cache;

/******** API for tcmu-runner handler ********/

//XXXXX figure out the intended difference from tcmu_get_dev_block_size (module_params ?)
int
tcmu_get_attribute(struct tcmu_device * tcmu_dev, string_t attr_str)
{
    if (!strcmp(attr_str, "hw_block_size")) {
	if (tcmu_dev->scst_tgt_dev) {
	    struct scst_vdisk_dev * virt_dev = tcmu_dev->scst_tgt_dev->dev->dh_priv;
	    assert(virt_dev);
	    expect(virt_dev->blk_shift >= 9);   /* minimum block size 512 */
	    if (virt_dev->blk_shift < 9) {
		sys_warning("XXXXX assuming hw_block_size=512");
		virt_dev->blk_shift = 9;
	    }
	    return 1ul << virt_dev->blk_shift;
	} else {
	    //XXXXX Need to get this from somewhere
	    sys_warning("XXXXX ASSUMING hw_block_size=512");
	    return 1ul << 9;
	}
    }

    sys_warning("Unknown TCMU attribute %s requested for device %s",
		attr_str, tcmu_get_dev_name(tcmu_dev));
    return -ENOENT;
}

ssize_t
tcmu_get_device_size(struct tcmu_device * tcmu_dev)
{
    return 4*1024*1024*1024l;  //XXXXXXXXXXXX
}

int
tcmu_set_sense_data(uint8_t * sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t * info)
{
    memset(sense_buf, 0, 18);
    sense_buf[0] = 0x70;		/* current, fixed fmt sense data */
    assert((key&0xf0) == 0);
    sense_buf[2] = key;			/* ILLEGAL_REQUEST, MEDIUM_ERROR, etc */
    sense_buf[7] = 10;			/* additional sense length */
    put_unaligned_be16(asc_ascq, &sense_buf[12]);    /* ASC / ASCQ */
    if (info) {
	if (key == MISCOMPARE) {
	    put_unaligned_be32(*info, &sense_buf[3]);	/* cmd information */
	    sense_buf[0] |= 0x80;			/* cmd information valid */
	} else if (key == NOT_READY) {
	    put_unaligned_be16(*info, &sense_buf[16]);	/* key information */
	    sense_buf[15] |= 0x80;			/* key information valid */
	}
    }
    return SAM_STAT_CHECK_CONDITION;	/* for caller convenience */
}

/******** Rishathra ********/

static void
_thread_assimilate(void)
{
    assert(!current);
    /* This thread was created by the handler on its own -- set its "kernel thread" environment */
    /* The thread will deliver into "kernel" code that expects a "current" to be set */
    char name[32];
    int err = pthread_getname_np(pthread_self(), name, sizeof(name));
    if (err) strncpy(name, "tcmu_handler", sizeof(name));
    /* XXX These structures are not freed anywhere */
    sys_thread = sys_thread_alloc((void *)"scstu_tcmu", "scstu_tcmu", (void *)vstrdup(name));
    current = UMC_current_alloc();
    UMC_current_init(current, sys_thread, (void *)"scstu_tcmu", "scstu_tcmu", vstrdup(name));
}

static inline void
thread_assimilate(void)
{
    if (!current) _thread_assimilate();
}

/* XXX Only one handler can be registered at a time for now */
static struct tcmur_handler * scstu_tcmu_handler;

errno_t
tcmur_register_handler(struct tcmur_handler * handler)
{
    if (scstu_tcmu_handler == handler) {
	assert(handler->registered);
	return -EEXIST;
    }
    if (handler->registered) {
	return -EBADFD;	    /* messed-up state */
    }
    if (scstu_tcmu_handler != NULL) {
	return -EBUSY;
    }

    handler->registered = true;
    scstu_tcmu_handler = handler;
    return E_OK;
}

bool
tcmur_unregister_handler(struct tcmur_handler * handler)
{
    if (handler != scstu_tcmu_handler) {
	sys_warning("unregister nonexistent handler %s", handler->name);
	if (scstu_tcmu_handler)
	    sys_warning("registered handler is %s", scstu_tcmu_handler->name);
	return false;
    }
    if (!handler->registered) {
	sys_warning("unregister unregistered handler %s", handler->name);
    }

    handler->registered = false;
    scstu_tcmu_handler = NULL;
    return true;
}

/******** SCST VDISK BLOCKIO Implementor ********/

static errno_t
init_scst_vdisk_aio(void)
{
    assert(!op_cache);
    op_cache = kmem_cache_create(
			"scstu_tcmu_op_cache",
			sizeof(struct tcmulib_cmd),
			0,		/* use default alignment */
			IGNORED,	/* gfp */
			IGNORED);	/* constructer */
    assert(op_cache);

    assert(!scstu_tcmu_handler);
    errno_t err = handler_init();
    if (err) {
	sys_warning("handler_init() returned ERROR %d", err);
	expect(scstu_tcmu_handler == NULL);
	scstu_tcmu_handler = NULL;	/* just in case */
	kmem_cache_destroy(op_cache);
	op_cache = NULL;
	return err;
    }
    assert(scstu_tcmu_handler);

    return E_OK;
}

static void
exit_scst_vdisk_aio(void)
{
    assert(scstu_tcmu_handler);
    assert(op_cache);
    if (scstu_tcmu_handler) {
	expect(scstu_tcmu_handler->registered);
	if (scstu_tcmu_handler->handler_exit) {
	    scstu_tcmu_handler->handler_exit();
	    expect(scstu_tcmu_handler == NULL);
	}
	scstu_tcmu_handler = NULL;
    }
    kmem_cache_destroy(op_cache);
    op_cache = NULL;
}

static errno_t
vdisk_aio_attach_tgt(struct scst_tgt_dev * tgt_dev)
{
    errno_t err;
    struct tcmu_device * tcmu_dev;
    struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
    size_t dev_size;
    assert(virt_dev);
    expect(virt_dev->blk_shift);
    expect(virt_dev->nblocks);
    lockdep_assert_held(&scst_mutex);
    TRACE_ENTRY();

    tcmu_dev = vzalloc(sizeof(*tcmu_dev));
    tcmu_dev->handler = scstu_tcmu_handler;	//XXX Single handler
    tcmu_dev->scst_tgt_dev = tgt_dev;
    strlcpy(tcmu_dev->dev_name, "scstu_tcmu", sizeof(tcmu_dev->dev_name));
    strlcpy(tcmu_dev->cfgstring_orig, "/rbd/foo", sizeof(tcmu_dev->cfgstring_orig));  //XXXXX bogus
    tcmu_set_dev_block_size(tcmu_dev, 1 << virt_dev->blk_shift);
    tcmu_set_dev_num_lbas(tcmu_dev, virt_dev->nblocks);

    if (tcmu_dev->handler->check_config) {
	char * reason = NULL;
	char * cfg_str = tcmu_get_dev_cfgstring(tcmu_dev);
	if (!tcmu_dev->handler->check_config(cfg_str, &reason)) {
	    if (reason) {
		sys_warning(LOGID" handler %s failed check_config(%s) reason: %s",
			    tcmu_dev->handler->name, cfg_str, *reason);
		vfree(reason);
	    } else {
		sys_warning(LOGID" handler %s failed check_config(%s)",
			    tcmu_dev->handler->name, cfg_str);
	    }
	}
    }

    /* handler->open() might corrupt the config string using strtok() */
    memcpy(tcmu_dev->cfgstring, tcmu_dev->cfgstring_orig, sizeof(tcmu_dev->cfgstring));
    err = tcmu_dev->handler->open(tcmu_dev);
    if (err < 0) {
	expect_noerr(err, "%s handler->open(%s)",
			  tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));
	goto fail_free;
    }

    virt_dev->aio_private = tcmu_dev; 
    virt_dev->tgt_dev_cnt++;
    virt_dev->dif_fd = NULL;

#define tcmu_get_device_size(tcmu_dev)	((tcmu_dev)->block_size * (tcmu_dev)->num_lbas)
    expect_eq(virt_dev->file_size, tcmu_get_device_size(tcmu_dev));
    expect_eq(virt_dev->nblocks, tcmu_get_dev_num_lbas(tcmu_dev));
    dev_size = tcmu_get_device_size(tcmu_dev);

    if (dev_size < virt_dev->file_size) {
	sys_warning(LOGID" target %s size %"PRIu64" too small < %"PRIu64,
		    tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev),
		    dev_size, virt_dev->file_size);
	err = -EBADFD;	    /* messed-up state */
	goto fail_close;
    }

    sys_notice(LOGID" handler %s attach target %s size %"PRIu64,
	       tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev), virt_dev->file_size);
out:
    TRACE_EXIT_RES(err);
    return err;
fail_close:
    tcmu_dev->handler->close(tcmu_dev);
    virt_dev->tgt_dev_cnt--;
    virt_dev->aio_private = NULL;
    virt_dev->file_size = 0;
    virt_dev->nblocks = 0;
fail_free:
    vfree(tcmu_dev);
    goto out;
}

/* Does what vdisk_detach_tgt() does, and also frees the handler instance */
static void
vdisk_aio_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
    struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
    struct tcmu_device * tcmu_dev = virt_dev->aio_private;
    assert(tcmu_dev->scst_tgt_dev == tgt_dev);
    lockdep_assert_held(&scst_mutex);
    assert(virt_dev->blockio);

    if (--virt_dev->tgt_dev_cnt > 0) {
	trace_tcmu(LOGID" handler %s detach target: %s refcount remaining=%d",
	      tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev), virt_dev->tgt_dev_cnt);
	return;
    }

    sys_notice(LOGID" handler %s detach tgt: %s refcount zero -- closing",
	       tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));
    tcmu_dev->handler->close(tcmu_dev);
    vfree(tcmu_dev);
    virt_dev->aio_private = NULL;
    virt_dev->file_size = 0;
    virt_dev->nblocks = 0;
}

static inline void
aio_finish(struct tcmulib_cmd * op)
{
    blockio_check_finish(op->blockio_work);
    if (op->iovec && op->iovec != op->iov_space) vfree(op->iovec);
    kmem_cache_free(op_cache, op);
}

static inline void
aio_endio(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat, bool is_write)
{
    struct scst_blockio_work * blockio_work = op->blockio_work;
    thread_assimilate();

    /* See comment in blockio_endio() */
    if (unlikely(sam_stat != SAM_STAT_GOOD)) {
	unsigned long flags;
	spin_lock_irqsave(&vdev_err_lock, flags);

	if (is_write)
	    scst_set_cmd_error(blockio_work->cmd,
		    SCST_LOAD_SENSE(scst_sense_write_error));
	else
	    scst_set_cmd_error(blockio_work->cmd,
		    SCST_LOAD_SENSE(scst_sense_read_error));

	spin_unlock_irqrestore(&vdev_err_lock, flags);
    }

    aio_finish(op);
}

static void
aio_readv_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    aio_endio(tcmu_dev, op, sam_stat, false);
}

static void
aio_writev_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    aio_endio(tcmu_dev, op, sam_stat, true);
}

static void
blockio_exec_rw(struct vdisk_cmd_params *p, bool is_write, bool fua)
{
    struct scst_blockio_work * blockio_work;
    struct tcmulib_cmd * op = NULL;
    struct scst_cmd * scst_cmd = p->cmd;
    struct scst_vdisk_dev * virt_dev = scst_cmd->dev->dh_priv;
    struct tcmu_device * tcmu_dev = virt_dev->aio_private;

    bool dif = virt_dev->blk_integrity &&
	       (scst_get_dif_action(scst_get_dev_dif_actions(scst_cmd->cmd_dif_actions))
							    != SCST_DIF_ACTION_NONE);
    if (dif) {
	WARN_ONCE(dif, "XXX TODO: Add DIF support for scstu_tcmu");
	WARN_ONCE(fua, "XXX TODO: Add FUA support for scstu_tcmu");
	dif = false;
    }

    TRACE_ENTRY();
    WARN_ON(virt_dev->nullio);
    assert(tcmu_dev);
    assert(tcmu_dev->handler);
    assert(tcmu_dev->handler->registered);

    uint64_t seekpos = scst_cmd_get_lba(scst_cmd) << virt_dev->blk_shift;

    blockio_work = kmem_cache_zalloc(blockio_work_cachep, IGNORED);
    assert(blockio_work);
    blockio_work->cmd = scst_cmd;

    op = kmem_cache_zalloc(op_cache, IGNORED);
    assert(op);
    op->blockio_work = blockio_work;
    op->scst_cmd = scst_cmd;

    uint32_t niov = scst_cmd_get_sg_cnt(scst_cmd);
    if (niov <= ARRAY_SIZE(op->iov_space)) op->iovec = op->iov_space;
    else op->iovec = vzalloc(niov * sizeof(struct iovec));

    uint32_t iovn = 0;
    size_t aio_op_len = 0;
    uint8_t * segaddr;
    size_t seglen = scst_get_buf_first(scst_cmd, &segaddr); /* first segment of I/O buffer */

    /* Translate the segments of the (scattered) I/O buffer into iovec entries,
     * coalescing adjacent buffer segments.  (It is OK that coalescing means we
     * might not use all of the iovec array)
     */
    while (seglen > 0) {
	if (iovn > 0 && segaddr == op->iovec[iovn-1].iov_base + op->iovec[iovn-1].iov_len) {
	    op->iovec[iovn-1].iov_len += seglen;    /* coalesce with previous entry */
	} else {
	    assert_lt(iovn, niov);
	    op->iovec[iovn].iov_base = segaddr;	    /* fill in a new entry */
	    op->iovec[iovn].iov_len = seglen;
	    ++iovn;
	}

	aio_op_len += seglen;

	scst_put_buf(scst_cmd, segaddr);		/* release current SCST sg segment */
	seglen = scst_get_buf_next(scst_cmd, &segaddr);	/* get next sg segment */
    }

    expect_eq(aio_op_len % tcmu_get_dev_block_size(tcmu_dev), 0);

    op->iov_cnt = iovn;		    /* number of iovec elements we filled in */
    op->len = aio_op_len;	    /* I/O bytes */
    op->tcmu_dev = tcmu_dev;

    atomic_inc(&blockio_work->bios_inflight);

    /* Submit the command to the handler */
    sam_stat_t sam_stat;
    if (is_write) {
	op->done = aio_writev_done;
	sam_stat = tcmu_dev->handler->write(op->tcmu_dev, op, op->iovec, op->iov_cnt, op->len, seekpos);
	if (sam_stat != SAM_STAT_GOOD) goto out_finish;
    } else {
	op->done = aio_readv_done;
	sam_stat = tcmu_dev->handler->read(op->tcmu_dev, op, op->iovec, op->iov_cnt, op->len, seekpos);
	if (sam_stat != SAM_STAT_GOOD) goto out_finish;
    }

out:
    TRACE_EXIT();
    return;

out_finish:
    scst_set_cmd_error(scst_cmd, SCST_LOAD_SENSE(scst_sense_internal_failure));  //XXXXXXX use handler's sense data
    aio_finish(op);
    goto out;
}

/* NB: op->scst_cmd may be NULL */
static void
aio_fsync_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    thread_assimilate();
    struct scst_cmd * scst_cmd = op->scst_cmd;
    TRACE_ENTRY();

    if (unlikely(sam_stat != SAM_STAT_GOOD)) {
	PRINT_ERROR(LOGID" flush failed: %d (scst_cmd %p)", sam_stat, scst_cmd);
	if (scst_cmd) {
	    scst_set_cmd_error(scst_cmd, SCST_LOAD_SENSE(scst_sense_write_error));
	}
    }

    if (scst_cmd) {
	scst_cmd->completed = 1;
	scst_cmd->scst_cmd_done(scst_cmd, SCST_CMD_STATE_DEFAULT, scst_estimate_context());
    }

    if (op->sync_done) complete(op->sync_done); /* for synchronous flush */
    kmem_cache_free(op_cache, op);

    TRACE_EXIT();
}

/* NB: scst_cmd may be NULL */
static errno_t
vdisk_fsync_blockio(loff_t loff, loff_t len, struct scst_device *dev,
		    gfp_t gfp_flags, struct scst_cmd *scst_cmd, bool async)
{
    errno_t err = E_OK;
    struct scst_vdisk_dev * virt_dev = dev->dh_priv;
    struct tcmu_device * tcmu_dev = virt_dev->aio_private;
    struct tcmulib_cmd * op;
    DECLARE_COMPLETION_ONSTACK(scst_completion);

    TRACE_ENTRY();
    EXTRACHECKS_BUG_ON(!virt_dev->blockio);
    WARN_ONCE(virt_dev->dif_fd != NULL, "XXX TODO: Add DIF support for RBE");

    assert(tcmu_dev);
    assert(tcmu_dev->handler);
    assert(tcmu_dev->handler->registered);

    op = kmem_cache_zalloc(op_cache, gfp_flags);
    op->scst_cmd = scst_cmd;
    op->tcmu_dev = tcmu_dev;
    op->done = aio_fsync_done;

    if (!async) op->sync_done = &scst_completion;

    sam_stat_t sam_stat = tcmu_dev->handler->flush(op->tcmu_dev, op);
    if (sam_stat != SAM_STAT_GOOD) {
	if (sam_stat == SAM_STAT_TASK_SET_FULL) err = -EBUSY;	//XXXX right?
	else err = -EIO;					//XXXX right?
	goto out_finish;
    }

    if (!async) {
	trace_tcmu("vdisk_fsync_blockio: synchronous fsync starts");
	wait_for_completion(&scst_completion);
	trace_tcmu("vdisk_fsync_blockio: synchronous fsync finishes");
    }

out:
    TRACE_EXIT_RES(err);
    return err;

out_finish:
    if (scst_cmd) {
	scst_set_cmd_error(scst_cmd, SCST_LOAD_SENSE(scst_sense_internal_failure));
	scst_cmd->completed = 1;
	scst_cmd->scst_cmd_done(scst_cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
    }
    kmem_cache_free(op_cache, op);
    goto out;
}

/* Supposed to return 0 on success with file size in *file_size; otherwise -errno */
static errno_t
vdisk_get_file_size(const char * filename, bool blockio, loff_t *file_sizep)
{
    errno_t err = E_OK;
    struct tcmu_device * tcmu_dev;
    assert(file_sizep);
    assert(blockio);
    TRACE_ENTRY();
    assert(filename);
    assert(strlen(filename));

    *file_sizep = 0;

    if (!strlen(filename)) return -EINVAL;
    if (strlen(filename) >= sizeof(tcmu_dev->cfgstring)) return -EINVAL;

    tcmu_dev = vzalloc(sizeof(*tcmu_dev));
    tcmu_dev->handler = scstu_tcmu_handler;	//XXX Single handler
    strlcpy(tcmu_dev->dev_name, "scstu_tcmu", sizeof(tcmu_dev->dev_name));
    strlcpy(tcmu_dev->cfgstring_orig, filename, sizeof(tcmu_dev->cfgstring));

    /* handler->open() might corrupt the config string using strtok() */
    memcpy(tcmu_dev->cfgstring, tcmu_dev->cfgstring_orig, sizeof(tcmu_dev->cfgstring));
    err = tcmu_dev->handler->open(tcmu_dev);
    if (err < 0) {
	expect_noerr(err, "%s handler->open(%s)",
			  tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));
	goto free;
    }

    *file_sizep = tcmu_get_device_size(tcmu_dev);
    tcmu_dev->handler->close(tcmu_dev);

free:
    trace_tcmu("TCMU device size=%"PRIu64, *file_sizep);
    vfree(tcmu_dev);
    TRACE_EXIT_RES(err);
    return err;
}

#endif /* SCST_USERMODE_TCMU */
#endif /* SCST_USERMODE */
