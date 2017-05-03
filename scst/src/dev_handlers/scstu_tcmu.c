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

#define MY_ID "scstu_tcmu"

static struct kmem_cache * op_cache;

/******** Interface to tcmu-runner handler ********/

/* "tcmu" symbols below are intended to be compatible with tcmu-runner handlers */

struct tcmu_device {
    void		      * hm_private;	    /* keep first for efficiency */
    // struct scst_tgt_dev	      * tgt_dev;
    uint64_t			num_lbas;
    uint32_t			block_size;
    char			dev_name[16];
    char			cfgstring[256];
    struct tcmur_handler      * handler;
};

char *
tcmu_get_dev_name(struct tcmu_device * tcmu_dev)
{
    return tcmu_dev->dev_name;
}

char *
tcmu_get_dev_cfgstring(struct tcmu_device * tcmu_dev)
{
    return tcmu_dev->cfgstring;
}

long long
tcmu_get_device_size(struct tcmu_device * tcmu_dev)
{
    return tcmu_dev->num_lbas * tcmu_dev->block_size;
}

uint32_t
tcmu_get_dev_block_size(struct tcmu_device * tcmu_dev)
{
    return tcmu_dev->block_size;
}

void
tcmu_set_dev_block_size(struct tcmu_device * tcmu_dev, uint32_t block_size)
{
    tcmu_dev->block_size = block_size;
}

uint64_t
tcmu_get_dev_num_lbas(struct tcmu_device * tcmu_dev)
{
    return tcmu_dev->num_lbas;
}

void
tcmu_set_dev_num_lbas(struct tcmu_device * tcmu_dev, uint64_t num_lbas)
{
    tcmu_dev->num_lbas = num_lbas;
}

/*
void *
tcmu_get_dev_private(struct tcmu_device * tcmu_dev)
{
    return tcmu_dev->hm_private;
}
*/

void
tcmu_set_dev_private(struct tcmu_device * tcmu_dev, void *priv)
{
    tcmu_dev->hm_private = priv;
}

//XXXXX figure out the intended difference from tcmu_get_dev_block_size
errno_t
tcmu_get_attribute(struct tcmu_device * tcmu_dev, string_t attr_str)
{
    if (!strcmp(attr_str, "hw_block_size")) {
	return tcmu_dev->block_size;
    }
    sys_warning("Unknown TCMU attribute %s on device %s", attr_str, tcmu_dev->dev_name);
    return 0;
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

size_t
tcmu_memcpy_into_iovec(struct iovec * iov, size_t niov, void * buf, size_t len)
{
    size_t ret = 0;
    while (len && niov) {
	size_t seglen = min(len, iov->iov_len);
	memcpy(iov->iov_base, buf, seglen);
	ret += seglen;
	buf += seglen;
	len -= seglen;
	++iov;
	--niov;
    }
    return ret;
}

size_t
tcmu_memcpy_from_iovec(void * buf, size_t len, struct iovec *iov, size_t niov)
{
    size_t ret = 0;
    while (len && niov) {
	size_t seglen = min(len, iov->iov_len);
	memcpy(buf, iov->iov_base, seglen);
	ret += seglen;
	buf += seglen;
	len -= seglen;
	++iov;
	--niov;
    }
    return ret;
}

// XXX
// off_t tcmu_compare_with_iovec(void *mem, struct iovec *iovec, size_t size);
// size_t tcmu_iovec_length(struct iovec *iovec, size_t iov_cnt);
// void	tcmu_zero_iovec(struct iovec *iovec, size_t iov_cnt);
// void	tcmu_seek_in_iovec(struct iovec *iovec, size_t count);

/******** Rishathra ********/

static void
_thread_assimilate(void)
{
    assert(!current);
    /* This thread was created by the handler on its own -- set its "kernel thread" environment */
    /* The thread will deliver into "kernel" code that expects a "current" to be set */
    char name[32];
    int err = pthread_getname_np(pthread_self(), name, sizeof(name));
    if (err) strncpy(name, "tmcu_handler", sizeof(name));
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
    /* Validate assumption used for fast access to hm_private */
    assert_eq(offsetof(struct tcmu_device, hm_private), 0);

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
    if (err) goto free_cache;
    assert(scstu_tcmu_handler);

    return E_OK;

free_cache:
    kmem_cache_destroy(op_cache);
    op_cache = NULL;
    return err;
}

static void
exit_scst_vdisk_aio(void)
{
    assert(op_cache);
    if (scstu_tcmu_handler && scstu_tcmu_handler->handler_exit) {
	scstu_tcmu_handler->handler_exit();
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
    assert(virt_dev);
    lockdep_assert_held(&scst_mutex);
    TRACE_ENTRY();

    tcmu_dev = vzalloc(sizeof(*tcmu_dev));
    virt_dev->aio_private = tcmu_dev; 
    // tcmu_dev->tgt_dev = tgt_dev;
    strlcpy(tcmu_dev->dev_name, "scstu_tcmu", sizeof(tcmu_dev->dev_name));    //XXXXX bogus
    tcmu_dev->block_size = 1 << virt_dev->blk_shift;
    tcmu_dev->num_lbas = virt_dev->nblocks;
    strlcpy(tcmu_dev->cfgstring, "/rbd/foo", sizeof(tcmu_dev->cfgstring));  //XXXXX bogus
    tcmu_dev->handler = scstu_tcmu_handler;

    if (!virt_dev->blk_shift) {
	sys_warning("bad virt_dev->blk_shift=0, using block_size=512");
	tcmu_dev->block_size = 512;
    }
    if (!virt_dev->nblocks) {
	tcmu_dev->num_lbas = 8192*1024;
	sys_warning("bad virt_dev->nblocks=0, using %"PRIu64, tcmu_dev->block_size);
    }

    if (tcmu_dev->handler->check_config) {
	char * reason = NULL;
	if (!tcmu_dev->handler->check_config(tcmu_dev->cfgstring, &reason)) {
	    if (reason) {
		sys_warning(MY_ID" handler failed check_config(%s) reason: %s",
			    tcmu_dev->cfgstring, *reason);
		vfree(reason);
	    } else {
		sys_warning(MY_ID" handler failed check_config(%s)", tcmu_dev->cfgstring);
	    }
	}
    }

    err = tcmu_dev->handler->open(tcmu_dev);
    if (err < 0) {
	expect_noerr(err, "tcmu_dev->handler->open(%s)", tcmu_dev->handler->name);
	goto fail_free;
    }

    virt_dev->tgt_dev_cnt++;
    virt_dev->dif_fd = NULL;

    /* XXXX Should check actual backing storage size against expected */

    //XXXX hack because vdisk_get_file_size is not implemented
    if (virt_dev->file_size == 0) {
	virt_dev->file_size = tcmu_dev->num_lbas * tcmu_dev->block_size;
	virt_dev->nblocks = tcmu_dev->num_lbas;
    }
    expect_eq(virt_dev->file_size, tcmu_dev->num_lbas * tcmu_dev->block_size);
    expect_eq(virt_dev->nblocks, tcmu_dev->num_lbas);

    if (tcmu_dev->num_lbas * tcmu_dev->block_size < virt_dev->file_size) {
	sys_warning(MY_ID" target %s size %"PRIu64" too small < %"PRIu64,
		    tcmu_dev->handler->name, tcmu_dev->num_lbas * tcmu_dev->block_size,
		    virt_dev->file_size);
	err = -EBADFD;	    /* messed-up state */
	goto fail_close;
    }

    sys_notice(MY_ID" attach_target %s size %"PRIu64,
	       tcmu_dev->handler->name, virt_dev->file_size);
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
    lockdep_assert_held(&scst_mutex);
    assert(virt_dev->blockio);

    if (--virt_dev->tgt_dev_cnt > 0) {
	trace(MY_ID" detach_tgt: %s refcount remaining=%d",
	      tcmu_dev->dev_name, virt_dev->tgt_dev_cnt);
	return;
    }

    sys_notice(MY_ID" detach_tgt: %s refcount zero -- closing", tcmu_dev->dev_name);
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
    size_t aio_op_len;
    uint32_t iovn;
    struct tcmulib_cmd * op = NULL;
    struct scst_cmd * scst_cmd = p->cmd;
    struct scst_vdisk_dev * virt_dev = scst_cmd->dev->dh_priv;
    struct tcmu_device * tcmu_dev = virt_dev->aio_private;
    bool dif = virt_dev->blk_integrity &&
	       (scst_get_dif_action(scst_get_dev_dif_actions(scst_cmd->cmd_dif_actions))
							    != SCST_DIF_ACTION_NONE);
    TRACE_ENTRY();
    WARN_ON(virt_dev->nullio);
    assert(tcmu_dev);
    assert(tcmu_dev->handler);
    assert(tcmu_dev->handler->registered);

    if (dif) {
	WARN_ONCE(dif, "XXX TODO: Add DIF support for scstu_tcmu");
	WARN_ONCE(fua, "XXX TODO: Add FUA support for scstu_tcmu");
	dif = false;
    }

    u64 seekpos = scst_cmd_get_lba(scst_cmd) << virt_dev->blk_shift;

    blockio_work = kmem_cache_zalloc(blockio_work_cachep, IGNORED);
    assert(blockio_work);
    blockio_work->cmd = scst_cmd;
    atomic_set(&blockio_work->bios_inflight, 1);

    op = kmem_cache_zalloc(op_cache, IGNORED);
    assert(op);
    op->blockio_work = blockio_work;
    op->scst_cmd = scst_cmd;

    uint32_t niov = scst_cmd_get_sg_cnt(scst_cmd);
    if (niov <= ARRAY_SIZE(op->iov_space)) op->iovec = op->iov_space;
    else op->iovec = vzalloc(niov * sizeof(struct iovec));

    iovn = 0;
    aio_op_len = 0;
    uint8_t * segaddr;
    size_t seglen = scst_get_buf_first(scst_cmd, &segaddr); /* first segment of I/O buffer */

    /* Translate the segments of the (scattered) receive buffer into iov
     * entries, coalescing adjacent buffer segments.  (It is OK that any
     * coalescing means we don't use all of the iovec array)
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

    expect_eq(aio_op_len % 512, 0);

    op->iov_cnt = iovn;		    /* number of iovec elements we filled in */
    op->len = aio_op_len;
    op->tcmu_dev = tcmu_dev;

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

/* NB: scst_cmd may be NULL */
static void
aio_fsync_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    thread_assimilate();
    struct scst_cmd * scst_cmd = op->scst_cmd;
    TRACE_ENTRY();

    if (unlikely(sam_stat != SAM_STAT_GOOD)) {
	PRINT_ERROR(MY_ID" flush failed: %d (scst_cmd %p)", sam_stat, scst_cmd);
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
vdisk_fsync_blockio(loff_t loff, loff_t len, struct scst_device *scst_dev,
		    gfp_t gfp_flags, struct scst_cmd *scst_cmd, bool async)
{
    errno_t err = E_OK;
    struct scst_vdisk_dev * virt_dev = scst_dev->dh_priv;
    struct tcmu_device * tcmu_dev = virt_dev->aio_private;
    struct tcmulib_cmd * op = kmem_cache_zalloc(op_cache, IGNORED);
    DECLARE_COMPLETION_ONSTACK(scst_completion);

    TRACE_ENTRY();
    assert(op);
    EXTRACHECKS_BUG_ON(!virt_dev->blockio);
    WARN_ONCE(virt_dev->dif_fd != NULL, "XXX TODO: Add DIF support for RBE");

    assert(tcmu_dev);
    assert(tcmu_dev->handler);
    assert(tcmu_dev->handler->registered);

    op->scst_cmd = scst_cmd;
    op->tcmu_dev = tcmu_dev;
    op->done = aio_fsync_done;

    if (!async) op->sync_done = &scst_completion;

    sam_stat_t sam_stat = tcmu_dev->handler->flush(op->tcmu_dev, op);
    if (sam_stat != SAM_STAT_GOOD) {
	expect_eq(sam_stat, SAM_STAT_TASK_SET_FULL);
	err = -EBUSY;	    /* XXXX right? */
	goto out_free_op;
    }

    if (!async) {
	sys_notice("vdisk_fsync_blockio: synchronous fsync starts");
	wait_for_completion(&scst_completion);
	sys_notice("vdisk_fsync_blockio: synchronous fsync finishes");
    }

out:
    TRACE_EXIT_RES(err);
    return err;

out_free_op:
    scst_set_cmd_error(scst_cmd, SCST_LOAD_SENSE(scst_sense_internal_failure));
    scst_cmd->completed = 1;
    scst_cmd->scst_cmd_done(scst_cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
    kmem_cache_free(op_cache, op);
    goto out;
}

/* Supposed to return 0 on success with file size in *file_size; otherwise -errno */
static errno_t
vdisk_get_file_size(const char * filename, bool blockio, loff_t *file_sizep)
{
    errno_t err = E_OK;
    assert(file_sizep);
    assert(blockio);
    TRACE_ENTRY();

    sys_warning(MY_ID" get_file_size(%s) not implemented", filename);
    *file_sizep = 0;	//XXXX fixed up in the attach function

    TRACE_EXIT_RES(err);
    return err;
}

#endif /* SCST_USERMODE_TCMU */
#endif /* SCST_USERMODE */
