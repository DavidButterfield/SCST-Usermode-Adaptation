/* scst_vdisk_ceph_rbd.c
 * Copyright 2017 David A. Butterfield
 * SCST_USERMODE support for SCST BLOCKIO using the Ceph RBD provider
 *
 * Compiled with SCST_USERMODE_CEPH_RBD to take over implementation of blockio.
 * This supports the same configuration as using scstu_tcmu and the rbd.c
 * plugin for tcmu-runner -- but is older and buggier.  I suggest doing it the
 * other way.
 *
 * Just to be clear, this code runs only in usermode, but it is called from SCST
 * kernel code that is not aware it is running outside the kernel in usermode.
 */
#ifdef SCST_USERMODE
#ifdef SCST_USERMODE_CEPH_RBD
#include <rbd/librbd.h>

#define trace_debug(fmtargs...) TRACE(TRACE_AIO, fmtargs)

static struct kmem_cache      * aio_op_cache;

struct scst_aio_tgt {
    string_t			name;
    string_t			pool;
    struct scst_rados         * rados;
    rados_ioctx_t		ioctx;
    rbd_image_t			image;
    size_t			size;
};

#define VDISK_AIO_MAXIOV 1  //XXXX

typedef struct vdisk_aio_op {
    struct iovec	        iov[VDISK_AIO_MAXIOV];
    unsigned int		niov;
    struct scst_cmd	      * cmd;
    struct scst_device	      * dev;
    size_t			len;		/* read/write bytes */
    struct scst_blockio_work  * blockio_work;	/* read and write */
    struct completion         * op_done;	/* for synchronous flush */
} vdisk_aio_op_t;

static rados_t rados;	//XXX single instance; use only in vdisk_aio_attach_tgt

static void
rbd_thread_assimilate(void)
{
    assert(!current);
    /* This thread was created by rados on its own -- set its "kernel thread" environment */
    /* The thread will deliver into "kernel" code expecting a "current" to be set */
    char name[32];
    int err = pthread_getname_np(pthread_self(), name, sizeof(name));
    if (err) strncpy(name, "rados_thread", sizeof(name));

    /* XXX These structures are not freed anywhere */
    sys_thread = sys_thread_alloc(rados, rados, kstrdup(name, IGNORED));
    current = UMC_current_alloc();
    UMC_current_init(current, sys_thread, (void *)rados, rados, kstrdup(name, IGNORED));
}

static inline errno_t
aio_get_return_value(rbd_completion_t completion)
{
    if (!current) {
	rbd_thread_assimilate();
    }
    return rbd_aio_get_return_value(completion);
}

static errno_t
init_scst_vdisk_aio(void)
{
    errno_t err;
    assert(!aio_op_cache);
    aio_op_cache = kmem_cache_create(
			"aio_op_cache",
			sizeof(struct vdisk_aio_op),
			0,		/* use default alignment */
			IGNORED,	/* gfp */
			IGNORED);	/* constructer */
    assert(aio_op_cache);

    assert(!rados);
    err = rados_create(&rados, NULL);
    if (err < 0) {
	sys_warning("rados_create() returned %d (%s)", err, strerror(-err));
	goto free_cache;
    }
    assert(rados);
    sys_notice("finished rados_create()");

    err = rados_conf_read_file(rados, NULL);
    if (err < 0) {
	sys_warning("rados_conf_read_file() returned %d (%s)", err, strerror(-err));
	goto rados_destroy;
    }
    sys_notice("finished rados_conf_read_file()");

    err = rados_connect(rados);
    if (err < 0) {
	sys_warning("rados_connect() returned %d (%s)", err, strerror(-err));
	goto rados_destroy;
    }
    sys_notice("finished rados_connect()");

    return E_OK;

rados_destroy:
    rados_shutdown(rados);
    rados = NULL;

free_cache:
    kmem_cache_destroy(aio_op_cache);
    aio_op_cache = NULL;

    return err;
}

static void
exit_scst_vdisk_aio(void)
{
    if (!rados) return;

    rados_shutdown(rados);
    rados = NULL;

    assert(aio_op_cache);
    kmem_cache_destroy(aio_op_cache);
    aio_op_cache = NULL;
}

static errno_t
vdisk_aio_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
    struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
    struct scst_aio_tgt * tgt = vzalloc(sizeof(*tgt));
    virt_dev->aio_private = tgt; 
    errno_t err;
    lockdep_assert_held(&scst_mutex);
    assert(rados);
    if (!rados) return -ENOTCONN;

    TRACE_ENTRY();

    /* For now there is only one rados instance; do not know it except here to set tgt->rados */
    tgt->rados = rados;		//XXXX

    tgt->pool = "rbd";		//XXXX parse filename into pool/imagename or something
    assert(virt_dev->filename[0]);
    tgt->name = virt_dev->filename + 1;	/* skip the "/" */

    virt_dev->tgt_dev_cnt++;
    virt_dev->dif_fd = NULL;

    err = rados_ioctx_create(rados, tgt->pool, &tgt->ioctx);
    if (err < 0) {
	sys_warning("rados_ioctx_create(%s) returned %d (%s)",
		    tgt->pool, err, strerror(-err));
	goto fail_out;
    }
    trace_debug("finished rados_ioctx_create(%s)", tgt->pool);

    err = rbd_open(tgt->ioctx, tgt->name, &tgt->image, NULL);
    if (err < 0) {
	sys_warning("rbd_open(%s/%s) returned %d (%s)",
		    tgt->pool, tgt->name, err, strerror(-err));
	goto rados_disconnect;
    }
    trace_debug("finished rbd_open(%s/%s)", tgt->pool, tgt->name);

    err = rbd_get_size(tgt->image, &tgt->size);
    if(err < 0) {
	sys_warning("rbd_get_size(%s/%s) returned %d (%s)",
		    tgt->pool, tgt->name, err, strerror(-err));
	goto rados_disconnect;
    }

    if (virt_dev->file_size == 0) {
	//XXXXXX hack needs to be fixed right
	virt_dev->file_size = tgt->size;
	virt_dev->nblocks = virt_dev->file_size >> virt_dev->blk_shift;
    }

    expect_eq(tgt->size, virt_dev->file_size);
    if (tgt->size < virt_dev->file_size) {
	sys_warning("ceph_rbd attach_tgt(%s/%s) "
		    "RBD target size (%"PRIu64") < (%"PRIu64") virt_dev->file_size",
		    tgt->pool, tgt->name, tgt->size, virt_dev->file_size);
	goto rados_disconnect;
    }

    sys_notice("ceph_rbd attach_tgt(%s/%s) size %"PRIu64"/0x%"PRIx64,
	       tgt->pool, tgt->name, tgt->size, tgt->size);

out:
    TRACE_EXIT_RES(err);
    return err;

rados_disconnect:
    rados_ioctx_destroy(tgt->ioctx);

fail_out:
    virt_dev->tgt_dev_cnt--;
    goto out;
}

/* Does what vdisk_detach_tgt() does, and also frees the rbd instance */
static void
vdisk_aio_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
    assert(rados);
    struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
    struct scst_aio_tgt * tgt = virt_dev->aio_private;
    lockdep_assert_held(&scst_mutex);
    assert(virt_dev->blockio);

    if (--virt_dev->tgt_dev_cnt == 0) {
	sys_notice("ceph_rbd detach_tgt: %s refcount zero -- calling rados_ioctx_destroy()",
		   virt_dev->name);
	rados_ioctx_destroy(tgt->ioctx);
    } else {
	trace_debug("vdisk_aio_detach_tgt %s/%s %d refcount remaining",
		    tgt->name, tgt->pool, virt_dev->tgt_dev_cnt);
    }
}

static inline void
aio_endio(rbd_completion_t completion, struct vdisk_aio_op * op, bool is_write)
{
    struct scst_blockio_work * blockio_work = op->blockio_work;

    /* XXX Ceph does not document in any obvious place the specific values
     *	   returned by this function, and neither do the the return values
     *	   follow the corresponding POSIX interfaces, leaving us to guess.
     *     They usually seem to think non-zero is a failure, which seems
     *     to be true for write ops but not read ops.
     */
    ssize_t size = aio_get_return_value(completion);
    ssize_t expected = is_write ? 0 : op->len;

    rbd_aio_release(completion);

    if (unlikely(size != expected)) {
	unsigned long flags;
	PRINT_ERROR_RATELIMITED(
		"RBD I/O for %s cmd %p size %"PRId64" finished with %s %"PRId64,
		is_write?"write":"read", blockio_work->cmd, op->len,
		size<=0?"error":"wrong size", size);

	/* To protect from several bios finishing simultaneously +
	 * unsuccessful DIF tags reading/writing
	 */
	spin_lock_irqsave(&vdev_err_lock, flags);

	if (is_write)
	    scst_set_cmd_error(blockio_work->cmd,
		    SCST_LOAD_SENSE(scst_sense_write_error));
	else
	    scst_set_cmd_error(blockio_work->cmd,
		    SCST_LOAD_SENSE(scst_sense_read_error));

	spin_unlock_irqrestore(&vdev_err_lock, flags);
    }

    blockio_check_finish(blockio_work);
    kmem_cache_free(aio_op_cache, op);
}

static void
aio_readv_done(rbd_completion_t completion, void * op)
{
    aio_endio(completion, op, false);
}

static void
aio_writev_done(rbd_completion_t completion, void * op)
{
    aio_endio(completion, op, true);
}

static void
blockio_exec_rw(struct vdisk_cmd_params *p, bool is_write, bool fua)
{
    struct scst_cmd *cmd = p->cmd;
    gfp_t gfp_mask = cmd->cmd_gfp_mask;
    rbd_completion_t rbd_completion;
    struct vdisk_aio_op * op = NULL;
    struct scst_device *dev = cmd->dev;
    struct scst_vdisk_dev *virt_dev = dev->dh_priv;
    struct scst_aio_tgt * tgt = virt_dev->aio_private;
    bool dif = virt_dev->blk_integrity &&
	       (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions))
							    != SCST_DIF_ACTION_NONE);
    struct scst_blockio_work * blockio_work;
    u64 seekpos = scst_cmd_get_lba(cmd) << dev->block_shift;
    size_t aio_op_len;
    uint32_t niov;
    TRACE_ENTRY();
    WARN_ON(virt_dev->nullio);
    WARN_ONCE(dif, "XXX TODO: Add DIF support for RBD");
    WARN_ONCE(fua, "XXX TODO: Add FUA support for RBD");

    blockio_work = kmem_cache_zalloc(blockio_work_cachep, gfp_mask);
    assert(blockio_work);
    blockio_work->cmd = cmd;
    /* Start with extra ref to block completion until we are done with the submit(s) */
    atomic_set(&blockio_work->bios_inflight, 1);

    uint8_t * buf;
    size_t length = scst_get_buf_first(cmd, &buf);	/* first segment of I/O buffer */

    if (WARN_ONCE((length % 512) != 0 || ((uintptr_t)buf % 512) != 0,
		  "Refused aio with invalid length %d and/or address %p.\n",
		  length, buf)) {
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto put_out;
    }

    /* Translate the segments of the receive buffer into iov entries,
     * coalescing adjacent buffer segments -- when we have accumulated the
     * maximum number of entries, or we have exhausted the list of receive
     * buffer segments, submit another op.
     */
    while (length > 0) {	/* Process (another) receive buffer segment */
	if (!op) {
	    /* Allocate (another) op */
	    op = kmem_cache_zalloc(aio_op_cache, gfp_mask);
	    op->blockio_work = blockio_work;
	    assert(op);
	    niov = 0;
	    aio_op_len = 0;
	}

	aio_op_len += length;

	assert_lt(niov, ARRAY_SIZE(op->iov));
	if (niov > 0 && buf == op->iov[niov-1].iov_base + op->iov[niov-1].iov_len) {
	    /* coalesce with previous entry */
	    op->iov[niov-1].iov_len += length;
	} else {
	    /* fill in a new entry */
	    op->iov[niov].iov_base = buf;
	    op->iov[niov].iov_len = length;
	    ++niov;
	}

	scst_put_buf(cmd, buf);		 /* release current segment */
	length = scst_get_buf_next(cmd, &buf);	/* get next segment */

	if (niov >= ARRAY_SIZE(op->iov) || length == 0) {
	    /* The iovec array is full, or we have exhausted the segment list */
	    assert_le(niov, ARRAY_SIZE(op->iov));
	    assert_eq(aio_op_len % 512, 0);

	    op->niov = niov;
	    op->cmd = cmd;
	    op->dev = dev;
	    op->len = aio_op_len;

	    atomic_inc(&blockio_work->bios_inflight);

	    /* Pass the request to librbd */
	    errno_t err;
	    if (is_write) {
		err = rbd_aio_create_completion(op, aio_writev_done, &rbd_completion);
		if (err < 0) {
		    goto out_free_op;
		}
		err = rbd_aio_writev(tgt->image, op->iov, niov, seekpos, rbd_completion);
		if (err < 0) {
		    goto out_release_completion;
		}
	    } else {
		err = rbd_aio_create_completion(op, aio_readv_done, &rbd_completion);
		if (err < 0) {
		    goto out_free_op;
		}
		err = rbd_aio_readv(tgt->image, op->iov, niov, seekpos, rbd_completion);
		if (err < 0) {
		    goto out_release_completion;
		}
	    }

	    seekpos += aio_op_len;
	    op = NULL;
	}
    }

out:
    blockio_check_finish(blockio_work); /* release extra ref we took on bios_inflight */
    TRACE_EXIT();
    return;

out_release_completion:
    rbd_aio_release(rbd_completion);

out_free_op:
    scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_internal_failure));  //XXXXX
    kmem_cache_free(aio_op_cache, op);

put_out:
    scst_put_buf(cmd, buf);
    cmd->completed = 1;
    cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
    goto out;
}

static void
aio_fsync_done(rbd_completion_t completion, void * v_op)
{
    errno_t err = aio_get_return_value(completion);
    struct vdisk_aio_op * op = v_op;
    struct scst_cmd * cmd = op->cmd;
    TRACE_ENTRY();
    assert(rados);

    rbd_aio_release(completion);

    if (unlikely(err != 0)) {
	PRINT_ERROR("FLUSH aio failed: %d (cmd %p)", err, cmd);
	if (cmd) {
	    scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_write_error));
	}
    }

    if (cmd) {
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, scst_estimate_context());
    }

    if (op->op_done) complete(op->op_done); /* for synchronous flush */
    kmem_cache_free(aio_op_cache, op);

    TRACE_EXIT();
}

static errno_t
vdisk_fsync_blockio(loff_t loff,
		    loff_t len, struct scst_device *dev, gfp_t gfp_flags,
		    struct scst_cmd *cmd, bool async)
{
    struct scst_vdisk_dev *virt_dev = dev->dh_priv;
    struct scst_aio_tgt * tgt = virt_dev->aio_private;

    TRACE_ENTRY();
    EXTRACHECKS_BUG_ON(!virt_dev->blockio);
    assert(rados);

    WARN_ONCE(virt_dev->dif_fd != NULL, "XXX TODO: Add DIF support for RBE");

    struct vdisk_aio_op * op = kmem_cache_zalloc(aio_op_cache, IGNORED);
    op->cmd = cmd;
    op->dev = dev;

    DECLARE_COMPLETION_ONSTACK(scst_completion);
    if (!async) op->op_done = &scst_completion;

    rbd_completion_t rbd_completion;
    errno_t err = rbd_aio_create_completion(op, aio_fsync_done, &rbd_completion);
    if (err < 0) {
	goto out_free_op;
    }

    err = rbd_aio_flush(tgt->image, rbd_completion);
    if (err < 0) {
	goto out_release_completion;
    }

    if (!async) {
	sys_notice("vdisk_fsync_blockio: synchronous fsync starts");
	wait_for_completion(&scst_completion);
	sys_notice("vdisk_fsync_blockio: synchronous fsync finishes");
    }

out:
    TRACE_EXIT_RES(err);
    return err;

out_release_completion:
    rbd_aio_release(rbd_completion);

out_free_op:
    scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_internal_failure));  //XXXXX
    kmem_cache_free(aio_op_cache, op);

    cmd->completed = 1;
    cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
    goto out;
}

/* Returns 0 on success with file size in *file_size; otherwise -errno */
static errno_t
vdisk_get_file_size(struct scst_vdisk_dev *virt_dev, loff_t *file_sizep)
{
    const char *filename = virt_dev->filename;
    bool blockio = virt_dev->blockio;
    errno_t err = E_OK;
    assert(file_sizep);
    assert(blockio);
    TRACE_ENTRY();

    sys_notice("XXXXXXXXXXXXXXXXXX ceph_rbd get_file_size(%s)", filename);

    *file_sizep = 0;

#if 0
    //XXXXX
    struct scst_aio_tgt * tgt = virt_dev->aio_private;
    if (!rados) return ENOTCONN;
    if (!tgt) return ENOTCONN;
    if (!tgt->image) return ENOTCONN;

    assert(rados);
    assert(tgt->image);

    err = rbd_get_size(tgt->image, file_sizep);
    if (err < 0) {
	sys_warning("rbd_get_size(%s/%s) returned %d (%s)",
		    tgt->pool, tgt->name, err, strerror(-err));
    } else {
	sys_notice("ceph_rbd get_file_size(%s/%s) returns %"PRIu64"/0x%"PRIx64,
		   tgt->pool, tgt->name, tgt->size, tgt->size);
    }
#endif

    TRACE_EXIT_RES(err);
    return err;
}

#endif /* SCST_USERMODE_CEPH_RBD */
#endif /* SCST_USERMODE */
