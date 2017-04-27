/* scst_vdisk_aio.c
 * Copyright 2016 David A. Butterfield
 * SCST_USERMODE support for async disk I/O using the MTE aio_service provider
 *
 * When compiled with SCST_USERMODE_AIO, takes over implementation of blockio
 */
#ifdef SCST_USERMODE
#ifdef SCST_USERMODE_AIO

#ifdef SCST_USERMODE_CEPH_RBD
#include "scst_vdisk_ceph_rbd.c"
#else

#include "mtelib.h"

#define aio_exec(cmd) blockio_exec(cmd)

/* Configuration for the MTE AIO service Implementor */
struct MTE_aio_service_cfg const aios_cfg = {
    /* Maximum number of aio operations (read, write, sync) concurrently
     * outstanding to the kernel on any one open aio_handle (representing
     * one open backing file or block device) */
    .max_ops_outstanding = 256,		//XXXX TUNE

    /* When completion of an aio operation drops the number of aio ops
     * outstanding to the kernel below this threshold, another batch of
     * ops will be submitted, as many as are available and can fit within
     * the max_ops_outstanding limit. */
    .min_ops_outstanding = 32,		//XXXX TUNE

    /* Maximum number of aio completion callbacks to apply before returning
     * to the event thread scheduler to check for more urgent work.  The
     * completion handler will reschedule itself to continue working if this
     * limit is reached before executing all pending callbacks. */
    .max_ops_per_dispatch = 64,		//XXXX TUNE
};

#define VDISK_AIO_MAXIOV MTE_AIO_MAXIOV

typedef struct vdisk_aio_op {
    struct scst_cmd	  * cmd;
    struct completion     * op_done;
    struct iovec	    iov[VDISK_AIO_MAXIOV];
    uint8_t		    aio_private[0];
} vdisk_aio_op_t;

static aio_service_handle_t AIOS;
static struct kmem_cache * aio_op_cache;

static void
init_scst_vdisk_aio(void)
{
    /* Establish AIO service */
    assert(!AIOS);
    AIOS = MTE_aio_service_get();
    aio_service_init(AIOS, &aios_cfg);

    /* Make a cache of per-aio_op allocs with space for iovec array and aio_op private space */
    assert_eq(aio_op_cache, NULL);
    aio_op_cache = kmem_cache_create(
			"aio_op_cache",
			sizeof(struct vdisk_aio_op) + AIOS->op_private_bytes,
			0,		/* use default alignment */
			IGNORED,	/* gfp */
			IGNORED);	/* constructer */
}

static void
exit_scst_vdisk_aio(void)
{
    aio_service_fini(AIOS);
    MTE_aio_service_put(AIOS);
    AIOS = NULL;

    kmem_cache_destroy(aio_op_cache);
    aio_op_cache = NULL;
}

/* Calls vdisk_attach_tgt() and then sets up an aio instance */
static int
vdisk_aio_attach_tgt(struct scst_tgt_dev *tgt_dev)
{
    TRACE_ENTRY();

    int ret = vdisk_attach_tgt(tgt_dev);

    if (ret == E_OK) {
	struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
	if (virt_dev->blockio && !virt_dev->aio_private) {
	    size_t size;
	    virt_dev->aio_private = aio_fopen(AIOS, virt_dev->fd->fd, &size, virt_dev->filename);
	    sys_notice("vdisk_aio_attach_tgt: %s size=%ld",
		       virt_dev->name, virt_dev->file_size);
	    expect_eq(size, virt_dev->file_size, "file=%s", virt_dev->filename);
	}
    }

    TRACE_EXIT();
    return ret;
}

/* Does what vdisk_detach_tgt() does, and also frees the aio instance */
static void
vdisk_aio_detach_tgt(struct scst_tgt_dev *tgt_dev)
{
    struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
    TRACE_ENTRY();
    lockdep_assert_held(&scst_mutex);
    assert(virt_dev->blockio);

    if (--virt_dev->tgt_dev_cnt == 0) {
	string_t str = aio_fmt((struct aio_handle*)virt_dev->aio_private);
	sys_notice("vdisk_aio_detach_tgt: %s\n\t%s", virt_dev->name, str);
	vfree(str);

	aio_close((struct aio_handle*)virt_dev->aio_private);   /* closes the aio but not the file descriptor */
	virt_dev->aio_private = NULL;
	vdisk_close_fd(virt_dev);
    }

    TRACE_EXIT();
}

static inline void
aio_endio(struct scst_blockio_work * blockio_work, bool is_write, errno_t error)
{
    if (unlikely(error != 0)) {
	unsigned long flags;

	PRINT_ERROR_RATELIMITED(
		"AIO for cmd %p finished with error %d",
		blockio_work->cmd, error);

	/* //XXX Lock needed in SCST_USERMODE ?
	 * To protect from several bios finishing simultaneously +
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

    return;
}

static void
aio_readv_done(void * v_work, uintptr_t u_sys_aio_op, errno_t err)
{
    uint8_t * sys_aio_op = (void *)u_sys_aio_op;
    struct vdisk_aio_op * op =
	    (void *)container_of(sys_aio_op, struct vdisk_aio_op, aio_private[0]);
    struct scst_blockio_work * blockio_work = v_work;

    kmem_cache_free(aio_op_cache, op);
    aio_endio(blockio_work, false/*!is_write*/, err);
}

static void
aio_writev_done(void * v_work, uintptr_t u_sys_aio_op, errno_t err)
{
    uint8_t * sys_aio_op = (void *)u_sys_aio_op;
    struct vdisk_aio_op * op =
	    (void *)container_of(sys_aio_op, struct vdisk_aio_op, aio_private[0]);
    struct scst_blockio_work * blockio_work = v_work;

    kmem_cache_free(aio_op_cache, op);
    aio_endio(blockio_work, true/*is_write*/, err);
}

static void
blockio_exec_rw(struct vdisk_cmd_params *p, bool is_write, bool fua)
{
    struct scst_cmd *cmd = p->cmd;
    gfp_t gfp_mask = cmd->cmd_gfp_mask;

    TRACE_ENTRY();

    struct scst_device *dev = cmd->dev;
    struct scst_vdisk_dev *virt_dev = dev->dh_priv;
    WARN_ON(virt_dev->nullio);
    bool dif = virt_dev->blk_integrity &&
	       (scst_get_dif_action(scst_get_dev_dif_actions(cmd->cmd_dif_actions))
							    != SCST_DIF_ACTION_NONE);
    WARN_ONCE(dif, "XXX No DIF support for AIO");
    WARN_ONCE(fua, "XXX No FUA support for AIO");

    uint8_t * buf;
    size_t length = scst_get_buf_first(cmd, &buf);	/* first segment of I/O buffer */

    if (WARN_ONCE((length % 512) != 0 || ((uintptr_t)buf % 512) != 0,
		  "Refused aio with invalid length %d and/or address %p.\n",
		  length, buf)) {
	scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
	goto put_out;
    }

    {
	struct scst_blockio_work * blockio_work =
			    kmem_cache_alloc(blockio_work_cachep, gfp_mask);
	blockio_work->cmd = cmd;
	/* Start with extra ref to block completion until we are done with the submit(s) */
	atomic_set(&blockio_work->bios_inflight, 1);

	u64 seekpos = scst_cmd_get_lba(cmd) << dev->block_shift;
	struct vdisk_aio_op * op = NULL;
	size_t aio_op_len = 0;
	uint32_t niov = 0;

	/* Translate the segments of the receive buffer into iov entries,
	 * coalescing adjacent buffer segments -- when we have accumulated the
	 * maximum number of entries, or we have exhausted the list of receive
	 * buffer segments, submit another op.
	 */
	while (length > 0) {	/* Process (another) receive buffer segment */
	    if (!op) {
		/* Allocate (another) op */
		op = kmem_cache_alloc(aio_op_cache, gfp_mask);
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

		atomic_inc(&blockio_work->bios_inflight);

		/* Pass the request to the aio service implementor */
		if (is_write) {
		    aio_writev((struct aio_handle*)virt_dev->aio_private,
				&op->aio_private,
				aio_writev_done, blockio_work,
				seekpos, aio_op_len, niov, op->iov);
		} else {
		    aio_readv((struct aio_handle*)virt_dev->aio_private,
				&op->aio_private,
				aio_readv_done, blockio_work,
				seekpos, aio_op_len, niov, op->iov);
		}

		seekpos += aio_op_len;
		op = NULL;
	    }
	}

	blockio_check_finish(blockio_work); /* release extra ref we took on bios_inflight */
    }

out:
    TRACE_EXIT();
    return;

put_out:
    scst_put_buf(cmd, buf);
    cmd->completed = 1;
    cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, SCST_CONTEXT_SAME);
    goto out;
}

static void
aio_fsync_done(void * v_op, uintptr_t u_sys_aio_op, errno_t err)
{
    struct vdisk_aio_op * op = v_op;
    assert_eq(u_sys_aio_op, &op->aio_private);
    struct scst_cmd * cmd = op->cmd;

    TRACE_ENTRY();

    if (unlikely(err != 0)) {
	PRINT_ERROR("FLUSH aio failed: %d (cmd %p)", err, cmd);
	if (cmd)
	    scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_write_error));
    }

    if (cmd) {
	cmd->completed = 1;
	cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT, scst_estimate_context());
    }

    if (op->op_done) complete(op->op_done);
    kmem_cache_free(aio_op_cache, op);

    TRACE_EXIT();
}

static int
vdisk_fsync_blockio(loff_t loff,
		    loff_t len, struct scst_device *dev, gfp_t gfp_flags,
		    struct scst_cmd *cmd, bool async)
{
	int res = E_OK;
	struct scst_vdisk_dev *virt_dev = dev->dh_priv;

	TRACE_ENTRY();
	EXTRACHECKS_BUG_ON(!virt_dev->blockio);
	WARN_ONCE(virt_dev->dif_fd != NULL, "XXX No DIF support for AIO");
	/** !!! CAUTION !!!: cmd can be NULL here!  **/

	DECLARE_COMPLETION_ONSTACK(completion);

	/* For the aio private space */
	struct vdisk_aio_op * op = kmem_cache_alloc(aio_op_cache, IGNORED);
	op->cmd = cmd;
	if (!async) op->op_done = &completion;

	res = aio_sync((struct aio_handle*)virt_dev->aio_private, &op->aio_private, aio_fsync_done, op);
					    /*** op may be gone now ***/

	//XXX Is this the intended semantic for async vs. non-async ?
	if (!async) {
	    wait_for_completion(&completion);
	}

	TRACE_EXIT_RES(res);
	return res;
}

#endif /* !SCST_USERMODE_CEPH_RBD */
#endif /* SCST_USERMODE_AIO */
#endif /* SCST_USERMODE */
