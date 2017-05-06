/* scstu_tcmu.c
 * Shim to run tcmu-runner handlers under an SCST_USERMODE build
 * Copyright 2017 David A. Butterfield
 *
 * Supports connection of a single tcmu-runner handler plugin.
 * This supports Read/Write/Flush only -- the handler will receive NO callbacks to handle_cmd()
 */
#ifdef SCST_USERMODE
#ifdef SCST_USERMODE_TCMU
#include <sys/time.h>
#include <sys/resource.h>

#define SCSTU_TIMING 1	/* XXX move to Makefile */

#include "../../usermode/scstu_tcmu.h"

#define LOGID "scstu_tcmu"
#define trace_tcmu(fmtargs...)	sys_notice("TRACE: "fmtargs)

static struct kmem_cache * op_cache;

/******** API for tcmu-runner handler ********/

/* This is used by the handler to query scst about the expected block size */
int
tcmu_get_attribute(struct tcmu_device * tcmu_dev, string_t attr_str)
{
    if (!strcmp(attr_str, "hw_block_size")) {
	assert_ge(tcmu_dev->scst_block_size, 512);
	assert_eq(tcmu_dev->scst_block_size % 512, 0);
	return tcmu_dev->scst_block_size;
    }

    sys_warning("Unknown TCMU attribute %s requested for device %s",
		attr_str, tcmu_get_dev_name(tcmu_dev));
    return -ENOENT;
}

/* This is used by the handler to query scst about the expected device size */
ssize_t
tcmu_get_device_size(struct tcmu_device * tcmu_dev)
{
    assert_ge(tcmu_dev->scst_block_size, 512);
    assert_eq(tcmu_dev->scst_block_size % 512, 0);
    return tcmu_dev->scst_nlba * tcmu_dev->scst_block_size;
}

#define SENSE_BUF_USED 18u	//XXX

int
tcmu_set_sense_data(uint8_t * sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t * info)
{
    memset(sense_buf, 0, SENSE_BUF_USED);
    sense_buf[0] = 0x70;		/* current, fixed fmt sense data */
    assert_eq(key&0xf0, 0);
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
    /* This thread was created by the handler on its own -- set its "kernel thread" environment.
     * The thread will deliver into "kernel" code that expects a "current" to be set.
     * Add a '*' to the front of assimilated threads in the command name shown in top(1)
     */
    char name[32];
    int err = pthread_getname_np(pthread_self(), name+1, sizeof(name)-1);
    if (err) strncpy(name, "*tcmu_handler", sizeof(name));
    name[0] = '*';
    name[15] = '\0';
    err = pthread_setname_np(pthread_self(), name);

    /* XXX These structures and their strings are not freed anywhere */
    sys_thread = sys_thread_alloc((void *)"scstu_tcmu", "scstu_tcmu", (void *)vstrdup(name));
    current = UMC_current_alloc();
    UMC_current_init(current, sys_thread, (void *)"scstu_tcmu", "scstu_tcmu", vstrdup(name));
}

/* Keep this function inline and fast */
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

/* Track time spent in OP requests and completion callbacks -- keep these inline and fast */

static inline void
scstu_call_begin(struct tcmu_device * td, struct timeval * u, struct timeval * s)
{
#ifdef SCSTU_TIMING
    struct rusage ru;
    int rc = getrusage(RUSAGE_THREAD, &ru);
    if (likely(rc == 0)) {
	*u = ru.ru_utime;
	*s = ru.ru_stime;
    } else {
	timerclear(u);
	timerclear(s);
    }
#endif
}

static inline void
scstu_reqcall_end(struct tcmu_device * td, struct timeval * u, struct timeval * s)
{
#ifdef SCSTU_TIMING
    struct rusage ru;
    int rc = getrusage(RUSAGE_THREAD, &ru);
    if (unlikely(!td)) return;
    if (likely(rc == 0)) {
	td->last_req_utime = ru.ru_utime;
	td->last_req_stime = ru.ru_stime;
	if (timerisset(u)) {
	    struct timeval delta;
	    assert(timercmp(&ru.ru_utime, u, >=));
	    timersub(&ru.ru_utime, u, &delta);
	    timeradd(&delta, &td->req_utime, &td->req_utime);

	    assert(timercmp(&ru.ru_stime, s, >=));
	    timersub(&ru.ru_stime, s, &delta);
	    timeradd(&delta, &td->req_stime, &td->req_stime);
	    td->nreq++;
	}
    }
#endif
}

static inline void
scstu_rspcall_end(struct tcmu_device * td, struct timeval * u, struct timeval * s)
{
#ifdef SCSTU_TIMING
    struct rusage ru;
    int rc = getrusage(RUSAGE_THREAD, &ru);
    if (unlikely(!td)) return;
    if (likely(rc == 0)) {
	td->last_rsp_utime = ru.ru_utime;
	td->last_rsp_stime = ru.ru_stime;
	if (timerisset(u)) {
	    struct timeval delta;
	    assert(timercmp(&ru.ru_utime, u, >=));
	    timersub(&ru.ru_utime, u, &delta);
	    timeradd(&delta, &td->rsp_utime, &td->rsp_utime);

	    assert(timercmp(&ru.ru_stime, s, >=));
	    timersub(&ru.ru_stime, s, &delta);
	    timeradd(&delta, &td->rsp_stime, &td->rsp_stime);
	    td->nrsp++;
	}
    }
#endif
}

static inline uint32_t
PCT(uint64_t const n, uint64_t const d)
{
    return d ? (100*n + d/2) / d : 0;
}

/* CPU time tracked is time spent in the handler during Requests, and time
 * spent in SCST during Responses.  This can be used to estimate the division
 * of time on Request and Response threads between SCST and our client
 * interface to the backstorage.
 */
static void
scstu_tcmu_device_stat_dump(struct tcmu_device * td)
{
#ifdef SCSTU_TIMING
    uint64_t tot_u_req = 1000000u * td->last_req_utime.tv_sec + td->last_req_utime.tv_usec;
    uint64_t tot_s_req = 1000000u * td->last_req_stime.tv_sec + td->last_req_stime.tv_usec;
    uint64_t tot_u_rsp = 1000000u * td->last_rsp_utime.tv_sec + td->last_rsp_utime.tv_usec;
    uint64_t tot_s_rsp = 1000000u * td->last_rsp_stime.tv_sec + td->last_rsp_stime.tv_usec;

    uint64_t req_utime = 1000000u * td->req_utime.tv_sec + td->req_utime.tv_usec;
    uint64_t req_stime = 1000000u * td->req_stime.tv_sec + td->req_stime.tv_usec;
    uint64_t rsp_utime = 1000000u * td->rsp_utime.tv_sec + td->rsp_utime.tv_usec;
    uint64_t rsp_stime = 1000000u * td->rsp_stime.tv_sec + td->rsp_stime.tv_usec;

    /* Share of Request thread's usr/sys time spent in the handler */
    uint32_t req_u_pct = PCT(req_utime, tot_u_req);
    uint32_t req_s_pct = PCT(req_stime, tot_s_req);
    /* Share of Response thread's usr/sys time spent in the SCST callback */
    uint32_t rsp_u_pct = PCT(rsp_utime, tot_u_rsp);
    uint32_t rsp_s_pct = PCT(rsp_stime, tot_s_rsp);

    /* Time per op spent in handler during Request (in units of 10ns) */
    uint32_t req_u_per = PCT(req_utime, td->nreq);
    uint32_t req_s_per = PCT(req_stime, td->nreq);
    /* Time per op spent in SCST during Response */
    uint32_t rsp_u_per = PCT(rsp_utime, td->nrsp);
    uint32_t rsp_s_per = PCT(rsp_stime, td->nrsp);

    /* Total time per op on Request thread (in units of 10ns) */
    uint32_t treq_u_per = PCT(tot_u_req, td->nreq);
    uint32_t treq_s_per = PCT(tot_s_req, td->nreq);
    /* Total time per op on Response thread */
    uint32_t trsp_u_per = PCT(tot_u_rsp, td->nrsp);
    uint32_t trsp_s_per = PCT(tot_s_rsp, td->nrsp);

    sys_notice(LOGID
	    " device %s (%s) handler %s nreq=%"PRIu64" (microseconds per OP, %% of thread):"
	    " REQ_USR=%u.%02u/%u.%02u (%u%%)  REQ_SYS=%u.%02u/%u.%02u (%u%%)"
	    " RSP_USR=%u.%02u/%u.%02u (%u%%)  RSP_SYS=%u.%02u/%u.%02u (%u%%)",
	    td->dev_name, td->cfgstring_orig, td->handler->name, td->nreq,
	    req_u_per/100, req_u_per%100, treq_u_per/100, treq_u_per%100, req_u_pct,
	    req_s_per/100, req_s_per%100, treq_s_per/100, treq_s_per%100, req_s_pct,
	    rsp_u_per/100, rsp_u_per%100, trsp_u_per/100, trsp_u_per%100, rsp_u_pct,
	    rsp_s_per/100, rsp_s_per%100, trsp_s_per/100, trsp_s_per%100, rsp_s_pct);
#endif
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

static inline struct tcmu_device *
scstu_tcmu_openprep(struct scst_vdisk_dev * virt_dev, struct tcmur_handler * handler,
		    string_t name, string_t cfg)
{
    struct tcmu_device * tcmu_dev;

    if (!cfg) return NULL;
    if (!strlen(cfg)) return NULL;
    if (strlen(cfg) >= sizeof(tcmu_dev->cfgstring)) return NULL;

    tcmu_dev = vzalloc(sizeof(*tcmu_dev));
    tcmu_dev->handler = handler;
    tcmu_dev->virt_dev = virt_dev;
    strlcpy(tcmu_dev->dev_name, name, sizeof(tcmu_dev->dev_name));
    strlcpy(tcmu_dev->cfgstring_orig, cfg, sizeof(tcmu_dev->cfgstring_orig));
    memcpy(tcmu_dev->cfgstring, tcmu_dev->cfgstring_orig, sizeof(tcmu_dev->cfgstring));

    tcmu_dev->scst_block_size = 1ul << virt_dev->blk_shift;
    tcmu_dev->scst_nlba = virt_dev->nblocks;
    /* num_lbas and block_size filled by handler->open() */

    return tcmu_dev;
}

static errno_t
vdisk_aio_attach_tgt(struct scst_tgt_dev * tgt_dev)
{
    errno_t err;
    size_t dev_size;
    struct tcmu_device * tcmu_dev;
    struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
    assert(virt_dev);
    assert(virt_dev->blockio);
    assert_ge(virt_dev->blk_shift, 9);	    /* sector size */
    assert(virt_dev->nblocks);
    assert_eq(virt_dev->file_size, virt_dev->nblocks << virt_dev->blk_shift);

    TRACE_ENTRY();
    lockdep_assert_held(&scst_mutex);

    /* XXX To support multiple handlers, add code here to lookup the handler */
    tcmu_dev = scstu_tcmu_openprep(virt_dev, scstu_tcmu_handler, "scstu_tcmu", virt_dev->filename);
    if (!tcmu_dev) {
	err = EINVAL;
	goto out;
    }

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

    err = tcmu_dev->handler->open(tcmu_dev);	    /* Call into handler */

    /* handler->open() might corrupt the config string using strtok() */
    memcpy(tcmu_dev->cfgstring, tcmu_dev->cfgstring_orig, sizeof(tcmu_dev->cfgstring));

    if (err < 0) {
	expect_noerr(err, "%s handler->open(%s)",
			  tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));
	goto fail_free;
    }

    virt_dev->aio_private = tcmu_dev; 
    virt_dev->tgt_dev_cnt++;

    expect_eq(tcmu_get_dev_num_lbas(tcmu_dev), virt_dev->nblocks);
    expect_eq(tcmu_get_dev_block_size(tcmu_dev), 1ul << virt_dev->blk_shift);
    expect_eq(tcmu_get_device_size(tcmu_dev), virt_dev->file_size);

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
fail_free:
    vfree(tcmu_dev);
    goto out;
}

/* Does what vdisk_detach_tgt() does, and also closes/frees the handler instance */
static void
vdisk_aio_detach_tgt(struct scst_tgt_dev * tgt_dev)
{
    struct scst_vdisk_dev * virt_dev = tgt_dev->dev->dh_priv;
    struct tcmu_device * tcmu_dev = virt_dev->aio_private;
    assert_eq(tcmu_dev->virt_dev, virt_dev);

    TRACE_ENTRY();
    lockdep_assert_held(&scst_mutex);

    if (--virt_dev->tgt_dev_cnt > 0) {
	trace_tcmu(LOGID" handler %s detach target: %s refcount remaining=%d",
	      tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev), virt_dev->tgt_dev_cnt);
	return;
    }

    sys_notice(LOGID" handler %s detach tgt: %s refcount zero -- closing",
	       tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));

    scstu_tcmu_device_stat_dump(tcmu_dev);

    tcmu_dev->handler->close(tcmu_dev);
    virt_dev->aio_private = NULL;
    vfree(tcmu_dev);
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
    thread_assimilate();

    /* See comment in blockio_endio() */
    if (unlikely(sam_stat != SAM_STAT_GOOD)) {
	unsigned long flags;
	spin_lock_irqsave(&vdev_err_lock, flags);

	errno_t err = scst_alloc_sense(op->scst_cmd, IGNORED);
	assert(!err);

	size_t copylen = min_t(int, op->scst_cmd->sense_buflen, SENSE_BUF_USED);
	memcpy(op->scst_cmd->sense, op->sense_buf, copylen);
	op->scst_cmd->sense_valid_len = copylen;

	spin_unlock_irqrestore(&vdev_err_lock, flags);
    }

    aio_finish(op);
}

static void
aio_readv_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    struct timeval u, s;
    scstu_call_begin(tcmu_dev, &u, &s);
    aio_endio(tcmu_dev, op, sam_stat, false);
    scstu_rspcall_end(tcmu_dev, &u, &s);
}

static void
aio_writev_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    struct timeval u, s;
    scstu_call_begin(tcmu_dev, &u, &s);
    aio_endio(tcmu_dev, op, sam_stat, true);
    scstu_rspcall_end(tcmu_dev, &u, &s);
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
    struct timeval u, s;
    if (is_write) {
	op->done = aio_writev_done;
	scstu_call_begin(tcmu_dev, &u, &s);
	sam_stat = tcmu_dev->handler->write(op->tcmu_dev, op, op->iovec, op->iov_cnt, op->len, seekpos);
	scstu_reqcall_end(tcmu_dev, &u, &s);
	if (sam_stat != SAM_STAT_GOOD) goto out_finish;
    } else {
	op->done = aio_readv_done;
	scstu_call_begin(tcmu_dev, &u, &s);
	sam_stat = tcmu_dev->handler->read(op->tcmu_dev, op, op->iovec, op->iov_cnt, op->len, seekpos);
	scstu_reqcall_end(tcmu_dev, &u, &s);
	if (sam_stat != SAM_STAT_GOOD) goto out_finish;
    }

out:
    TRACE_EXIT();
    return;

out_finish:
    aio_endio(tcmu_dev, op, sam_stat, is_write);
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
	    errno_t err = scst_alloc_sense(op->scst_cmd, IGNORED);
	    assert(!err);
	    size_t copylen = min_t(int, op->scst_cmd->sense_buflen, SENSE_BUF_USED);
	    memcpy(op->scst_cmd->sense, op->sense_buf, copylen);
	    op->scst_cmd->sense_valid_len = copylen;
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

/* Return 0 on success with file size in *file_size; otherwise -errno */
static errno_t
vdisk_get_file_size(struct scst_vdisk_dev *virt_dev, loff_t *file_sizep)
{
    const char *filename = virt_dev->filename;
    bool blockio = virt_dev->blockio;
    errno_t err = E_OK;
    struct tcmu_device * tcmu_dev;

    TRACE_ENTRY();
    lockdep_assert_held(&scst_mutex);
    assert(file_sizep);
    assert(blockio);
    assert(filename);
    assert(strlen(filename));

    *file_sizep = 0;

    /* XXX To support multiple handlers, add code here to lookup the handler */
    tcmu_dev = scstu_tcmu_openprep(virt_dev, scstu_tcmu_handler, "scstu_tcmu", filename);
    if (!tcmu_dev) {
	err = EINVAL;
	goto out;
    }

    /* Open the handler so it fills in num_lbas and block_size */
    err = tcmu_dev->handler->open(tcmu_dev);

    /* handler->open() might corrupt the config string using strtok() */
    memcpy(tcmu_dev->cfgstring, tcmu_dev->cfgstring_orig, sizeof(tcmu_dev->cfgstring));

    if (err < 0) {
	expect_noerr(err, "%s handler->open(%s)",
			  tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));
	goto out_free;
    }

    *file_sizep = tcmu_dev->num_lbas * tcmu_dev->block_size;

    tcmu_dev->handler->close(tcmu_dev);

out_free:
    vfree(tcmu_dev);
out:
    trace_tcmu("TCMU device size=%"PRIu64, *file_sizep);
    TRACE_EXIT_RES(err);
    return err;
}

#endif /* SCST_USERMODE_TCMU */
#endif /* SCST_USERMODE */
