/* bio_tcmu.c
 * Shim to run tcmu-runner handlers under a Usermode Compatibility build
 * Copyright 2017-2019 David A. Butterfield
 *
 * Supports connection of a single tcmu-runner handler plugin.
 * This supports Read/Write/Flush only -- the handler will receive NO callbacks to handle_cmd()
 */
#define BIO_TCMU_TIMING 0	/* XXX move to Makefile */

#if BIO_TCMU_TIMING
#include <sys/time.h>
#include <sys/resource.h>
#endif

#include "usermode_lib.h"

#include "bio_tcmu.h"

#define LOGID "bio_tcmu"
#define trace_tcmu(fmtargs...)	sys_notice("TCMU: "fmtargs)

#if 0
#define TRACE_ENTRY()	    trace_tcmu("ENTER %s", __func__)
#define TRACE_EXIT()	    trace_tcmu("EXIT %s", __func__)
#define TRACE_EXIT_RES(res) trace_tcmu("EXIT %s returning %d", __func__, (res))
#else
#define TRACE_ENTRY()	    /* */
#define TRACE_EXIT()	    /* */
#define TRACE_EXIT_RES(res) /* */
#endif

/* XXX Only one handler type can be registered at a time for now */
static struct tcmur_handler * bio_tcmu_handler;

static struct kmem_cache * op_cache;

static int bio_tcmu_major = 3;	//XXXXX

#define BIO_TCMU_MAX_MINORS 256	//XXX
struct tcmu_device * bio_tcmu_minors[BIO_TCMU_MAX_MINORS];

#ifndef bio_op
#define bio_op(bio)	    ((bio)->bi_rw & 0xff)
#endif

#define bdev_size(bdev)	    ((bdev)->bd_disk->part0.nr_sects * 512)
#define block_size(bdev)    ((bdev)->bd_block_size)

/******** Implementation for tcmu-runner handler API ********/

#define SENSE_BUF_USED 18u	//XXX
#define MISCOMPARE 0x0e
#define NOT_READY 0x02

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

/* This can be called by a handler to query our client about the device size */
ssize_t
tcmu_get_device_size(struct tcmu_device * tcmu_dev)
{
    struct bdev_tcmu * bdev_tcmu = tcmu_dev->bdev_tcmu;
    return bdev_size(bdev_tcmu->bdev);
}

errno_t
tcmur_register_handler(struct tcmur_handler * handler)
{
    TRACE_ENTRY();

    if (bio_tcmu_handler == handler) {
	assert(handler->registered);
	return -EEXIST;
    }
    if (handler->registered) {
	return -EBADFD;	    /* messed-up state */
    }
    if (bio_tcmu_handler != NULL) {
	return -EBUSY;
    }

    handler->registered = true;
    bio_tcmu_handler = handler;

    TRACE_EXIT();
    return E_OK;
}

bool
tcmur_unregister_handler(struct tcmur_handler * handler)
{
    TRACE_ENTRY();

    if (handler != bio_tcmu_handler) {
	sys_warning("unregister nonexistent handler %s", handler->name);
	if (bio_tcmu_handler)
	    sys_warning("registered handler is %s", bio_tcmu_handler->name);
	return false;
    }
    if (!handler->registered) {
	sys_warning("unregister unregistered handler %s", handler->name);
    }

    handler->registered = false;
    bio_tcmu_handler = NULL;

    TRACE_EXIT();
    return true;
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
    sys_thread = sys_thread_alloc((void *)"bio_tcmu", "bio_tcmu", (void *)vstrdup(name));
    current = UMC_current_alloc();
    UMC_current_init(current, sys_thread, (void *)"bio_tcmu", "bio_tcmu", vstrdup(name));
}

/* Keep this function inline and fast */
static inline void
thread_assimilate(void)
{
    if (!current) _thread_assimilate();
}

/******************************************************************************/
/* Track time spent in OP requests and completion callbacks -- keep these inline and fast */

static inline void
bio_call_begin(struct tcmu_device * td, struct timeval * u, struct timeval * s)
{
#if BIO_TCMU_TIMING
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
bio_reqcall_end(struct tcmu_device * td, struct timeval * u, struct timeval * s)
{
#if BIO_TCMU_TIMING
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
bio_rspcall_end(struct tcmu_device * td, struct timeval * u, struct timeval * s)
{
#if BIO_TCMU_TIMING
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
 * spent in the client during Responses.
 */
static void
bio_tcmu_device_stat_dump(struct tcmu_device * td)
{
#if BIO_TCMU_TIMING
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
    /* Share of Response thread's usr/sys time spent in the client callback */
    uint32_t rsp_u_pct = PCT(rsp_utime, tot_u_rsp);
    uint32_t rsp_s_pct = PCT(rsp_stime, tot_s_rsp);

    /* Time per op spent in handler during Request (in units of 10ns) */
    uint32_t req_u_per = PCT(req_utime, td->nreq);
    uint32_t req_s_per = PCT(req_stime, td->nreq);
    /* Time per op spent in the client during Response */
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

/******************************************************************************/

static inline void
tcmu_bio_endio(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat, bool is_write)
{
    struct bio * bio = op->bio;
    thread_assimilate();

    if (unlikely(sam_stat != SAM_STAT_GOOD))
	bio->bi_error = -EIO;
    else
	bio->bi_flags |= 1<<BIO_UPTODATE;

    bio_endio(bio, bio->bi_error);

    if (op->iovec && op->iovec != op->iov_space)
	vfree(op->iovec);
    kmem_cache_free(op_cache, op);
}

static void
tcmu_bio_readv_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    struct timeval u, s;
    TRACE_ENTRY();

    bio_call_begin(tcmu_dev, &u, &s);
    tcmu_bio_endio(tcmu_dev, op, sam_stat, false);
    bio_rspcall_end(tcmu_dev, &u, &s);

    TRACE_EXIT();
}

static void
tcmu_bio_writev_done(struct tcmu_device * tcmu_dev, struct tcmulib_cmd * op, sam_stat_t sam_stat)
{
    TRACE_ENTRY();

    struct timeval u, s;
    bio_call_begin(tcmu_dev, &u, &s);
    tcmu_bio_endio(tcmu_dev, op, sam_stat, true);
    bio_rspcall_end(tcmu_dev, &u, &s);

    TRACE_EXIT();
}

static errno_t
tcmu_make_request(struct request_queue *rq_unused, struct bio * bio)
{
    int ret = E_OK;
    bool is_write = op_is_write(bio_op(bio));
    // bool fua = op_is_flush(bio_op(bio));    //XXX add fua support
    struct tcmulib_cmd * op = NULL;

    struct gendisk * disk = bio->bi_bdev->bd_disk;
    struct bdev_tcmu * tcmu_bdev = disk->private_data;
    struct tcmu_device * tcmu_dev = tcmu_bdev->tcmu_dev;

    TRACE_ENTRY();
    assert(tcmu_dev);
    assert(tcmu_dev->handler);
    assert(tcmu_dev->handler->registered);

    uint64_t seekpos = bio->bi_sector << 9;

    op = kmem_cache_zalloc(op_cache, IGNORED);
    assert(op);
    op->bio = bio;

    uint32_t niov = bio->bi_vcnt;
    if (niov <= ARRAY_SIZE(op->iov_space))
	op->iovec = op->iov_space;
    else
	op->iovec = vzalloc(niov * sizeof(struct iovec));

    uint32_t iovn = 0;
    size_t aio_op_len = 0;

    /* Translate the segments of the (scattered) I/O buffer into iovec entries,
     * coalescing adjacent buffer segments.  (It is OK that coalescing means we
     * might not use all of the iovec array)
     */
    while (bio->bi_idx < bio->bi_vcnt) {
	size_t seglen = bio->bi_io_vec[bio->bi_idx].bv_len;	    /* get next sg segment */
	uint8_t * segaddr = bio->bi_io_vec[bio->bi_idx].bv_page->vaddr
				+ bio->bi_io_vec[bio->bi_idx].bv_offset;

	if (iovn > 0 && segaddr == op->iovec[iovn-1].iov_base + op->iovec[iovn-1].iov_len) {
	    op->iovec[iovn-1].iov_len += seglen;    /* coalesce with previous entry */
	} else {
	    assert_lt(iovn, niov);
	    op->iovec[iovn].iov_base = segaddr;	    /* fill in a new entry */
	    op->iovec[iovn].iov_len = seglen;
	    ++iovn;
	}
	aio_op_len += seglen;
	++bio->bi_idx;
    }

    expect_eq(aio_op_len, bio->bi_size);
    expect_eq(aio_op_len % 512, 0);

    op->iov_cnt = iovn;		    /* number of iovec elements we filled in */
    op->len = aio_op_len;	    /* I/O bytes */
    op->tcmu_dev = tcmu_dev;

#if 0
    tcmu_dev_info(tcmu_dev, "%s %lu bytes at sector %lu",
			is_write?"WRITE":" READ", aio_op_len, bio->bi_sector);
#endif

    /* Submit the command to the handler */
    sam_stat_t sam_stat;
    struct timeval u, s;
    if (is_write) {
	op->done = tcmu_bio_writev_done;
	bio_call_begin(tcmu_dev, &u, &s);
	sam_stat = tcmu_dev->handler->write(op->tcmu_dev, op, op->iovec, op->iov_cnt, op->len, seekpos);
	bio_reqcall_end(tcmu_dev, &u, &s);
	if (sam_stat != SAM_STAT_GOOD)
	    goto out_finish;
    } else {
	op->done = tcmu_bio_readv_done;
	bio_call_begin(tcmu_dev, &u, &s);
	sam_stat = tcmu_dev->handler->read(op->tcmu_dev, op, op->iovec, op->iov_cnt, op->len, seekpos);
	bio_reqcall_end(tcmu_dev, &u, &s);
	if (sam_stat != SAM_STAT_GOOD)
	    goto out_finish;
    }

out:
    TRACE_EXIT_RES(ret);
    return ret;

out_finish:
    bio->bi_error = -EIO;
    bio_endio(bio, bio->bi_error);
    ret = -EIO;	    //XXX ?
    goto out;
}

/******************************************************************************/

static error_t
bio_tcmu_open(struct block_device * bdev, fmode_t mode)
{
    TRACE_ENTRY();
    TRACE_EXIT();
    return E_OK;
}

static void
bio_tcmu_release(struct gendisk * disk, fmode_t mode)
{
    TRACE_ENTRY();
    TRACE_EXIT();
}

struct block_device_operations bio_tcmu_fops = {
    .open = bio_tcmu_open,
    .release = bio_tcmu_release
};

/* Create a block disk device using TCMU backing storage */
/* cfg is a config string for the underlying tcmu handler */
static errno_t
bio_tcmu_create(int minor, const char * cfg)
{
    errno_t err;
    size_t dev_size;

    struct bdev_tcmu * tcmu_bdev;
    struct gendisk * disk;
    struct device * dev;
    struct block_device * bdev;
    struct tcmu_device * tcmu_dev;

    size_t size;
    bool is_rdonly;

    TRACE_ENTRY();

    char name[sizeof(disk->disk_name)];
    memset(name, 0, sizeof(name));
    snprintf(name, sizeof(name), "tcmu%03u", minor);

    if (bio_tcmu_minors[minor]) {
	err = -EBUSY;
	goto out;
    }

    if (!cfg || !strlen(cfg)) {
	tcmu_err("%s: empty cfg string\n", name);
	err = -EINVAL;
	goto out;
    }

    if (strlen(cfg) >= sizeof(tcmu_dev->cfgstring)) {
	tcmu_err("%s: cfg string too long (%u/%u): '%s'\n",
		 name, strlen(cfg), sizeof(tcmu_dev->cfgstring), cfg);
	err = -EINVAL;
	goto out;
    }

    tcmu_bdev = record_alloc(tcmu_bdev);

    disk = alloc_disk(0/*IGNORED*/);
    disk->fops = &bio_tcmu_fops;
    disk->major = bio_tcmu_major;
    disk->first_minor = minor;
    memcpy(disk->disk_name, name, sizeof(disk->disk_name));
    disk->private_data = tcmu_bdev;

    disk->queue = blk_alloc_queue(IGNORED);
    disk->queue->make_request_fn = tcmu_make_request;
    disk->queue->queuedata = tcmu_bdev;

    add_disk(disk);		/* sets dev->devt */

    dev = disk_to_dev(disk);
    bdev = bdget(dev->devt);	/* must be after add_disk */
    bdev->bd_contains = bdev;
    bdev->bd_disk = disk;

    dev->this_bdev = bdev;

    /* Create tcmu device */
    tcmu_dev = record_alloc(tcmu_dev);
    tcmu_dev->handler = bio_tcmu_handler;
    strlcpy(tcmu_dev->dev_name, disk->disk_name, sizeof(tcmu_dev->dev_name));

    strlcpy(tcmu_dev->cfgstring_orig, cfg,
	    sizeof(tcmu_dev->cfgstring_orig));
    memcpy(tcmu_dev->cfgstring, tcmu_dev->cfgstring_orig, sizeof(tcmu_dev->cfgstring));

    tcmu_dev->bdev_tcmu = tcmu_bdev;

    tcmu_bdev->disk = disk;
    tcmu_bdev->bdev = bdev;
    tcmu_bdev->tcmu_dev = tcmu_dev;

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
	err = -EINVAL;
	goto fail_free;
    }

    err = tcmu_dev->handler->open(tcmu_dev);	    /* Call into handler */

    if (err < 0) {
	expect_noerr(err, "%s handler->open(%s)",
			  tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));
	goto fail_free;
    }

    /* handler->open() might corrupt the config string using strtok() */
    memcpy(tcmu_dev->cfgstring, tcmu_dev->cfgstring_orig, sizeof(tcmu_dev->cfgstring));

    is_rdonly = false;	//XXXX

    bdev->bd_block_size = tcmu_dev->block_size;
    bdev->bd_inode->i_blkbits = ilog2(bdev->bd_block_size);

    if (bdev->bd_block_size != 1 << bdev->bd_inode->i_blkbits) {
	tcmu_err("%s: bad block size=%d not a power of two [he says %d\n", name, bdev->bd_block_size, ilog2(bdev->bd_block_size));
	err = -EINVAL;
	goto fail_close;
    }

    if (bdev->bd_block_size < 512) {
	tcmu_err("%s: bad block size=%d\n", name, bdev->bd_block_size);
	err = -EINVAL;
	goto fail_close;
    }

    size = tcmu_dev->num_lbas * bdev->bd_block_size;

    if (size < bdev->bd_block_size) {
	tcmu_err("%s: bad device size=%"PRIu64"\n", name, size);
	err = -EINVAL;
	goto fail_close;
    }

    dev_size = tcmu_get_device_size(tcmu_dev);
    if (dev_size > size) {
	/* client above thinks the storage size is bigger than the handler below thinks */
	sys_warning(LOGID" target %s/%s nblocks=%"PRIu64" * blocksize=%u = %"PRIu64
		         " too small < %"PRIu64,
		    tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev),
		    tcmu_get_dev_num_lbas(tcmu_dev), tcmu_get_dev_block_size(tcmu_dev),
		    tcmu_get_dev_num_lbas(tcmu_dev) * tcmu_get_dev_block_size(tcmu_dev),
		    dev_size);
	err = -EBADFD;	    /* messed-up state */
	goto fail_close;
    }

    bdev->bd_inode->i_size = size;
    set_capacity(disk, size>>9);

    set_disk_ro(disk, is_rdonly);
    bdev->bd_inode->i_mode = S_IFBLK | (is_rdonly ? 0444 : 0666);

    // tcmu_set_dev_max_xfer_len(tcmu_dev, 8*1024*1024);	//XXX

    sys_notice(LOGID" handler %s attach target %s size %"PRIu64"/%"PRIu64" block_size %ld%s",
	       tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev),
	       dev_size, size, bdev->bd_block_size, is_rdonly ? " READONLY" : "READ/WRITE");

    bio_tcmu_minors[minor] = tcmu_dev;

out:
    TRACE_EXIT_RES(err);
    return err;

fail_close:
    tcmu_dev->handler->close(tcmu_dev);

fail_free:
    record_free(tcmu_dev);
    blk_put_queue(disk->queue);
    del_gendisk(disk);	/* frees dev and name */
    bdput(bdev);
    record_free(tcmu_bdev);
    goto out;
}

static errno_t
bio_tcmu_destroy(unsigned int minor)
{
    struct tcmu_device * tcmu_dev = bio_tcmu_minors[minor];
    if (!tcmu_dev)
	return -ENODEV;

    TRACE_ENTRY();

    sys_notice(LOGID" handler %s destroy tgt: %s",
	       tcmu_dev->handler->name, tcmu_get_dev_name(tcmu_dev));
    bio_tcmu_device_stat_dump(tcmu_dev);

    tcmu_dev->handler->close(tcmu_dev);

    bio_tcmu_minors[minor] = NULL;

    struct bdev_tcmu * tcmu_bdev = tcmu_dev->bdev_tcmu;
    record_free(tcmu_dev);
    blk_put_queue(tcmu_bdev->disk->queue);
    del_gendisk(tcmu_bdev->disk);
    bdput(tcmu_bdev->bdev);
    record_free(tcmu_bdev);
    TRACE_EXIT();
    return E_OK;
}

/******************************************************************************/

char * cfgs[] = {
    "/tmp/cfg1",
    "/tmp/cfg2",
    NULL
};

errno_t
tcmu_bio_init(void)
{
    unsigned int minor = 0;
    unsigned int nminor = 0;
    char ** cfgp = cfgs;
    errno_t err = E_OK;
    TRACE_ENTRY();

    assert(!op_cache);
    op_cache = kmem_cache_create(
			"bio_tcmu_op_cache",
			sizeof(struct tcmulib_cmd),
			0,		/* use default alignment */
			IGNORED,	/* gfp */
			IGNORED);	/* constructer */
    assert(op_cache);

    assert(!bio_tcmu_handler);
    err = handler_init();
    if (err) {
	sys_warning("handler_init() returned ERROR %d", err);
	expect_eq(bio_tcmu_handler, NULL);
	bio_tcmu_handler = NULL;	/* just in case */
	kmem_cache_destroy(op_cache);
	op_cache = NULL;
	goto out;
    }
    assert(bio_tcmu_handler);

    while (*cfgp && minor < BIO_TCMU_MAX_MINORS) {
	err = bio_tcmu_create(minor, *cfgp);
	if (err)
	    sys_warning("ERROR %d from bio_tcmu_create(%u, %s)", err, minor, *cfgp);
	else
	    nminor++;
	minor++;
	cfgp++;
    }

    if (*cfgp)
	sys_warning("minor table too small (%d) for %d configs",
		    BIO_TCMU_MAX_MINORS, sizeof(cfgs)/sizeof(cfgs[0]));

    sys_notice("tcmu_bio_init() created %d instances out of %d attempted", nminor, minor);

out:
    TRACE_EXIT_RES(err);
    return err;
}

void
tcmu_bio_exit(void)
{
    unsigned int minor = 0;
    char ** cfgp = cfgs;
    while (*cfgp) {
	error_t err = bio_tcmu_destroy(minor);
	if (err)
	    sys_warning("bio_tcmu_destroy() returned ERROR %d", err);
	cfgp++;
	minor++;
    }

    assert(bio_tcmu_handler);
    assert(op_cache);
    if (bio_tcmu_handler) {
	expect_ne(bio_tcmu_handler->registered, 0);
	if (bio_tcmu_handler->handler_exit) {
	    bio_tcmu_handler->handler_exit();
	    expect_eq(bio_tcmu_handler, NULL);
	}
	bio_tcmu_handler = NULL;
    }
    kmem_cache_destroy(op_cache);
    op_cache = NULL;
}
