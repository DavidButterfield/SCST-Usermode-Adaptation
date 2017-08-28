/* scstu_tcmu.h
 * Shim to run tcmu-runner plugins under Usermode SCST
 * Copyright 2017 David A. Butterfield
 */
#ifndef SCSTU_TCMU_H
#define SCSTU_TCMU_H
#include "scsi_defs.h"

#define MAX_FAST_IOV			    16	    //XXX TUNE
typedef int sam_stat_t;			    /* SAM status type */

/* These compatibility symbols are named as expected by tcmu-runner plugins */

extern int handler_init(void);		    /* Plugin provides this symbol */

#define tcmu_err(fmtargs...)		    sys_error(fmtargs)
#define tcmu_warn(fmtargs...)		    sys_warning(fmtargs)
#define tcmu_info(fmtargs...)		    sys_notice(fmtargs)
#define tcmu_dbg(fmtargs...)		    trace(fmtargs)

#define  tcmu_dev_err(dev, fmt...)	   _tcmu_dev_err((dev), ""fmt)
#define _tcmu_dev_err(dev, fmt, args...)    tcmu_err("%s:"fmt, tcmu_get_dev_name(dev), ##args)
#define  tcmu_dev_warn(dev, fmt...)	   _tcmu_dev_warn((dev), ""fmt)
#define _tcmu_dev_warn(dev, fmt, args...)   tcmu_warn("%s:"fmt, tcmu_get_dev_name(dev), ##args)
#define  tcmu_dev_info(dev, fmt...)	   _tcmu_dev_info((dev), ""fmt)
#define _tcmu_dev_info(dev, fmt, args...)   tcmu_info("%s:"fmt, tcmu_get_dev_name(dev), ##args)
#define  tcmu_dev_dbg(dev, fmt...)	   _tcmu_dev_dbg((dev), ""fmt)
#define _tcmu_dev_dbg(dev, fmt, args...)    tcmu_dbg("%s:"fmt, tcmu_get_dev_name(dev), ##args)

#define tcmu_make_absolute_logfile(buf, nm) snprintf((buf), PATH_MAX, "/var/log/%s", (nm));

#define SENSE_BUFFERSIZE		    96
#define TCMU_NOT_HANDLED		    (-1)
#define TCMU_ASYNC_HANDLED		    (-2)

struct tcmu_device;
struct tcmulib_cmd;
struct tgt_port_grp;

typedef sam_stat_t (*rw_fn_t)(struct tcmu_device *, struct tcmulib_cmd *, struct iovec *, size_t niov, size_t nbytes, off_t);
typedef int (*flush_fn_t)(struct tcmu_device *, struct tcmulib_cmd *);
typedef void (*cmd_done_t)(struct tcmu_device *, struct tcmulib_cmd *, sam_stat_t);

/* State for one Read/Write/Flush operation */
struct tcmulib_cmd {
    struct tcmu_device	      * tcmu_dev;
    size_t			iov_cnt;
    struct iovec	      *	iovec;		/* I/O data buffers */
    size_t			len;		/* read/write bytes */
    cmd_done_t			done;		/* completion handler */
    struct scst_cmd	      * scst_cmd;
    struct scst_blockio_work  * blockio_work;   /* read and write */
    struct completion         * sync_done;	/* for synchronous flush */
    struct iovec		iov_space[MAX_FAST_IOV];
    uint8_t			sense_buf[SENSE_BUFFERSIZE];
};

/* Exported by the tcmur handler through handler_init/tcmur_register_handler */
struct tcmur_handler {
    const char		      * name;		/* handler name */
    const char		      * subtype;	/* handler type */
    const char		      * cfg_desc;	/* config help string */
    void		      * opaque;		/* handler private */
    int				nr_threads;	/* desired number of threads */
    bool			registered;	/* handler is registered */
    rw_fn_t			write;		/* entry points */
    rw_fn_t			read;
    flush_fn_t			flush;
    int		             (* open)(struct tcmu_device *dev);
    void		     (* close)(struct tcmu_device *dev);
    bool		     (* check_config)(const char *cfgstring, char **reason);
    bool		     (* handler_exit)(void);	/* optional */
    /* BELOW ENTRY POINTS ARE NOT USED AND NEVER CALLED */
    void		      * handle_cmd;
    void		      * transition_state;
    void		      * report_state;
    void		      * lock;
    void		      * unlock;
    void		      * has_lock;
};

extern int	    tcmur_register_handler(struct tcmur_handler *handler);
extern bool	    tcmur_unregister_handler(struct tcmur_handler *handler);

/* scstu_tcmu private structure -- handlers should use accessors */
struct tcmu_device {
    void		      * hm_private;		/* owned by handler */
    struct tcmur_handler      * handler;
    struct scst_vdisk_dev     * virt_dev;
    uint64_t			num_lbas;		/* owned by handler */
    uint32_t			block_size;		/* owned by handler */
    uint32_t			max_xfer_len;		/* owned by handler */
    char			dev_name[16];
    char			cfgstring_orig[256];
    char			cfgstring[256];

    struct timeval		req_utime;		/* request CPU time */
    struct timeval		req_stime;		/* accumulated from ops */
    struct timeval		rsp_utime;		/* response CPU time */
    struct timeval		rsp_stime;		/* accumulated from ops */
    uint64_t			nreq;			/* requests to handler */
    uint64_t			nrsp;			/* completions to scst */

    struct timeval		last_req_utime;		/* XXX dodgy */
    struct timeval		last_req_stime;
    struct timeval		last_rsp_utime;
    struct timeval		last_rsp_stime;
};

#define tcmu_set_dev_private(tcmu_dev, priv)		((tcmu_dev)->hm_private = (priv))
#define tcmu_get_dev_private(tcmu_dev)			((tcmu_dev)->hm_private)
#define tcmu_set_dev_num_lbas(tcmu_dev, nlbas)		((tcmu_dev)->num_lbas = (nlbas))
#define tcmu_get_dev_num_lbas(tcmu_dev)			((tcmu_dev)->num_lbas)
#define tcmu_set_dev_block_size(tcmu_dev, bsize)	((tcmu_dev)->block_size = (bsize))
#define tcmu_get_dev_block_size(tcmu_dev)		((tcmu_dev)->block_size)
#define tcmu_set_dev_max_xfer_len(tcmu_dev, len)	((tcmu_dev)->max_xfer_len = (len))
#define tcmu_get_dev_max_xfer_len(tcmu_dev)		((tcmu_dev)->max_xfer_len)
#define tcmu_get_dev_name(tcmu_dev)			((tcmu_dev)->dev_name)
#define tcmu_get_dev_cfgstring(tcmu_dev)		((tcmu_dev)->cfgstring)

extern ssize_t	    tcmu_get_device_size(struct tcmu_device *);
extern int	    tcmu_get_attribute(struct tcmu_device *, string_t);
extern sam_stat_t   tcmu_set_sense_data(uint8_t * sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t * info);

/* Used by earlier versions of rbd.c for RBD without readv/writev ops */
static inline size_t
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
    if (len) tcmu_warn("iovec too small (to satisfy copy len) by %"PRIu64" bytes", len);
    return ret;
}

static inline size_t
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
    if (len) tcmu_warn("iovec too small (to satisfy copy len) by %"PRIu64" bytes", len);
    return ret;
}

/* Return the number of bytes referred to by the iovec array */
static inline size_t
tcmu_iovec_length(struct iovec * iov, size_t niov)
{
    size_t ret = 0;
    while (niov) {
	ret += iov->iov_len;
	iov++;
	niov--;
    }
    return ret;
}

/* Skip over the first nbytes referred to by the iovec array */
static inline void
tcmu_seek_in_iovec(struct iovec * iov, size_t nbytes)
{
    while (nbytes >= iov->iov_len) {
	nbytes -= iov->iov_len;
	iov->iov_len = 0;
	iov++;
    }
    iov->iov_len -= nbytes;
    iov->iov_base += nbytes;
}

#endif	/* SCSTU_TCMU_H */
