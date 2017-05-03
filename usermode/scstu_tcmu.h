/* scstu_tcmu.h
 * Shim to run tcmu-runner plugins under Usermode SCST
 * Copyright 2017 David A. Butterfield
 */
#ifndef SCSTU_TCMU_H
#define SCSTU_TCMU_H
#include "scsi_defs.h"

#define MAX_FAST_IOV		    16	    //XXX TUNE
typedef int sam_stat_t;		    /* SAM status type */

/* These compatibility symbols are named as expected by tcmu-runner plugins */

#define tcmu_err(fmtargs...)	    sys_error(fmtargs)
#define tcmu_warn(fmtargs...)	    sys_warning(fmtargs)
#define tcmu_info(fmtargs...)	    sys_notice(fmtargs)
#define tcmu_dbg(fmtargs...)	    trace(fmtargs)

#define tcmu_dev_err(dev, fmt...)   _tcmu_dev_err((dev), ""fmt)
#define _tcmu_dev_err(dev, fmt, args...) tcmu_err("%s:"fmt, tcmu_get_dev_name(dev), ##args)
#define tcmu_dev_warn(dev, fmt...)   _tcmu_dev_warn((dev), ""fmt)
#define _tcmu_dev_warn(dev, fmt, args...) tcmu_warn("%s:"fmt, tcmu_get_dev_name(dev), ##args)
#define tcmu_dev_info(dev, fmt...)   _tcmu_dev_info((dev), ""fmt)
#define _tcmu_dev_info(dev, fmt, args...) tcmu_info("%s:"fmt, tcmu_get_dev_name(dev), ##args)
#define tcmu_dev_dbg(dev, fmt...)   _tcmu_dev_dbg((dev), ""fmt)
#define _tcmu_dev_dbg(dev, fmt, args...) tcmu_dbg("%s:"fmt, tcmu_get_dev_name(dev), ##args)

#define SENSE_BUFFERSIZE	    96
#define TCMU_NOT_HANDLED	    (-1)
#define TCMU_ASYNC_HANDLED	    (-2)

struct tcmu_device;
struct tcmulib_cmd;
struct tgt_port_grp;

extern char	  * tcmu_get_dev_name(struct tcmu_device *dev);
extern char	  * tcmu_get_dev_cfgstring(struct tcmu_device *dev);
extern int	    tcmu_get_attribute(struct tcmu_device *dev, string_t);
extern sam_stat_t   tcmu_set_sense_data(uint8_t *sense_buf, uint8_t key, uint16_t asc_ascq, uint32_t *info);
extern long long    tcmu_get_device_size(struct tcmu_device *dev);
extern void	    tcmu_set_dev_block_size(struct tcmu_device *dev, uint32_t block_size);
extern uint32_t	    tcmu_get_dev_block_size(struct tcmu_device *dev);
extern void	    tcmu_set_dev_num_lbas(struct tcmu_device *dev, uint64_t num_lbas);
extern uint64_t	    tcmu_get_dev_num_lbas(struct tcmu_device *dev);
extern void	    tcmu_set_dev_private(struct tcmu_device *dev, void *priv);
// extern void	  * tcmu_get_dev_private(struct tcmu_device *dev);
/* Faster access to handler private data */
#define tcmu_get_dev_private(tmcu_dev) (*(void **)tmcu_dev)

typedef sam_stat_t (*rw_fn_t)(struct tcmu_device *, struct tcmulib_cmd *, struct iovec *, size_t niov, size_t nbytes, off_t);
typedef int (*flush_fn_t)(struct tcmu_device *, struct tcmulib_cmd *);
typedef void (*cmd_done_t)(struct tcmu_device *, struct tcmulib_cmd *, sam_stat_t);

struct tcmulib_cmd {
    struct tcmu_device	      * tcmu_dev;
    size_t			iov_cnt;
    struct iovec	      *	iovec;
    size_t			len;		/* read/write bytes */
    cmd_done_t			done;		/* completion handler */
    struct scst_cmd	      * scst_cmd;
    struct scst_blockio_work  * blockio_work;   /* read and write */
    struct completion         * sync_done;	/* for synchronous flush */
    struct iovec		iov_space[MAX_FAST_IOV];
    uint8_t			sense_buf[SENSE_BUFFERSIZE];
};

/* Exported by the plugin through handler_init/tcmur_register_handler */
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
	     /* BELOW ARE NOT USED AND NEVER CALLED */
    sam_stat_t		     (* handle_cmd)(struct tcmu_device *dev, struct tcmulib_cmd *cmd);
    sam_stat_t		     (* transition_state)(struct tcmu_device *dev, struct tgt_port_grp *group,
						  uint8_t new_state, uint8_t *sense);
    int			     (* report_state)(struct tcmu_device *dev, struct tgt_port_grp *group);
};

extern int tcmur_register_handler(struct tcmur_handler *handler);
extern bool tcmur_unregister_handler(struct tcmur_handler *handler);

/* iovec ops */
extern size_t	    tcmu_memcpy_from_iovec(void * buf, size_t len, struct iovec *iov, size_t niov);
extern size_t	    tcmu_memcpy_into_iovec(struct iovec * iov, size_t niov, void * buf, size_t len);
extern off_t	    tcmu_compare_with_iovec(void *mem, struct iovec *iovec, size_t size);
extern size_t	    tcmu_iovec_length(struct iovec *iovec, size_t iov_cnt);
extern void	    tcmu_zero_iovec(struct iovec *iovec, size_t iov_cnt);
extern void	    tcmu_seek_in_iovec(struct iovec *iovec, size_t count);

extern int handler_init(void);	/* Plugin provides this symbol */

#endif	/* SCSTU_TCMU_H */
