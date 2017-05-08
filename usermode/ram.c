/* ram.c -- ramdisk driver for tcmu-runner or scstu_tcmu
 * Author: David Butterfield
 *
 * mmaps a backing file or anonymous memory (config="/" is anon).
 * Backing files get msync(2) at detach and persist across sessions.
 * Data in anonymous mmaps is discarded at detach time.
 * Data can page to swapspace by default; mlock(2) configurable.
 */
#define _GNU_SOURCE 1
#include <sys/types.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <assert.h>

#include <scsi/scsi.h>

#include <sys/mman.h>
#ifndef MLOCK_ONFAULT
#define MLOCK_ONFAULT 0x01
#define mlock2(addr, len, flags) syscall(__NR_mlock2, (addr), (len), (flags))
#endif

#include "tcmu-runner.h"
#include "libtcmu.h"

typedef struct tcmu_ram {
	void	      *	ram;
	size_t		size;
	unsigned int	block_size;
	int		fd;
} * state_t;

static int tcmu_ram_read(struct tcmu_device *td, struct tcmulib_cmd *op,
	      struct iovec *iov, size_t niov, size_t size, off_t seekpos)
{
	state_t s = tcmu_get_dev_private(td);
	int sam_stat = SAM_STAT_GOOD;
	assert(seekpos % s->block_size == 0);
	assert(size % s->block_size == 0);

	if (seekpos < 0 || seekpos + size > s->size)
		sam_stat = tcmu_set_sense_data(op->sense_buf,
				 ILLEGAL_REQUEST, ASC_LBA_OUT_OF_RANGE, NULL);

	tcmu_memcpy_into_iovec(iov, niov, s->ram + seekpos, size);

	op->done(td, op, sam_stat);
	return 0;
}

static int tcmu_ram_write(struct tcmu_device *td, struct tcmulib_cmd *op,
	       struct iovec *iov, size_t niov, size_t size, off_t seekpos)
{
	state_t s = tcmu_get_dev_private(td);
	int sam_stat = SAM_STAT_GOOD;
	assert(seekpos % s->block_size == 0);
	assert(size % s->block_size == 0);

	if (seekpos < 0 || seekpos + size > s->size)
		sam_stat = tcmu_set_sense_data(op->sense_buf,
				 ILLEGAL_REQUEST, ASC_LBA_OUT_OF_RANGE, NULL);

	tcmu_memcpy_from_iovec(s->ram + seekpos, size, iov, niov);

	op->done(td, op, sam_stat);
	return 0;
}

static int tcmu_ram_flush(struct tcmu_device *td, struct tcmulib_cmd *op)
{
	state_t s = tcmu_get_dev_private(td);
	int sam_stat = SAM_STAT_GOOD;

	if (msync(s->ram, s->size, MS_SYNC) < 0) {
		int err = errno;
		tcmu_dev_err(td, "%s (%s): cannot msync (%d -- %s)\n",
			     tcmu_get_dev_cfgstring(td),
			     err, strerror(-err));
		sam_stat = tcmu_set_sense_data(op->sense_buf,
				 MEDIUM_ERROR, ASC_WRITE_ERROR, NULL);
	}

	op->done(td, op, sam_stat);
	return 0;
}

static void tcmu_ram_close(struct tcmu_device *td)
{
	state_t s = tcmu_get_dev_private(td);
	munmap(s->ram, s->size);
	close(s->fd);
	tcmu_set_dev_private(td, NULL);
	free(s);
}

static int tcmu_ram_open(struct tcmu_device * td)
{
	char *config;
	bool anon;
	int err, block_size, mmap_flags, mmap_fd;
	size_t file_size;
	ssize_t size;
	void *ram;
	state_t s;

	config = tcmu_get_dev_cfgstring(td);
	if (!config || config[0] != '/' || (config[1] == '@'
						&& config[2] == '\0')) {
		anon = true;
		tcmu_dev_warn(td, "No backing file configured -- "
			"anonymous memory will be discarded upon close\n");
	} else {
		anon = false;
		tcmu_dev_dbg(td, "%s: tcmu_ram_open config %s\n",
				 config);
	}

	block_size = tcmu_get_attribute(td, "hw_block_size");
	if (block_size <= 0) {
		tcmu_dev_err(td, "unspecified hw_block_size -- "
				 "using 512 Bytes\n");
		block_size = 512;
	}
	tcmu_set_dev_block_size(td, block_size);

	mmap_flags = MAP_SHARED;
	// mmap_flags |= MAP_HUGETLB;	    //XXX
	if (anon) {
		mmap_flags |= MAP_ANONYMOUS;
		mmap_fd = -1;
		file_size = 0;
	} else {
		mmap_fd = open(config, O_RDWR|O_CLOEXEC|O_CREAT, 0600);
		if (mmap_fd < 0) {
			err = -errno;
			tcmu_dev_err(td, "%s: cannot open (%d -- %s)\n",
					 config, err, strerror(-err));
			goto out_fail;
		}
		file_size = lseek(mmap_fd, 0, SEEK_END);
	}

	size = tcmu_get_device_size(td);    /* framework's idea */
	if (size == 0)
		size = file_size;	    /* take size from file */
	if (size == 0)		/* XXX this case needs to not happen */
		size = 4*1024*1024*1024l;   //XXXXXX

	if (size > file_size) {
		tcmu_dev_info(td, "extending backing file size %lld to %lld",
				  file_size, size);
		file_size = size;
	} else if (size < file_size) {
		tcmu_dev_warn(td, "%s space unused: size %lld < file_size %lld",
				  size, file_size);
	}

	assert(size > 0);
	assert(file_size >= size);

	if (mmap_fd >= 0) {
		if (ftruncate(mmap_fd, file_size) < 0) {
			err = -errno;
			tcmu_dev_warn(td, "%s: fallocate (%d -- %s)\n",
					  config, err, strerror(-err));
		}
		if (fallocate(mmap_fd, 0, 0, file_size) < 0) {
			err = -errno;
			tcmu_dev_warn(td, "%s: fallocate (%d -- %s)\n",
					  config, err, strerror(-err));
		}
	}

	tcmu_set_dev_num_lbas(td, size / block_size);

	ram = mmap(NULL, size, PROT_READ|PROT_WRITE, mmap_flags, mmap_fd, 0);
	if (ram == MAP_FAILED) {
		err = -errno;
		tcmu_dev_err(td, "%s: cannot mmap size=%lld (fd=%d) (%d -- %s)\n",
				 config, size, mmap_fd, err, strerror(-err));
		goto out_close;
	}

	//XXX Needs configurability, ineffective without permissions
	if (mlock2(ram, size, MLOCK_ONFAULT) < 0) {
		err = -errno;
		tcmu_dev_warn(td, "%s: mlock (%d -- %s)\n",
				  config, err, strerror(-err));
	}

	s = calloc(1, sizeof(*s));
	if (!s) {
		err = -ENOMEM;
		tcmu_dev_err(td, "%s: cannot allocate state (%d -- %s)\n",
				 config, err, strerror(-err));
		goto out_unmap;
	}
	s->ram = ram;
	s->size = size;
	s->fd = mmap_fd;
	s->block_size = block_size;
	tcmu_set_dev_private(td, s);
	
	tcmu_dev_dbg(td, "config %s, size %lld\n",
			 tcmu_get_dev_cfgstring(td), s->size);
	return 0;

out_unmap:
	munmap(ram, size);
out_close:
	close(mmap_fd);
out_fail:
	return err;
}

static const char tcmu_ram_cfg_desc[] =
	"RAM handler config string is the name of the backing file, "
	"or \"/\" for anonymous memory (non-persistent after detach)\n";

struct tcmur_handler tcmu_ram_handler = {
	.name	       = "RAM handler",
	.subtype       = "ram",
	.cfg_desc      = tcmu_ram_cfg_desc,
	.open	       = tcmu_ram_open,
	.close	       = tcmu_ram_close,
	.read	       = tcmu_ram_read,
	.write	       = tcmu_ram_write,
	.flush	       = tcmu_ram_flush,
};

int handler_init(void)
{
	return tcmur_register_handler(&tcmu_ram_handler);
}
