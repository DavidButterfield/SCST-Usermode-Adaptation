/* ram.c -- ramdisk driver for tcmu-runner or scstu_tcmu
 * Copyright 2017 David A. Butterfield
 -------------------------------------------------------------------------------
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
 -------------------------------------------------------------------------------
 *
 * This backstore handler does mmap(2) of a backing file or anonymous memory
 * and simply copies to/from the mmap for Write/Read.  Flush does msync(2).
 * Config string should be the pathname of the backing file, or "/@" to use an
 * anonymous mmap.
 *
 * Backing files get msync(2) at close time and persist across sessions.
 * Data in anonymous mmaps is discarded at close time.
 * Data can page to swapspace by default; mlock(2) enabled by config flag.
 *
 * XXX Notes areas in need of attention.
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
#ifndef MLOCK_ONFAULT	    //XXX header file issues
#define MLOCK_ONFAULT 0x01
#define mlock2(addr, len, flags) syscall(__NR_mlock2, (addr), (len), (flags))
#endif

#include "tcmu-runner.h"
#include "libtcmu.h"

typedef struct tcmu_ram {
	void	      *	ram;
	size_t		size;
	unsigned int	block_size;
	int		fd;	    /* when backing file (not anonymous) */
} * state_t;

/* Return true if the mmap memory should be locked */
static inline bool do_mlock(struct tcmu_device *td)
{
	return false;	    //XXX Needs a config switch
}

/* XXX Would it go faster by scheduling op->done() onto a different thread?
 *     Maybe schedule both the iovec copy and op->done() onto a thread?
 *     Maybe only do it on Read?
 */

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

	if (msync(s->ram, s->size, MS_SYNC) < 0) {
		int err = errno;
		tcmu_dev_warn(td, "%s (%s): close cannot msync (%d -- %s)\n",
			      tcmu_get_dev_cfgstring(td),
			      err, strerror(-err));
	}

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
	//XXX kinda hacky, but I don't know how it's supposed to be done
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
	// mmap_flags |= MAP_HUGETLB;	//XXX probably a big perf win
					//    but needs special setup?
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

	/* XXX needs to be fixed so this never happens */
	/* (I think that already should be true under a real tcmu-runner) */
	if (size == 0)
		size = 4*1024*1024*1024l;   //XXX Ugh -- default 4 GB RAMdisk

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

	if (do_mlock(td)) {
		if (mlock2(ram, size, MLOCK_ONFAULT) < 0) {
			err = -errno;
			tcmu_dev_warn(td, "%s: mlock (%d -- %s)\n",
					  config, err, strerror(-err));
		}
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
	"or \"/@\" for anonymous memory (non-persistent after close)\n";

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
