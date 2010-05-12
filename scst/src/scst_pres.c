/*
 *  scst_pres.c
 *
 *  Copyright (C) 2009 - 2010 Alexey Obitotskiy <alexeyo1@open-e.com>
 *  Copyright (C) 2009 - 2010 Open-E, Inc.
 *  Copyright (C) 2009 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU General Public License
 *  as published by the Free Software Foundation, version 2
 *  of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/time.h>
#include <linux/ctype.h>
#include <asm/byteorder.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <asm/uaccess.h>
#include <linux/namei.h>
#include <linux/version.h>
#include <asm/unaligned.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#include <linux/mount.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#include <linux/writeback.h>
#endif

#include "scst.h"
#include "scst_const.h"
#include "scst_priv.h"
#include "scst_pres.h"

#define SCST_PR_ROOT_ENTRY	"pr"
#define SCST_PR_FILE_SIGN	0xBBEEEEAAEEBBDD77LLU
#define SCST_PR_FILE_VERSION	1LLU

#define FILE_BUFFER_SIZE	512

#ifndef isblank
#define isblank(c)		((c) == ' ' || (c) == '\t')
#endif

/*
 * Experimental hack to support CONFIG_SCST_ISCSI_SKIP_ISID. ISCSI-SCST sets
 * this variable if CONFIG_SCST_ISCSI_SKIP_ISID defined, then tid_equal()
 * uses it to perform for iSCSI TransportIDs only initiator names comparison
 * ignoring the ISID part.
 */
bool iscsi_tid_name_only = false;
EXPORT_SYMBOL(iscsi_tid_name_only);

static void scst_pr_clear_holder(struct scst_device *dev);

static inline int tid_size(const uint8_t *tid)
{
	sBUG_ON(tid == NULL);

	if ((tid[0] & 0x0f) == SCSI_TRANSPORTID_PROTOCOLID_ISCSI)
		return be16_to_cpu(get_unaligned((__be16 *)&tid[2])) + 4;
	else
		return TID_COMMON_SIZE;
}

/* Secures tid by setting 0 in the last byte of NULL-terminated tid's */
static inline void tid_secure(uint8_t *tid)
{
	if ((tid[0] & 0x0f) == SCSI_TRANSPORTID_PROTOCOLID_ISCSI) {
		int size = tid_size(tid);
		tid[size - 1] = '\0';
	}

	return;
}

/* Returns false if tid's are not equal, true otherwise */
static bool tid_equal(const uint8_t *tid_a, const uint8_t *tid_b)
{
	int len;

	if (tid_a == NULL || tid_b == NULL)
		return false;

	if ((tid_a[0] & 0x0f) != (tid_b[0] & 0x0f)) {
		TRACE_DBG("%s", "Different protocol IDs");
		return false;
	}

	if ((tid_a[0] & 0x0f) == SCSI_TRANSPORTID_PROTOCOLID_ISCSI) {
		const uint8_t tid_a_fmt = tid_a[0] & 0xc0;
		const uint8_t tid_b_fmt = tid_b[0] & 0xc0;
		int tid_a_len, tid_a_max = tid_size(tid_a) - 4;
		int tid_b_len, tid_b_max = tid_size(tid_b) - 4;

		tid_a += 4;
		tid_b += 4;

		if (tid_a_fmt == 0x00)
			tid_a_len = strnlen(tid_a, tid_a_max);
		else if (tid_a_fmt == 0x40) {
			if ((tid_a_fmt != tid_b_fmt) || iscsi_tid_name_only) {
				uint8_t *p = strnchr(tid_a, tid_a_max, ',');
				if (p == NULL)
					goto out_error;
				tid_a_len = p - tid_a;

				sBUG_ON(tid_a_len > tid_a_max);
				sBUG_ON(tid_a_len < 0);
			} else
				tid_a_len = strnlen(tid_a, tid_a_max);
		} else
			goto out_error;

		if (tid_b_fmt == 0x00)
			tid_b_len = strnlen(tid_b, tid_b_max);
		else if (tid_b_fmt == 0x40) {
			if ((tid_a_fmt != tid_b_fmt) || iscsi_tid_name_only) {
				uint8_t *p = strnchr(tid_b, tid_b_max, ',');
				if (p == NULL)
					goto out_error;
				tid_b_len = p - tid_b;

				sBUG_ON(tid_b_len > tid_b_max);
				sBUG_ON(tid_b_len < 0);
			} else
				tid_b_len = strnlen(tid_b, tid_b_max);
		} else
			goto out_error;

		if (tid_a_len != tid_b_len)
			return false;

		len = tid_a_len;
	} else
		len = TID_COMMON_SIZE;

	return (memcmp(tid_a, tid_b, len) == 0);

out_error:
	PRINT_ERROR("%s", "Invalid initiator port transport id");
	return false;
}

static inline void scst_pr_set_holder(struct scst_device *dev,
	struct scst_dev_registrant *holder, uint8_t scope, uint8_t type)
{
	dev->pr_is_set = 1;
	dev->pr_scope = scope;
	dev->pr_type = type;
	if (dev->pr_type != TYPE_EXCLUSIVE_ACCESS_ALL &&
	    dev->pr_type != TYPE_WRITE_EXCLUSIVE_ALL)
		dev->pr_holder = holder;
}

static bool scst_pr_is_holder(struct scst_device *dev,
	struct scst_dev_registrant *reg)
{
	bool res = false;

	TRACE_ENTRY();

	if (!dev->pr_is_set)
		goto out;

	if (dev->pr_type == TYPE_EXCLUSIVE_ACCESS_ALL ||
	    dev->pr_type == TYPE_WRITE_EXCLUSIVE_ALL) {
		res = (reg != NULL);
	} else
		res = (dev->pr_holder == reg);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void scst_pr_dump_registrants(struct scst_device *dev)
{
	TRACE_PR("Dump registration records: device '%s'", dev->virt_name);

	if (list_empty(&dev->dev_registrants_list))
		TRACE_PR("%s", "No records");
	else {
		int i;
		struct scst_dev_registrant *reg;

		i = 0;
		list_for_each_entry(reg, &dev->dev_registrants_list,
					dev_registrants_list_entry) {
			TRACE_PR("[%d] initiator '%s' key '%016llx'", i++,
				debug_transport_id_to_initiator_name(
					reg->transport_id),
				reg->key);
		}
	}

	return;
}

static void scst_pr_dump_reservation(struct scst_device *dev)
{
	TRACE_PR("Dump persistent reservation: device '%s'", dev->virt_name);
	if (dev->pr_is_set) {
		struct scst_dev_registrant *holder = dev->pr_holder;
		if (holder != NULL)
			TRACE_PR("Reservation '%s' key '%016llx' scope %x "
				"type %x",
				holder ? debug_transport_id_to_initiator_name(
						holder->transport_id) : "*",
				holder->key, dev->pr_scope, dev->pr_type);
		else {
			/*
			 * TODO : handle all registrants case
			 */
		}
	} else
		TRACE_PR("%s", "No reservation");

	return;
}

static struct scst_dev_registrant *scst_pr_find_not_used_registrant(
	struct scst_device *dev, const uint8_t *transport_id,
	const uint16_t rel_tgt_id)
{
	struct scst_dev_registrant *reg, *reg_found = NULL;

	TRACE_ENTRY();

	list_for_each_entry(reg, &dev->dev_registrants_list,
				dev_registrants_list_entry) {
		if ((reg->rel_tgt_id == rel_tgt_id) &&
		    tid_equal(reg->transport_id, transport_id) &&
		    (reg->tgt_dev == NULL)) {
			reg_found = reg;
			break;
		}
	}

	TRACE_EXIT_HRES(reg_found);
	return reg_found;
}

static void scst_pr_find_registrants_list_all(struct scst_device *dev,
	struct scst_dev_registrant *exclude_reg, struct list_head *list)
{
	struct scst_dev_registrant *reg;

	TRACE_ENTRY();

	TRACE_PR("Find all registered records except: device '%s' "
		"with exclude reg key '%016llx'",
		dev->virt_name, exclude_reg->key);

	list_for_each_entry(reg, &dev->dev_registrants_list,
				dev_registrants_list_entry) {
		if (reg == exclude_reg)
			continue;
		TRACE_PR("Add registered record to list: "
			"initiator '%s' key '%016llx'",
			debug_transport_id_to_initiator_name(
				reg->transport_id),
			reg->key);
		list_add_tail(&reg->aux_list_entry, list);
	}

	TRACE_EXIT();
	return;
}

static void scst_pr_find_registrants_list_key(struct scst_device *dev,
	uint64_t key, struct list_head *list)
{
	struct scst_dev_registrant *reg;

	TRACE_ENTRY();

	TRACE_PR("Find registered records for: device '%s' with key '%016llx'",
		dev->virt_name, key);

	list_for_each_entry(reg, &dev->dev_registrants_list,
				dev_registrants_list_entry) {
		if (reg->key == key) {
			TRACE_PR("Add registered record to list: "
				"initiator '%s' key '%016llx'",
				debug_transport_id_to_initiator_name(
					reg->transport_id),
				key);
			list_add_tail(&reg->aux_list_entry, list);
		}
	}

	TRACE_EXIT();
	return;
}

static struct scst_tgt_dev *scst_pr_find_tgt_dev_not_registered_first(
	struct scst_device *dev, const uint8_t *transport_id,
	const uint16_t rel_tgt_id, struct scst_tgt_dev *exclude_tgt_dev)
{
	struct scst_tgt_dev *tgt_dev, *tgt_dev_found = NULL;
	struct scst_tgt_dev *tgt_dev_found_reg = NULL;

	TRACE_ENTRY();

	list_for_each_entry(tgt_dev, &dev->dev_tgt_dev_list,
				dev_tgt_dev_list_entry) {
		if ((tgt_dev->sess->tgt->rel_tgt_id == rel_tgt_id) &&
		    tid_equal(tgt_dev->sess->transport_id, transport_id) &&
		    (tgt_dev != exclude_tgt_dev)) {
			if (tgt_dev->registrant != NULL) {
				if (tgt_dev_found_reg == NULL)
					tgt_dev_found_reg = tgt_dev;
			} else {
				tgt_dev_found = tgt_dev;
				break;
			}
		}
	}

	if (tgt_dev_found == NULL)
		tgt_dev_found = tgt_dev_found_reg;

	TRACE_EXIT_HRES(tgt_dev_found);
	return tgt_dev_found;
}

static struct scst_dev_registrant *scst_pr_add_registrant(
	struct scst_device *dev, const uint8_t *transport_id,
	const uint16_t rel_tgt_id, uint64_t key, bool aptpl,
	struct scst_tgt_dev *tgt_dev)
{
	struct scst_dev_registrant *reg = NULL;

	TRACE_ENTRY();

	sBUG_ON(dev == NULL);
	sBUG_ON(transport_id == NULL);

	TRACE_PR("Registering dev %p transport_id %p tgt_dev %p",
		dev, transport_id, tgt_dev);

	reg = kzalloc(sizeof(*reg), GFP_KERNEL);
	if (reg == NULL) {
		PRINT_ERROR("%s", "Unable to allocate registration record");
		goto out;
	}

	reg->transport_id = kzalloc(tid_size(transport_id), GFP_KERNEL);
	if (reg->transport_id == NULL) {
		PRINT_ERROR("%s", "Unable to allocate initiator port "
			"transport id");
		goto out_free;
	}
	memcpy(reg->transport_id, transport_id, tid_size(transport_id));

	reg->rel_tgt_id = rel_tgt_id;
	reg->key = key;
	reg->tgt_dev = tgt_dev;

	dev->pr_aptpl = aptpl;

	if (tgt_dev != NULL)
		tgt_dev->registrant = reg;

	list_add_tail(&reg->dev_registrants_list_entry,
		&dev->dev_registrants_list);

out:
	TRACE_EXIT_HRES((unsigned long)reg);
	return reg;

out_free:
	kfree(reg);
	reg = NULL;
	goto out;
}

static void scst_pr_remove_registrant(struct scst_device *dev,
	struct scst_dev_registrant *reg)
{
	TRACE_ENTRY();

	TRACE_PR("Remove registration record: initiator '%s' key '%016llx'",
		debug_transport_id_to_initiator_name(reg->transport_id),
		reg->key);

	list_del(&reg->dev_registrants_list_entry);

	if (scst_pr_is_holder(dev, reg))
		scst_pr_clear_holder(dev);

	if (reg->tgt_dev)
		reg->tgt_dev->registrant = NULL;

	kfree(reg->transport_id);
	kfree(reg);

	TRACE_EXIT();
	return;
}

static void scst_pr_send_ua_reg(struct scst_device *dev,
	struct scst_dev_registrant *reg,
	int key, int asc, int ascq)
{
	static uint8_t ua[SCST_STANDARD_SENSE_LEN];

	TRACE_ENTRY();

	scst_set_sense(ua, sizeof(ua), dev->d_sense, key, asc, ascq);

	TRACE_PR("Set sense [%x %x %x]: initiator '%s' key "
		"'%016llx'", ua[2], ua[12], ua[13],
		debug_transport_id_to_initiator_name(
			reg->transport_id), reg->key);

	if (reg->tgt_dev)
		scst_check_set_UA(reg->tgt_dev, ua, sizeof(ua), 0);

	TRACE_EXIT();
	return;
}

static void scst_pr_send_ua_all(struct scst_device *dev,
	struct scst_dev_registrant *exclude_reg,
	int key, int asc, int ascq)
{
	struct scst_dev_registrant *reg;

	TRACE_ENTRY();

	list_for_each_entry(reg, &dev->dev_registrants_list,
				dev_registrants_list_entry) {
		if (reg != exclude_reg)
			scst_pr_send_ua_reg(dev, reg, key, asc, ascq);
	}

	TRACE_EXIT();
	return;
}

/*
 * lock sess_list_lock
 * abort tasks for all registrants from list,
 * e.g. for all registered initiator's sessions
 * abort all cmds
 */
static void scst_pr_abort_reg(struct scst_device *dev,
	struct scst_cmd *exclude_cmd, struct scst_dev_registrant *reg)
{
	struct scst_session *sess = exclude_cmd->sess;
	struct scst_cmd *sess_cmd;

	TRACE_ENTRY();

	TRACE_PR("Abort commands for: initiator '%s' key '0x%016llx' "
		"session", debug_transport_id_to_initiator_name(
				reg->transport_id), reg->key);

	if (reg->tgt_dev == NULL) {
		TRACE_PR("Registered record for initiator '%s' key "
			"'0x%016llx' have no attached target device",
			debug_transport_id_to_initiator_name(
				reg->transport_id),
			reg->key);
		goto out;
	}

	spin_lock_irq(&sess->sess_list_lock);
	list_for_each_entry(sess_cmd, &sess->sess_cmd_list,
				sess_cmd_list_entry) {
		if ((sess_cmd->tgt_dev == reg->tgt_dev) &&
		    (sess_cmd != exclude_cmd)) {
			TRACE_PR("Abort cmd '%s'", sess_cmd->op_name);
			/*
			 * ToDo: dev handlers should be notified
			 * somehow about the abortion to abort
			 * faster.
			 */
			scst_abort_cmd(sess_cmd, NULL, 0, 0);
		}
	}
	spin_unlock_irq(&sess->sess_list_lock);
out:
	TRACE_EXIT();
	return;
}

static void scst_pr_clear_holder(struct scst_device *dev)
{
	TRACE_ENTRY();

	WARN_ON(!dev->pr_is_set);

	if (dev->pr_type == TYPE_WRITE_EXCLUSIVE_ALL ||
	    dev->pr_type == TYPE_EXCLUSIVE_ACCESS_ALL) {
		if (list_empty(&dev->dev_registrants_list)) {
			dev->pr_is_set = 0;
			dev->pr_scope = SCOPE_LU;
			dev->pr_type = TYPE_UNSPECIFIED;
		}
	} else {
		dev->pr_is_set = 0;
		dev->pr_scope = SCOPE_LU;
		dev->pr_type = TYPE_UNSPECIFIED;
	}

	dev->pr_holder = NULL;

	TRACE_EXIT();
	return;
}

#ifndef CONFIG_SCST_PROC

/* Abstract vfs_unlink & path_put for different kernel versions */
static inline void scst_pr_vfs_unlink_and_put(struct nameidata *nd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	vfs_unlink(nd->dentry->d_parent->d_inode, nd->dentry);
	dput(nd->dentry);
	mntput(nd->mnt);
#else
	vfs_unlink(nd->path.dentry->d_parent->d_inode,
		nd->path.dentry);
	path_put(&nd->path);
#endif
}

static inline void scst_pr_path_put(struct nameidata *nd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
	dput(nd->dentry);
	mntput(nd->mnt);
#else
	path_put(&nd->path);
#endif
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
static int scst_pr_vfs_fsync(struct file *file, loff_t loff, loff_t len)
{
	int res;

	res = sync_page_range(file->f_dentry->d_inode, file->f_mapping,
			loff, len);
	return res;
}
#endif

static int scst_pr_do_load_device_file(struct scst_device *dev,
	const char *file_name)
{
	int res = 0, rc;
	struct file *file = NULL;
	struct inode *inode;
	char *buf = NULL;
	loff_t file_size, pos, data_size;
	uint64_t sign, version;
	mm_segment_t old_fs;
	uint8_t pr_is_set;
	uint64_t key;
	uint16_t rel_tgt_id;

	TRACE_ENTRY();

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	TRACE_PR("Load persistent file '%s'", file_name);

	file = filp_open(file_name, O_RDONLY, 0);
	if (IS_ERR(file)) {
		res = PTR_ERR(file);
		TRACE_PR("Unable to open file '%s' - error %d", file_name, res);
		goto out;
	}

	inode = file->f_dentry->d_inode;

	if (S_ISREG(inode->i_mode))
		/* Nothing to do */;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		PRINT_ERROR("Invalid file mode 0x%x", inode->i_mode);
		goto out_close;
	}

	file_size = inode->i_size;

	/* Let's limit the file size by some reasonable number */
	if ((file_size == 0) || (file_size >= 15*1024*1024)) {
		PRINT_ERROR("Invalid PR file size %d", (int)file_size);
		res = -EINVAL;
		goto out_close;
	}

	buf = vmalloc(file_size);
	if (buf == NULL) {
		res = -ENOMEM;
		PRINT_ERROR("%s", "Unable to allocate buffer");
		goto out_close;
	}

	pos = 0;
	rc = vfs_read(file, buf, file_size, &pos);
	if (rc != file_size) {
		PRINT_ERROR("Unable to read file '%s' - error %d", file_name,
			rc);
		res = rc;
		goto out_close;
	}

	data_size = 0;
	data_size += sizeof(sign);
	data_size += sizeof(version);
	data_size += sizeof(pr_is_set);
	data_size += sizeof(dev->pr_type);
	data_size += sizeof(dev->pr_scope);

	if (file_size < data_size) {
		res = -EINVAL;
		PRINT_ERROR("Invalid file '%s' - size too small", file_name);
		goto out_close;
	}

	pos = 0;

	sign = get_unaligned((uint64_t *)&buf[pos]);
	if (sign != SCST_PR_FILE_SIGN) {
		res = -EINVAL;
		PRINT_ERROR("Invalid persistent file signature %016llx "
			"(expected %016llx)", sign, SCST_PR_FILE_SIGN);
		goto out_close;
	}
	pos += sizeof(sign);

	version = get_unaligned((uint64_t *)&buf[pos]);
	if (version != SCST_PR_FILE_VERSION) {
		res = -EINVAL;
		PRINT_ERROR("Invalid persistent file version %016llx "
			"(expected %016llx)", version, SCST_PR_FILE_VERSION);
		goto out_close;
	}
	pos += sizeof(version);

	while (data_size < file_size) {
		uint8_t *tid;

		data_size++;
		tid = &buf[data_size];
		data_size += tid_size(tid);
		data_size += sizeof(key);
		data_size += sizeof(rel_tgt_id);

		if (data_size > file_size) {
			res = -EINVAL;
			PRINT_ERROR("Invalid file '%s' - size mismatch have "
				"%lld expected %lld", file_name, file_size,
				data_size);
			goto out_close;
		}
	}

	pr_is_set = buf[pos];
	dev->pr_is_set = pr_is_set ? 1 : 0;
	pos += sizeof(pr_is_set);

	dev->pr_type = buf[pos];
	pos += sizeof(dev->pr_type);

	dev->pr_scope = buf[pos];
	pos += sizeof(dev->pr_scope);

	while (pos < file_size) {
		uint8_t is_holder;
		uint8_t *tid;
		struct scst_dev_registrant *reg = NULL;

		is_holder = buf[pos++];

		tid = &buf[pos];
		pos += tid_size(tid);

		key = get_unaligned((uint64_t *)&buf[pos]);
		pos += sizeof(key);

		rel_tgt_id = get_unaligned((uint16_t *)&buf[pos]);
		pos += sizeof(rel_tgt_id);

		/*
		 * Add a registrant without initiator name and without
		 * attaching to a tgt_dev. The attachment will be done in
		 * scst_pr_init_tgt_dev.
		 */
		reg = scst_pr_add_registrant(dev, tid, rel_tgt_id, key,
			0, NULL);
		if (reg == NULL) {
			res = -ENOMEM;
			goto out_close;
		}

		if (is_holder)
			dev->pr_holder = reg;
	}

out_close:
	filp_close(file, NULL);

out:
	if (buf != NULL)
		vfree(buf);

	set_fs(old_fs);

	TRACE_EXIT_RES(res);
	return res;
}

int scst_pr_load_device_file(struct scst_device *dev)
{
	int res;

	TRACE_ENTRY();

	if (dev->pr_file_name == NULL || dev->pr_file_name1 == NULL) {
		PRINT_ERROR("Invalid file paths for '%s'", dev->virt_name);
		res = -EINVAL;
		goto out;
	}

	res = scst_pr_do_load_device_file(dev, dev->pr_file_name);
	if (res == 0)
		goto out;
	else if (res == -ENOMEM)
		goto out;

	res = scst_pr_do_load_device_file(dev, dev->pr_file_name1);

	scst_pr_dump_registrants(dev);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static int scst_pr_copy_file(const char *src, const char *dest)
{
	int res = 0;
	struct inode *inode;
	loff_t file_size, pos;
	uint8_t *buf = NULL;
	struct file *file_src = NULL, *file_dest = NULL;
	mm_segment_t old_fs = get_fs();

	TRACE_ENTRY();

	if (src == NULL || dest == NULL) {
		res = -EINVAL;
		PRINT_ERROR("%s", "Invalid persistent files path - backup "
			"skipped");
		goto out;
	}

	TRACE_PR("Copy '%s' into '%s'", src, dest);

	set_fs(KERNEL_DS);

	file_src = filp_open(src, O_RDONLY, 0);
	if (IS_ERR(file_src)) {
		res = PTR_ERR(file_src);
		TRACE_PR("Unable to open file '%s' - error %d", src,
			res);
		goto out_free;
	}

	file_dest = filp_open(dest, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(file_dest)) {
		res = PTR_ERR(file_dest);
		TRACE_PR("Unable to open backup file '%s' - error %d", dest,
			res);
		goto out_close;
	}

	inode = file_src->f_dentry->d_inode;

	if (S_ISREG(inode->i_mode))
		/* Nothing to do */;
	else if (S_ISBLK(inode->i_mode))
		inode = inode->i_bdev->bd_inode;
	else {
		PRINT_ERROR("Invalid file mode 0x%x", inode->i_mode);
		res = -EINVAL;
		set_fs(old_fs);
		goto out_skip;
	}

	file_size = inode->i_size;

	buf = vmalloc(file_size);
	if (buf == NULL) {
		res = -ENOMEM;
		PRINT_ERROR("%s", "Unable to allocate temporary buffer");
		goto out_skip;
	}

	pos = 0;
	res = vfs_read(file_src, buf, file_size, &pos);
	if (res != file_size) {
		PRINT_ERROR("Unable to read file '%s' - error %d", src, res);
		goto out_skip;
	}

	pos = 0;
	res = vfs_write(file_dest, buf, file_size, &pos);
	if (res != file_size) {
		PRINT_ERROR("Unable to write to '%s' - error %d", dest, res);
		goto out_skip;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	res = scst_pr_vfs_fsync(file_dest, 0, file_size);
#else
	res = vfs_fsync(file_dest, file_dest->f_path.dentry, 0);
#endif
	if (res != 0) {
		PRINT_ERROR("fsync() of the backup PR file failed: %d", res);
		goto out_skip;
	}

out_skip:
	filp_close(file_dest, NULL);

out_close:
	filp_close(file_src, NULL);

out_free:
	if (buf != NULL)
		vfree(buf);

	set_fs(old_fs);

out:
	TRACE_EXIT_RES(res);
	return res;
}

static void scst_pr_remove_device_files(struct scst_tgt_dev *tgt_dev)
{
	int res = 0;
	struct scst_device *dev = tgt_dev->dev;
	struct nameidata nd;
	mm_segment_t old_fs = get_fs();

	TRACE_ENTRY();

	set_fs(KERNEL_DS);

	res = path_lookup(dev->pr_file_name, 0, &nd);
	if (!res)
		scst_pr_vfs_unlink_and_put(&nd);
	else
		TRACE_PR("Unable to lookup file '%s' - error %d",
			dev->pr_file_name, res);

	res = path_lookup(dev->pr_file_name1, 0, &nd);
	if (!res)
		scst_pr_vfs_unlink_and_put(&nd);
	else
		TRACE_PR("Unable to lookup file '%s' - error %d",
			dev->pr_file_name1, res);

	set_fs(old_fs);

	TRACE_EXIT();
	return;
}

static int scst_pr_sync_device_file(struct scst_tgt_dev *tgt_dev)
{
	int res = 0;
	struct scst_device *dev = tgt_dev->dev;
	struct file *file;
	mm_segment_t old_fs = get_fs();
	loff_t pos = 0;
	uint64_t sign;
	uint64_t version;
	uint8_t pr_is_set;

	TRACE_ENTRY();

	if (dev->pr_aptpl == 0) {
		scst_pr_remove_device_files(tgt_dev);
		goto out;
	}

	scst_pr_copy_file(dev->pr_file_name, dev->pr_file_name1);

	set_fs(KERNEL_DS);

	file = filp_open(dev->pr_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (IS_ERR(file)) {
		res = PTR_ERR(file);
		PRINT_ERROR("Unable to (re)create PR file '%s' - error %d",
			dev->pr_file_name, res);
		goto out_set_fs;
	}

	TRACE_PR("Update pr file '%s'", dev->pr_file_name);

	/*
	 * signature
	 */
	sign = 0;
	pos = 0;
	res = vfs_write(file, (char *)&sign, sizeof(sign), &pos);
	if (res != sizeof(sign))
		goto write_error;

	/*
	 * version
	 */
	version = SCST_PR_FILE_VERSION;
	res = vfs_write(file, (char *)&version, sizeof(version), &pos);
	if (res != sizeof(version))
		goto write_error;

	/*
	 * reservation
	 */
	pr_is_set = dev->pr_is_set;
	res = vfs_write(file, (char *)&pr_is_set, sizeof(pr_is_set), &pos);
	if (res != sizeof(pr_is_set))
		goto write_error;

	res = vfs_write(file, &dev->pr_type, sizeof(dev->pr_type), &pos);
	if (res != sizeof(dev->pr_type))
		goto write_error;

	res = vfs_write(file, &dev->pr_scope, sizeof(dev->pr_scope), &pos);
	if (res != sizeof(dev->pr_scope))
		goto write_error;

	/*
	 * registration records
	 */
	if (!list_empty(&dev->dev_registrants_list)) {
		struct scst_dev_registrant *reg;

		list_for_each_entry(reg, &dev->dev_registrants_list,
					dev_registrants_list_entry) {
			uint8_t is_holder = 0;
			int size;

			is_holder = (dev->pr_holder == reg);

			res = vfs_write(file, &is_holder, sizeof(is_holder),
					&pos);
			if (res != sizeof(is_holder))
				goto write_error;

			size = tid_size(reg->transport_id);
			res = vfs_write(file, reg->transport_id, size, &pos);
			if (res != size)
				goto write_error;

			res = vfs_write(file, (char *)&reg->key,
					sizeof(reg->key), &pos);
			if (res != sizeof(reg->key))
				goto write_error;

			res = vfs_write(file, (char *)&reg->rel_tgt_id,
					sizeof(reg->rel_tgt_id), &pos);
			if (res != sizeof(reg->rel_tgt_id))
				goto write_error;
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	res = scst_pr_vfs_fsync(file, 0, pos);
#else
	res = vfs_fsync(file, file->f_path.dentry, 0);
#endif
	if (res != 0) {
		PRINT_ERROR("fsync() of the PR file failed: %d", res);
		goto write_error_close;
	}

	sign = SCST_PR_FILE_SIGN;
	pos = 0;
	res = vfs_write(file, (char *)&sign, sizeof(sign), &pos);
	if (res != sizeof(sign))
		goto write_error;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	res = scst_pr_vfs_fsync(file, 0, sizeof(sign));
#else
	res = vfs_fsync(file, file->f_path.dentry, 0);
#endif
	if (res != 0) {
		PRINT_ERROR("fsync() of the PR file failed: %d", res);
		goto write_error_close;
	}

	res = 0;

	filp_close(file, NULL);

out_set_fs:
	set_fs(old_fs);

out:
	if (res != 0)
		PRINT_ERROR("Unable to save persistent information (target %s, "
			"initiator %s, device %s)", tgt_dev->sess->tgt->tgt_name,
			tgt_dev->sess->initiator_name, dev->virt_name);

	TRACE_EXIT_RES(res);
	return res;

write_error:
	PRINT_ERROR("Error writing to '%s' - error %d", dev->pr_file_name, res);

write_error_close:
	filp_close(file, NULL);
	{
		struct nameidata nd;
		int rc;

		rc = path_lookup(dev->pr_file_name, 0,	&nd);
		if (!rc)
			scst_pr_vfs_unlink_and_put(&nd);
		else
			TRACE_PR("Unable to lookup '%s' - error %d",
				dev->pr_file_name, rc);
	}
	goto out_set_fs;
}

int scst_pr_check_pr_path(void)
{
	int res;
	struct nameidata nd;
	mm_segment_t old_fs = get_fs();

	TRACE_ENTRY();

	set_fs(KERNEL_DS);

	res = path_lookup(SCST_PR_DIR, 0, &nd);
	if (res != 0) {
		PRINT_ERROR("Unable to find %s (err %d), you should create "
			"this directory manually or reinstall SCST",
			SCST_PR_DIR, res);
		goto out_setfs;
	}

	scst_pr_path_put(&nd);

out_setfs:
	set_fs(old_fs);

	TRACE_EXIT_RES(res);
	return res;
}

#endif /* CONFIG_SCST_PROC */

int scst_pr_init_dev(struct scst_device *dev)
{
	int res = 0;
	uint8_t q;
	int name_len;

	TRACE_ENTRY();

	mutex_init(&dev->dev_pr_mutex);

	dev->pr_generation = 0;
	dev->pr_is_set = 0;
	dev->pr_holder = NULL;
	dev->pr_scope = SCOPE_LU;
	dev->pr_type = TYPE_UNSPECIFIED;

	INIT_LIST_HEAD(&dev->dev_registrants_list);

	name_len = snprintf(&q, sizeof(q), "%s/%s", SCST_PR_DIR, dev->virt_name) + 1;
	dev->pr_file_name = kzalloc(name_len, GFP_KERNEL);
	if (dev->pr_file_name == NULL) {
		PRINT_ERROR("Allocation of device '%s' file path failed",
			dev->virt_name);
		res = -ENOMEM;
		goto out;
	} else
		snprintf(dev->pr_file_name, name_len, "%s/%s", SCST_PR_DIR,
			dev->virt_name);

	name_len = snprintf(&q, sizeof(q), "%s/%s.1", SCST_PR_DIR, dev->virt_name) + 1;
	dev->pr_file_name1 = kzalloc(name_len, GFP_KERNEL);
	if (dev->pr_file_name1 == NULL) {
		PRINT_ERROR("Allocation of device '%s' backup file path failed",
			dev->virt_name);
		res = -ENOMEM;
		goto out_free_name;
	} else
		snprintf(dev->pr_file_name1, name_len, "%s/%s.1", SCST_PR_DIR,
			dev->virt_name);

#ifndef CONFIG_SCST_PROC
	res = scst_pr_load_device_file(dev);
	if (res == -ENOENT)
		res = 0;
#endif

	if (res != 0)
		goto out_free_name1;

out:
	TRACE_EXIT_RES(res);
	return res;

out_free_name1:
	kfree(dev->pr_file_name1);
	dev->pr_file_name1 = NULL;

out_free_name:
	kfree(dev->pr_file_name);
	dev->pr_file_name = NULL;
	goto out;
}

void scst_pr_clear_dev(struct scst_device *dev)
{
	struct scst_dev_registrant *reg, *tmp_reg;

	TRACE_ENTRY();

	list_for_each_entry_safe(reg, tmp_reg, &dev->dev_registrants_list,
			dev_registrants_list_entry) {
		scst_pr_remove_registrant(dev, reg);
	}

	kfree(dev->pr_file_name);
	kfree(dev->pr_file_name1);

	TRACE_EXIT();
	return;
}

int scst_pr_init_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	int res = 0;

	TRACE_ENTRY();

	tgt_dev->registrant = scst_pr_find_not_used_registrant(
		tgt_dev->dev, tgt_dev->sess->transport_id,
		tgt_dev->sess->tgt->rel_tgt_id);

	if (tgt_dev->registrant != NULL) {
		sBUG_ON(tgt_dev->registrant->tgt_dev != NULL);
		tgt_dev->registrant->tgt_dev = tgt_dev;
	}

	TRACE_EXIT_RES(res);
	return res;
}

void scst_pr_clear_tgt_dev(struct scst_tgt_dev *tgt_dev)
{
	TRACE_ENTRY();

	tgt_dev->initialized = 0;

	if (tgt_dev->registrant != NULL)
		tgt_dev->registrant->tgt_dev = NULL;

	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
static int scst_pr_register_with_spec_i_pt(struct scst_cmd *cmd,
	uint8_t *buffer, int buffer_size, bool aptpl,
	struct list_head *rollback_list)
{
	int res = 0;
	int offset, ext_size;
	uint64_t action_key;
	struct scst_device *dev = cmd->dev;
	struct scst_session *sess = cmd->sess;
	struct scst_dev_registrant *reg;
	uint8_t *transport_id;

	action_key = get_unaligned((__be64 *)&buffer[8]);

	ext_size = be32_to_cpu(get_unaligned((__be32 *)&buffer[24]));
	if ((ext_size + 28) > buffer_size) {
		TRACE_PR("Invalid buffer size %d (max %d)", buffer_size,
			ext_size + 28);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		res = -EINVAL;
		goto out;
	}

	offset = 0;
	while (offset < ext_size) {
		transport_id = &buffer[28 + offset];

		if ((offset + tid_size(transport_id)) > ext_size) {
			TRACE_PR("Invalid transport_id size %d (max %d)",
				tid_size(transport_id), ext_size - offset);
			scst_set_cmd_error(cmd,
				SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
			res = -EINVAL;
			goto out;
		}
		tid_secure(transport_id);
		offset += tid_size(transport_id);
	}

	offset = 0;
	while (offset < ext_size) {
		transport_id = &buffer[28 + offset];

		if ((transport_id[0] & 0x0f) == SCSI_TRANSPORTID_PROTOCOLID_ISCSI &&
		    (transport_id[0] & 0xc0) == 0) {
			struct scst_tgt_dev *t;
			list_for_each_entry(t, &dev->dev_tgt_dev_list,
					dev_tgt_dev_list_entry) {
				if (!tid_equal(t->sess->transport_id,
						transport_id))
					continue;
				if (t->registrant == NULL) {
					reg = scst_pr_add_registrant(dev,
						t->sess->transport_id,
						sess->tgt->rel_tgt_id,
						action_key, aptpl, t);
					if (reg == NULL) {
						scst_set_busy(cmd);
						res = -ENOMEM;
						goto out;
					}
				} else {
					reg = t->registrant;
					reg->rollback_key = reg->key;
					reg->key = action_key;
				}
				list_add_tail(&reg->aux_list_entry,
					rollback_list);
			}
		} else {
			struct scst_tgt_dev *tgt_dev;
			tgt_dev = scst_pr_find_tgt_dev_not_registered_first(
					dev, transport_id,
					sess->tgt->rel_tgt_id, cmd->tgt_dev);
			if (tgt_dev->registrant == NULL) {
				reg = scst_pr_add_registrant(dev,
					tgt_dev->sess->transport_id,
					sess->tgt->rel_tgt_id, action_key,
					aptpl, tgt_dev);
				if (reg == NULL) {
					scst_set_busy(cmd);
					res = -ENOMEM;
					goto out;
				}
			} else {
				reg = tgt_dev->registrant;
				reg->rollback_key = reg->key;
				reg->key = action_key;
			}
			list_add_tail(&reg->aux_list_entry,
				rollback_list);
		}
		offset += tid_size(transport_id);
	}
out:
	return res;
}

/* Called with dev_pr_mutex locked, no IRQ */
static void scst_pr_unregister(struct scst_device *dev,
	struct scst_dev_registrant *reg)
{
	bool is_holder;
	uint8_t pr_type;

	TRACE_ENTRY();

	TRACE_PR("Unregistering key '%0llx'", reg->key);

	is_holder = scst_pr_is_holder(dev, reg);
	pr_type = dev->pr_type;

	scst_pr_remove_registrant(dev, reg);

	if (is_holder && !dev->pr_is_set) {
		/* A registration just released */
		switch (pr_type) {
		case TYPE_WRITE_EXCLUSIVE_REGONLY:
		case TYPE_EXCLUSIVE_ACCESS_REGONLY:
			scst_pr_send_ua_all(dev, NULL,
				SCST_LOAD_SENSE(scst_sense_reservation_released));
			break;
		}
	}

	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_register(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size)
{
	int aptpl, spec_i_pt, all_tg_pt;
	uint64_t key, action_key;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_session *sess = cmd->sess;
	struct scst_dev_registrant *reg, *treg;
	LIST_HEAD(rollback_list);

	TRACE_ENTRY();

	aptpl = buffer[20] & 0x01;
	spec_i_pt = (buffer[20] >> 3) & 0x01;
	all_tg_pt = (buffer[20] >> 2) & 0x01;
	key = get_unaligned((__be64 *)&buffer[0]);
	action_key = get_unaligned((__be64 *)&buffer[8]);

	if (spec_i_pt == 0 && buffer_size != 24) {
		TRACE_PR("Invalid buffer size %d", buffer_size);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		goto out;
	}

	if (all_tg_pt) {
		TRACE_PR("%s", "ALL_TG_PT not supported");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

#ifdef CONFIG_SCST_PROC
	if (aptpl) {
		TRACE_PR("%s", "APTL not supported");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}
#endif

	TRACE_PR("Register: initiator '%s' key '%0llx' action_key '%0llx'",
		sess->initiator_name, key, action_key);

	reg = tgt_dev->registrant;
	if (reg == NULL) {
		TRACE_PR("Initiator '%s' is not registered yet - trying to "
			"register", sess->initiator_name);
		if (key) {
			TRACE_PR("%s", "Key must be zero on new registration");
			scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
			goto out;
		}
		if (action_key) {
			if (spec_i_pt) {
				int rc;
				rc = scst_pr_register_with_spec_i_pt(cmd,
					buffer, buffer_size, aptpl,
					&rollback_list);
				if (rc != 0)
					goto out_rollback;
			}

			/*
			 * tgt_dev can be among TIDs for
			 * scst_pr_register_with_spec_i_pt()
			 */
			if (tgt_dev->registrant == NULL) {
				reg = scst_pr_add_registrant(dev,
					sess->transport_id,
					sess->tgt->rel_tgt_id,
					action_key, aptpl, tgt_dev);
				if (reg == NULL) {
					scst_set_busy(cmd);
					goto out_rollback;
				}
			}
		} else
			TRACE_PR("%s", "Doing nothing - action_key is zero");
	} else {
		if (reg->key != key) {
			TRACE_PR("Initiator '%s' key '%0llx' already "
				"registered - reservation key mismatch",
				debug_transport_id_to_initiator_name(
					reg->transport_id), reg->key);
			scst_set_cmd_error_status(cmd,
				SAM_STAT_RESERVATION_CONFLICT);
			goto out;
		}
		if (spec_i_pt) {
			TRACE_PR("%s", "spec_i_pt must be zero in this case");
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				scst_sense_invalid_field_in_cdb));
			goto out;
		}
		if (action_key == 0)
			scst_pr_unregister(dev, reg);
		else
			reg->key = action_key;
	}

	dev->pr_generation++;

#ifndef CONFIG_SCST_PROC
	if (scst_pr_sync_device_file(tgt_dev)) {
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}
#endif

	scst_pr_dump_registrants(dev);

out:
	list_for_each_entry(reg, &rollback_list, aux_list_entry) {
		reg->rollback_key = 0;
	}

	TRACE_EXIT();
	return;

out_rollback:
	list_for_each_entry_safe(reg, treg, &rollback_list, aux_list_entry) {
		list_del(&reg->aux_list_entry);
		if (reg->rollback_key == 0)
			scst_pr_remove_registrant(dev, reg);
		else {
			reg->key = reg->rollback_key;
			reg->rollback_key = 0;
		}
	}
	goto out;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_register_and_ignore(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size)
{
	int aptpl, all_tg_pt;
	uint64_t action_key;
	struct scst_dev_registrant *reg = NULL;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	aptpl = buffer[20] & 0x01;
	all_tg_pt = (buffer[20] >> 2) & 0x01;
	action_key = get_unaligned((__be64 *)&buffer[8]);

	if (buffer_size != 24) {
		TRACE_PR("Invalid buffer size %d", buffer_size);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		goto out;
	}

	if (all_tg_pt) {
		TRACE_PR("%s", "ALL_TG_PT not supported");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

#ifdef CONFIG_SCST_PROC
	if (aptpl) {
		TRACE_PR("%s", "APTL not supported");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}
#endif

	TRACE_PR("Register and ignore: initiator '%s' action_key '%016llx'",
		sess->initiator_name, action_key);

	reg = tgt_dev->registrant;
	if (reg == NULL) {
		TRACE_PR("Initiator '%s' is not registered yet - trying to "
			"register", sess->initiator_name);
		if (action_key) {
			reg = scst_pr_add_registrant(dev, sess->transport_id,
				sess->tgt->rel_tgt_id, action_key, aptpl,
				cmd->tgt_dev);
			if (reg == NULL) {
				scst_set_busy(cmd);
				goto out;
			}
		} else
			TRACE_PR("%s", "Doing nothing, action_key is zero");
	} else {
		if (action_key == 0)
			scst_pr_unregister(dev, reg);
		else
			reg->key = action_key;
	}

	dev->pr_generation++;

#ifndef CONFIG_SCST_PROC
	if (scst_pr_sync_device_file(tgt_dev)) {
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}
#endif

	scst_pr_dump_registrants(dev);

out:
	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_register_and_move(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size)
{
	int aptpl;
	int unreg;
	int tid_buffer_size;
	uint64_t key, action_key;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_tgt_dev *tgt_dev_move = NULL;
	struct scst_session *sess = cmd->sess;
	struct scst_dev_registrant *reg, *reg_move;
	const uint8_t *transport_id = NULL;
	uint8_t *transport_id_move = NULL;
	uint16_t rel_tgt_id_move;

	TRACE_ENTRY();

	aptpl = buffer[17] & 0x01;
	key = get_unaligned((__be64 *)&buffer[0]);
	action_key = get_unaligned((__be64 *)&buffer[8]);
	unreg = (buffer[17] >> 1) & 0x01;
	tid_buffer_size = be32_to_cpu(get_unaligned((__be32 *)&buffer[20]));

#ifdef CONFIG_SCST_PROC
	if (aptpl) {
		TRACE_PR("%s", "APTL not supported");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}
#endif

	if ((tid_buffer_size + 24) > buffer_size) {
		TRACE_PR("Invalid buffer size %d (%d)",
			buffer_size, tid_buffer_size + 24);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

	if (tid_buffer_size < 24) {
		TRACE_PR("%s", "Transport id buffer too small");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

	/* We already checked reg is not NULL */
	reg = tgt_dev->registrant;

	if (reg->key != key) {
		TRACE_PR("Key '%016llx' not equal to reservation holder "
			"key '%016llx'", key, reg->key);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out;
	}

	if (!dev->pr_is_set) {
		TRACE_PR("%s", "There must be a PR");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	/*
	 * This check also required by table "PERSISTENT RESERVE OUT service
	 * actions that are allowed in the presence of various reservations".
	 */
	if (!scst_pr_is_holder(dev, reg)) {
		TRACE_PR("'%s' is not holder",
			debug_transport_id_to_initiator_name(
				reg->transport_id));
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out;
	}

	if (action_key == 0) {
		TRACE_PR("%s", "Action key must be non-zero");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	transport_id = sess->transport_id;
	transport_id_move = (uint8_t *)&buffer[24];
	rel_tgt_id_move = be16_to_cpu(get_unaligned((__be16 *)&buffer[18]));

	if ((tid_size(transport_id_move) + 24) > buffer_size) {
		TRACE_PR("Invalid buffer size %d (%d)",
			buffer_size, tid_size(transport_id_move) + 24);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

	tid_secure(transport_id_move);

	tgt_dev_move = scst_pr_find_tgt_dev_not_registered_first(dev,
				transport_id_move, rel_tgt_id_move, tgt_dev);
	if (tgt_dev_move == NULL) {
		TRACE_PR("%s", "Unable to find target device for new record");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

	TRACE_PR("Register and move: on initiator '%s' move to initiator '%s' "
		"key '%016llx'", sess->initiator_name,
		tgt_dev_move->sess->initiator_name, action_key);

	if (dev->pr_type == TYPE_WRITE_EXCLUSIVE_ALL ||
	    dev->pr_type == TYPE_EXCLUSIVE_ACCESS_ALL) {
		TRACE_PR("Unable to finish operation due to wrong reservation "
			"type %02x", dev->pr_type);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out;
	}

	if (tid_equal(transport_id, transport_id_move)) {
		TRACE_PR("%s", "Equal transport id's");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_parm_list));
		goto out;
	}

	if (tgt_dev_move->registrant == NULL) {
		reg_move = scst_pr_add_registrant(dev, transport_id_move,
			tgt_dev_move->sess->tgt->rel_tgt_id, action_key,
			aptpl, tgt_dev_move);
		if (reg_move == NULL) {
			scst_set_busy(cmd);
			goto out;
		}
	} else
		tgt_dev_move->registrant->key = action_key;

	/* Move the holder */
	scst_pr_set_holder(dev, tgt_dev_move->registrant, dev->pr_scope,
		dev->pr_type);

	if (unreg)
		scst_pr_remove_registrant(dev, reg);

	dev->pr_generation++;

#ifndef CONFIG_SCST_PROC
	if (scst_pr_sync_device_file(tgt_dev)) {
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}
#endif

	scst_pr_dump_registrants(dev);
	scst_pr_dump_reservation(dev);

out:
	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_reserve(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size)
{
	uint8_t scope, type;
	uint64_t key;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_dev_registrant *reg;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	key = get_unaligned((__be64 *)&buffer[0]);
	scope = (cmd->cdb[2] & 0x0f) >> 4;
	type = cmd->cdb[2] & 0x0f;

	if (buffer_size != 24) {
		TRACE_PR("Invalid buffer size %d", buffer_size);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		goto out;
	}

	if ((PR_TYPE_SHIFT_MASK & (1 << type)) == 0) {
		TRACE_PR("Invalid reservation type %d", type);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	if (((cmd->cdb[2] & 0x0f) >> 4) != SCOPE_LU) {
		TRACE_PR("Invalid reservation scope %d", scope);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	TRACE_PR("Reserve: initiator '%s' key '%016llx' scope %d, type %d",
		sess->initiator_name, key, scope, type);

	/* We already checked reg is not NULL */
	reg = tgt_dev->registrant;
	if (reg->key != key) {
		TRACE_PR("Initiator's '%s' key '%016llx' mismatch",
			sess->initiator_name, key);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out;
	}

	if (!dev->pr_is_set)
		scst_pr_set_holder(dev, reg, scope, type);
	else {
		if (!scst_pr_is_holder(dev, reg)) {
			/*
			 * This check also required by table "PERSISTENT
			 * RESERVE OUT service actions that are allowed in the
			 * presence of various reservations".
			 */
			TRACE_PR("Only holder can override - initiator "
				"'%s' is not holder", sess->initiator_name);
			scst_set_cmd_error_status(cmd,
				SAM_STAT_RESERVATION_CONFLICT);
			goto out;
		} else {
			if (dev->pr_scope != scope || dev->pr_type != type) {
				TRACE_PR("Error overriding scope or type for "
					"initiator '%s'", sess->initiator_name);
				scst_set_cmd_error_status(cmd,
					SAM_STAT_RESERVATION_CONFLICT);
				goto out;
			} else
				TRACE_PR("%s", "Do nothing: reservation is "
					"the same");
		}
	}

	scst_pr_dump_registrants(dev);
	scst_pr_dump_reservation(dev);

out:
	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_release(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size)
{
	int scope, type;
	uint64_t key;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_dev_registrant *reg;
	struct scst_session *sess = cmd->sess;
	uint8_t cur_pr_type;

	TRACE_ENTRY();

	key = get_unaligned((__be64 *)&buffer[0]);
	scope = (cmd->cdb[2] & 0x0f) >> 4;
	type = cmd->cdb[2] & 0x0f;

	if (buffer_size != 24) {
		TRACE_PR("Invalid buffer size %d", buffer_size);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		goto out;
	}

	if (!dev->pr_is_set) {
		TRACE_PR("%s", "There is no PR - do nothing");
		goto out;
	}

	TRACE_PR("Release: initiator '%s', key '%016llx', scope '%d', type "
		"'%d'", sess->initiator_name, key, scope, type);

	/* We already checked reg is not NULL */
	reg = tgt_dev->registrant;
	if (reg->key != key) {
		TRACE_PR("Initiator's '%s' key '%016llx' mismatch",
			sess->initiator_name, key);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out;
	}

	if (!scst_pr_is_holder(dev, reg)) {
		TRACE_PR("Initiator '%s' is not a holder - do nothing",
			sess->initiator_name);
		goto out;
	}

	if (dev->pr_scope != scope || dev->pr_type != type) {
		TRACE_PR("%s", "Released scope or type do not match with "
			"holder");
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_release));
		goto out;
	}

	cur_pr_type = dev->pr_type; /* scst_pr_clear_holder() will clear it */

	scst_pr_clear_holder(dev);

	if (!dev->pr_is_set) {
		/* A registration just released */
		switch (cur_pr_type) {
		case TYPE_WRITE_EXCLUSIVE_REGONLY:
		case TYPE_EXCLUSIVE_ACCESS_REGONLY:
		case TYPE_WRITE_EXCLUSIVE:
		case TYPE_EXCLUSIVE_ACCESS:
			scst_pr_send_ua_all(dev, reg,
				SCST_LOAD_SENSE(scst_sense_reservation_released));
			break;
		}
	}

#ifndef CONFIG_SCST_PROC
	if (scst_pr_sync_device_file(tgt_dev)) {
		scst_set_cmd_error(cmd, SCST_LOAD_SENSE(scst_sense_hardw_error));
		goto out;
	}
#endif

	scst_pr_dump_registrants(dev);
	scst_pr_dump_reservation(dev);

out:
	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_clear(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size)
{
	int scope, type;
	uint64_t key;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_dev_registrant *reg, *r, *t;
	struct scst_session *sess = cmd->sess;

	TRACE_ENTRY();

	key = get_unaligned((__be64 *)&buffer[0]);
	scope = (cmd->cdb[2] & 0x0f) >> 4;
	type = cmd->cdb[2] & 0x0f;

	if (buffer_size != 24) {
		TRACE_PR("Invalid buffer size %d", buffer_size);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		goto out;
	}

	TRACE_PR("Clear: initiator '%s' key '%016llx'", sess->initiator_name,
		key);

	/* We already checked reg is not NULL */
	reg = tgt_dev->registrant;
	if (reg->key != key) {
		TRACE_PR("Initiator's '%s' key '%016llx' mismatch",
			sess->initiator_name, key);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out;
	}

	scst_pr_send_ua_all(dev, NULL,
		SCST_LOAD_SENSE(scst_sense_reservation_preempted));

	list_for_each_entry_safe(r, t, &dev->dev_registrants_list,
					dev_registrants_list_entry) {
		scst_pr_remove_registrant(dev, r);
	}

	dev->pr_generation++;

	scst_pr_dump_registrants(dev);
	scst_pr_dump_reservation(dev);

out:
	TRACE_EXIT();
	return;
}

static void scst_pr_do_preempt(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size, bool abort)
{
	uint64_t key, action_key;
	int scope, type;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_dev_registrant *reg, *r, *rt;
	struct scst_session *sess = cmd->sess;
	LIST_HEAD(preempt_list);

	TRACE_ENTRY();

	key = get_unaligned((__be64 *)&buffer[0]);
	action_key = get_unaligned((__be64 *)&buffer[8]);
	scope = (cmd->cdb[2] & 0x0f) >> 4;
	type = cmd->cdb[2] & 0x0f;

	if (buffer_size != 24) {
		TRACE_PR("Invalid buffer size %d", buffer_size);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_parameter_list_length_invalid));
		goto out;
	}

	if ((PR_TYPE_SHIFT_MASK & (1 << type)) == 0) {
		TRACE_PR("Invalid reservation type %d", type);
		scst_set_cmd_error(cmd,
			SCST_LOAD_SENSE(scst_sense_invalid_field_in_cdb));
		goto out;
	}

	TRACE_PR("Preempt%s: initiator '%s' key '%016llx' action_key '%016llx' "
		"scope %x type %x", abort ? " and abort" : "",
		sess->initiator_name, key, action_key, scope, type);

	/* We already checked reg is not NULL */
	reg = tgt_dev->registrant;
	if (reg->key != key) {
		TRACE_PR("Initiator's '%s' key '%016llx' mismatch",
			sess->initiator_name, key);
		scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
		goto out;
	}

	if (!dev->pr_is_set) {
		scst_pr_find_registrants_list_key(dev, action_key,
			&preempt_list);
		if (list_empty(&preempt_list))
			goto out_error;
		list_for_each_entry_safe(r, rt, &preempt_list, aux_list_entry) {
			if (r != reg)
				scst_pr_send_ua_reg(dev, r, SCST_LOAD_SENSE(
					scst_sense_registrations_preempted));
			scst_pr_remove_registrant(dev, r);
		}
		goto done;
	}

	if (dev->pr_type == TYPE_WRITE_EXCLUSIVE_ALL ||
	    dev->pr_type == TYPE_EXCLUSIVE_ACCESS_ALL) {
		if (action_key == 0) {
			scst_pr_find_registrants_list_all(dev, reg,
				&preempt_list);
			list_for_each_entry_safe(r, rt, &preempt_list,
					aux_list_entry) {
				if (r != reg)
					scst_pr_send_ua_reg(dev, r,
						SCST_LOAD_SENSE(
						scst_sense_registrations_preempted));
				scst_pr_remove_registrant(dev, r);
			}
			scst_pr_set_holder(dev, reg, scope, type);
		} else {
			scst_pr_find_registrants_list_key(dev, action_key,
				&preempt_list);
			if (list_empty(&preempt_list))
				goto out_error;
			list_for_each_entry_safe(r, rt, &preempt_list,
					aux_list_entry) {
				if (r != reg)
					scst_pr_send_ua_reg(dev, r,
						SCST_LOAD_SENSE(
						scst_sense_registrations_preempted));
				scst_pr_remove_registrant(dev, r);
			}
		}
		goto done;
	}

	sBUG_ON(dev->pr_holder == NULL);

	if (dev->pr_holder->key != action_key) {
		if (action_key == 0) {
			scst_set_cmd_error(cmd, SCST_LOAD_SENSE(
				scst_sense_invalid_field_in_parm_list));
			goto out;
		} else {
			scst_pr_find_registrants_list_key(dev, action_key,
				&preempt_list);
			if (list_empty(&preempt_list))
				goto out_error;
			list_for_each_entry_safe(r, rt, &preempt_list,
					aux_list_entry) {
				if (r != reg)
					scst_pr_send_ua_reg(dev, r,
						SCST_LOAD_SENSE(
						scst_sense_registrations_preempted));
				scst_pr_remove_registrant(dev, r);
			}
			goto done;
		}
	}

	scst_pr_find_registrants_list_key(dev, action_key,
		&preempt_list);

	list_for_each_entry_safe(r, rt, &preempt_list, aux_list_entry) {
		if (abort)
			scst_pr_abort_reg(dev, cmd, r);
		if (r != reg)
			scst_pr_send_ua_reg(dev, r, SCST_LOAD_SENSE(
				scst_sense_registrations_preempted));
		scst_pr_remove_registrant(dev, r);
	}

	if (dev->pr_type != type || dev->pr_scope != scope)
		list_for_each_entry(r, &dev->dev_registrants_list,
					dev_registrants_list_entry) {
			if (r != reg)
				scst_pr_send_ua_reg(dev, r, SCST_LOAD_SENSE(
					scst_sense_reservation_released));
		}

	scst_pr_set_holder(dev, reg, scope, type);

done:
	dev->pr_generation++;

	scst_pr_dump_registrants(dev);
	scst_pr_dump_reservation(dev);

out:
	TRACE_EXIT();
	return;

out_error:
	TRACE_PR("Invalid key '%016llx'", action_key);
	scst_set_cmd_error_status(cmd, SAM_STAT_RESERVATION_CONFLICT);
	goto out;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_preempt(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size)
{
	TRACE_ENTRY();

	scst_pr_do_preempt(cmd, buffer, buffer_size, false);

	TRACE_EXIT();
	return;
}

/*
 * Called with dev_pr_mutex locked, no IRQ. Expects session_list_lock
 * not locked
 */
void scst_pr_preempt_and_abort(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size)
{
	TRACE_ENTRY();

	scst_pr_do_preempt(cmd, buffer, buffer_size, true);

	TRACE_EXIT();
	return;
}

/* Checks if this is a Compatible Reservation Handling (CRH) case */
bool scst_pr_crh_case(struct scst_cmd *cmd)
{
	bool allowed;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_dev_registrant *reg;
	uint8_t type;

	TRACE_ENTRY();

	TRACE_DBG("Test if there is a CRH case for command '%s' (0x%x) from "
		"'%s'", cmd->op_name, cmd->cdb[0], cmd->sess->initiator_name);

	if (!dev->pr_is_set) {
		TRACE_PR("%s", "PR not set");
		allowed = false;
		goto out;
	}

	reg = tgt_dev->registrant;
	type = dev->pr_type;

	switch (type) {
	case TYPE_WRITE_EXCLUSIVE:
	case TYPE_EXCLUSIVE_ACCESS:
		WARN_ON(dev->pr_holder == NULL);
		if (reg == dev->pr_holder)
			allowed = true;
		else
			allowed = false;
		break;

	case TYPE_WRITE_EXCLUSIVE_REGONLY:
	case TYPE_EXCLUSIVE_ACCESS_REGONLY:
	case TYPE_WRITE_EXCLUSIVE_ALL:
	case TYPE_EXCLUSIVE_ACCESS_ALL:
		allowed = (reg != NULL);
		break;

	default:
		PRINT_ERROR("Invalid PR type %x", type);
		allowed = false;
		break;
	}

	if (!allowed)
		TRACE_PR("Command '%s' (0x%x) from '%s' is being rejected due "
			"to not CRH reservation", cmd->op_name, cmd->cdb[0],
			cmd->sess->initiator_name);
	else
		TRACE_DBG("Command %s (0x%x) from '%s' is allowed to execute "
			"due to CRH", cmd->op_name, cmd->cdb[0],
			cmd->sess->initiator_name);

out:
	TRACE_EXIT_RES(allowed);
	return allowed;

}

/* Check if command allowed in presence of reservation */
bool scst_pr_is_cmd_allowed(struct scst_cmd *cmd)
{
	bool allowed;
	struct scst_device *dev = cmd->dev;
	struct scst_tgt_dev *tgt_dev = cmd->tgt_dev;
	struct scst_dev_registrant *reg;
	uint8_t type;

	TRACE_ENTRY();

	TRACE_DBG("Test if command '%s' (0x%x) from '%s' allowed to execute",
		cmd->op_name, cmd->cdb[0], cmd->sess->initiator_name);

	reg = tgt_dev->registrant;
	type = dev->pr_type;

	switch (type) {
	case TYPE_WRITE_EXCLUSIVE:
		if (reg && reg == dev->pr_holder)
			allowed = true;
		else
			allowed = (cmd->op_flags & SCST_WRITE_EXCL_ALLOWED) != 0;
		break;

	case TYPE_EXCLUSIVE_ACCESS:
		if (reg && reg == dev->pr_holder)
			allowed = true;
		else
			allowed = (cmd->op_flags & SCST_EXCL_ACCESS_ALLOWED) != 0;
		break;

	case TYPE_WRITE_EXCLUSIVE_REGONLY:
	case TYPE_WRITE_EXCLUSIVE_ALL:
		if (reg)
			allowed = true;
		else
			allowed = (cmd->op_flags & SCST_WRITE_EXCL_ALLOWED) != 0;
		break;

	case TYPE_EXCLUSIVE_ACCESS_REGONLY:
	case TYPE_EXCLUSIVE_ACCESS_ALL:
		if (reg)
			allowed = true;
		else
			allowed = (cmd->op_flags & SCST_EXCL_ACCESS_ALLOWED) != 0;
		break;

	default:
		PRINT_ERROR("Invalid PR type %x", type);
		allowed = false;
		break;
	}

	if (!allowed)
		TRACE_PR("Command '%s' (0x%x) from '%s' is being rejected due "
			"to reservation", cmd->op_name, cmd->cdb[0],
			cmd->sess->initiator_name);
	else
		TRACE_DBG("Command %s (0x%x) from '%s' is allowed to execute",
			cmd->op_name, cmd->cdb[0], cmd->sess->initiator_name);

	TRACE_EXIT_RES(allowed);
	return allowed;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_read_keys(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size)
{
	int i, offset = 0, size, size_max;
	struct scst_device *dev = cmd->dev;
	struct scst_dev_registrant *reg;

	TRACE_ENTRY();

	if (buffer_size < 8) {
		TRACE_PR("buffer_size too small: %d. expected >= 8 "
			"(buffer %p)", buffer_size, buffer);
		goto skip;
	}

	TRACE_PR("Read Keys (dev %s): PRGen %d", dev->virt_name,
			dev->pr_generation);

	put_unaligned(cpu_to_be32(dev->pr_generation), (__be32 *)&buffer[0]);

	offset = 8;
	size = 0;
	size_max = buffer_size - 8;

	i = 0;
	list_for_each_entry(reg, &dev->dev_registrants_list,
				dev_registrants_list_entry) {
		if (size_max - size > 8) {
			TRACE_PR("Read Keys (dev %s): key 0x%llx",
				dev->virt_name, reg->key);

			WARN_ON(reg->key == 0);

			put_unaligned(cpu_to_be64(reg->key),
				(__be64 *)&buffer[offset + 8 * i]);

			offset += 8;
		}
		size += 8;
	}

	put_unaligned(cpu_to_be32(size), (__be32 *)&buffer[4]);

skip:
	scst_set_resp_data_len(cmd, offset);

	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_read_reservation(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size)
{
	struct scst_device *dev = cmd->dev;
	uint8_t b[24];
	int size = 0;

	TRACE_ENTRY();

	if (buffer_size < 8) {
		TRACE_PR("buffer_size too small: %d. expected >= 8 "
			"(buffer %p)", buffer_size, buffer);
		goto skip;
	}

	memset(b, 0, sizeof(b));

	put_unaligned(cpu_to_be32(dev->pr_generation), (__be32 *)&buffer[0]);

	if (!dev->pr_is_set) {
		TRACE_PR("Read Reservation: no reservation for dev %s",
			dev->virt_name);
		b[4] =
		b[5] =
		b[6] =
		b[7] = 0;

		size = 8;
	} else {
		uint64_t key = dev->pr_holder ? dev->pr_holder->key : 0;

		TRACE_PR("Read Reservation: dev %s, holder %p, key 0x%llx, "
			"scope %d, type %d", dev->virt_name, dev->pr_holder,
			key, dev->pr_scope, dev->pr_type);

		b[4] =
		b[5] =
		b[6] = 0;
		b[7] = 0x10;

		put_unaligned(cpu_to_be64(key), (__be64 *)&b[8]);
		b[21] = dev->pr_scope << 4 | dev->pr_type;

		size = 24;
	}

	memset(buffer, 0, buffer_size);
	memcpy(buffer, b, min(size, buffer_size));

skip:
	scst_set_resp_data_len(cmd, size);

	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_report_caps(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size)
{
	int offset = 0;
	unsigned int crh = 1;
	unsigned int atp_c = 0;
	unsigned int sip_c = 1;
#ifdef CONFIG_SCST_PROC
	unsigned int ptpl_c = 0;
#else
	unsigned int ptpl_c = 1;
#endif
	struct scst_device *dev = cmd->dev;

	TRACE_ENTRY();

	if (buffer_size < 8) {
		TRACE_PR("buffer_size too small: %d. expected >= 8 "
			"(buffer %p)", buffer_size, buffer);
		goto skip;
	}

	TRACE_PR("Report Capabilities (dev %s):  crh %x, sip_c %x, "
		"atp_c %x, ptpl_c %x, pr_aptpl %x", dev->virt_name,
		crh, sip_c, atp_c, ptpl_c, dev->pr_aptpl);

	buffer[0] = 0;
	buffer[1] = 8;

	buffer[2] = crh << 4 | sip_c << 3 | atp_c << 2 | ptpl_c;
	buffer[3] = (1 << 7) | (dev->pr_aptpl > 0 ? 1 : 0);

	/* All commands supported */
	buffer[4] = 0xEA;
	buffer[5] = 0x1;

	offset += 8;

skip:
	scst_set_resp_data_len(cmd, offset);

	TRACE_EXIT();
	return;
}

/* Called with dev_pr_mutex locked, no IRQ */
void scst_pr_read_full_status(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size)
{
	int offset = 0, size, size_max;
	struct scst_device *dev = cmd->dev;
	struct scst_dev_registrant *reg;

	TRACE_ENTRY();

	if (buffer_size < 8)
		goto skip;

	put_unaligned(cpu_to_be32(dev->pr_generation), (__be32 *)&buffer[0]);
	offset += 8;

	size = 0;
	size_max = buffer_size - 8;

	list_for_each_entry(reg, &dev->dev_registrants_list,
				dev_registrants_list_entry) {
		int ts;
		int rec_len;

		ts = tid_size(reg->transport_id);
		rec_len = 24 + ts;

		if (size_max - size > rec_len) {
			memset(&buffer[offset], 0, rec_len);

			put_unaligned(cpu_to_be64(reg->key),
				(__be64 *)(&buffer[offset]));

			if (dev->pr_is_set && scst_pr_is_holder(dev, reg)) {
				buffer[offset + 12] = 1;
				buffer[offset + 13] = (dev->pr_scope << 8) | dev->pr_type;
			}

			put_unaligned(cpu_to_be16(reg->rel_tgt_id),
				(__be16 *)&buffer[offset + 18]);
			put_unaligned(cpu_to_be32(ts),
				(__be32 *)&buffer[offset + 20]);

			memcpy(&buffer[offset + 24], reg->transport_id, ts);

			offset += rec_len;
		}
		size += rec_len;
	}

	put_unaligned(cpu_to_be32(size), (__be32 *)&buffer[4]);

skip:
	scst_set_resp_data_len(cmd, offset);

	TRACE_EXIT();
	return;
}
