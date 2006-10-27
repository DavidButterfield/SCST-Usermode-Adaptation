/*
 *  scst_disk.c
 *  
 *  Copyright (C) 2004-2006 Vladislav Bolkhovitin <vst@vlnb.net>
 *                 and Leonid Stoljar
 *
 *  SCSI disk (type 0) dev handler
 *  &
 *  SCSI disk (type 0) "performance" device handler (skip all READ and WRITE
 *   operations).
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

#include <linux/module.h>
#include <linux/init.h>

#define LOG_PREFIX           "dev_disk"
#include "scst_debug.h"
#include "scsi_tgt.h"
#include "scst_dev_handler.h"

#include "scst_debug.c"

# define DISK_NAME           "dev_disk"
# define DISK_PERF_NAME      "dev_disk_perf"

#define DISK_TYPE {          \
  name:     DISK_NAME,	     \
  type:     TYPE_DISK,       \
  parse_atomic:     1,       \
  dev_done_atomic:  1,       \
  exec_atomic:      1,       \
  attach:   disk_attach,     \
  detach:   disk_detach,     \
  parse:    disk_parse,      \
  dev_done: disk_done,       \
}

#define DISK_PERF_TYPE {     \
  name:     DISK_PERF_NAME,  \
  type:     TYPE_DISK,       \
  parse_atomic:     1,       \
  dev_done_atomic:  1,       \
  exec_atomic:      1,       \
  attach:   disk_attach,     \
  detach:   disk_detach,     \
  parse:    disk_parse,      \
  dev_done: disk_done,       \
  exec:     disk_exec,       \
}

#define DISK_RETRIES  2
#define DISK_SMALL_TIMEOUT  (3 * HZ)
#define DISK_REG_TIMEOUT    (60 * HZ)
#define DISK_LONG_TIMEOUT   (3600 * HZ)
#define READ_CAP_LEN  8

/* Flags */
#define BYTCHK         0x02

struct disk_params
{
	int sector_size;
};

int disk_attach(struct scst_device *dev);
void disk_detach(struct scst_device *dev);
int disk_parse(struct scst_cmd *cmd, const struct scst_info_cdb *info_cmd);
int disk_done(struct scst_cmd *cmd);
int disk_exec(struct scst_cmd *cmd);

#if defined(DEBUG) || defined(TRACING)
unsigned long trace_flag = SCST_DEFAULT_DEV_LOG_FLAGS;
#endif

static struct scst_dev_type disk_devtype = DISK_TYPE;
static struct scst_dev_type disk_devtype_perf = DISK_PERF_TYPE;

static int __init init_scst_disk_driver(void)
{
	int res = 0;

	TRACE_ENTRY();
	
	disk_devtype.module = THIS_MODULE;
	if (scst_register_dev_driver(&disk_devtype) < 0) {
		res = -ENODEV;
		goto out;
	}

	res = scst_dev_handler_build_std_proc(&disk_devtype);
	if (res != 0)
		goto out_unreg1;

	disk_devtype_perf.module = THIS_MODULE;
	if (scst_register_dev_driver(&disk_devtype_perf) < 0) {
		res = -ENODEV;
		goto out_unreg1_err1;
	}

	res = scst_dev_handler_build_std_proc(&disk_devtype_perf);
	if (res != 0)
		goto out_unreg2;

out:
	TRACE_EXIT_RES(res);
	return res;

out_unreg2:
	scst_dev_handler_destroy_std_proc(&disk_devtype_perf);

out_unreg1_err1:
	scst_dev_handler_destroy_std_proc(&disk_devtype);

out_unreg1:
	scst_unregister_dev_driver(&disk_devtype);
	goto out;
}

static void __exit exit_scst_disk_driver(void)
{
	TRACE_ENTRY();
	scst_dev_handler_destroy_std_proc(&disk_devtype_perf);
	scst_unregister_dev_driver(&disk_devtype_perf);
	scst_dev_handler_destroy_std_proc(&disk_devtype);
	scst_unregister_dev_driver(&disk_devtype);
	TRACE_EXIT();
	return;
}

module_init(init_scst_disk_driver);
module_exit(exit_scst_disk_driver);

/**************************************************************
 *  Function:  disk_attach
 *
 *  Argument:  
 *
 *  Returns :  1 if attached, error code otherwise
 *
 *  Description:  
 *************************************************************/
int disk_attach(struct scst_device *dev)
{
	int res = 0;
	uint8_t cmd[10];
	const int buffer_size = 512;
	uint8_t *buffer = NULL;
	int retries;
	unsigned char sense_buffer[SCSI_SENSE_BUFFERSIZE];
	enum dma_data_direction data_dir;
	unsigned char *sbuff;
	struct disk_params *disk;

	TRACE_ENTRY();

	if (dev->scsi_dev == NULL ||
	    dev->scsi_dev->type != dev->handler->type) {
		PRINT_ERROR_PR("%s", "SCSI device not define or illegal type");
		res = -ENODEV;
		goto out;
	}

	disk = kzalloc(sizeof(*disk), GFP_KERNEL);
	TRACE_MEM("kzalloc(GFP_KERNEL) for struct disk_params (%zu): %p",
	      sizeof(*disk), disk);
	if (disk == NULL) {
		TRACE(TRACE_OUT_OF_MEM, "%s",
		      "Unable to allocate struct disk_params");
		res = -ENOMEM;
		goto out;
	}

	buffer = kzalloc(buffer_size, GFP_KERNEL);
	TRACE_MEM("kzalloc(GFP_KERNEL) for %d: %p", buffer_size, buffer);
	if (!buffer) {
		TRACE(TRACE_OUT_OF_MEM, "%s", "Memory allocation failure");
		res = -ENOMEM;
		goto out_free_disk;
	}

	/* Clear any existing UA's and get disk capacity (disk block size) */
	memset(cmd, 0, sizeof(cmd));
	cmd[0] = READ_CAPACITY;
	cmd[1] = (dev->scsi_dev->scsi_level <= SCSI_2) ?
	    ((dev->scsi_dev->lun << 5) & 0xe0) : 0;
	retries = SCST_DEV_UA_RETRIES;
	while (1) {
		memset(buffer, 0, buffer_size);
		data_dir = SCST_DATA_READ;
		sbuff = sense_buffer;

		TRACE_DBG("%s", "Doing READ_CAPACITY");
		res = scsi_execute(dev->scsi_dev, cmd, data_dir, buffer, 
				   buffer_size, sbuff, 
				   DISK_REG_TIMEOUT, DISK_RETRIES, 0);

		TRACE_DBG("READ_CAPACITY done: %x", res);

		if (!res || (sbuff[12] != 0x28 && sbuff[12] != 0x29)) 
		{
			break;
		}
		if (!--retries) {
			PRINT_ERROR_PR("UA not clear after %d retries",
				SCST_DEV_UA_RETRIES);
			res = -ENODEV;
			goto out_free_buf;
		}
	}
	if (res == 0) {
		disk->sector_size = ((buffer[4] << 24) | (buffer[5] << 16) |
				     (buffer[6] << 8) | (buffer[7] << 0));
		TRACE_DBG("Sector size is %i", disk->sector_size);
		if (!disk->sector_size) {
			disk->sector_size = 512;
		}
	} else {
		TRACE_BUFFER("Sense set", sbuff, SCSI_SENSE_BUFFERSIZE);
		res = -ENODEV;
		goto out_free_buf;
	}

out_free_buf:
	TRACE_MEM("kfree for buffer: %p", buffer);
	kfree(buffer);

out_free_disk:
	if (res == 0)
		dev->dh_priv = disk;
	else {
		TRACE_MEM("kfree for disk: %p", disk);
		kfree(disk);
	}

out:
	TRACE_EXIT_RES(res);
	return res;
}

/************************************************************
 *  Function:  disk_detach
 *
 *  Argument: 
 *
 *  Returns :  None
 *
 *  Description:  Called to detach this device type driver
 ************************************************************/
void disk_detach(struct scst_device *dev)
{
	struct disk_params *disk = (struct disk_params *)dev->dh_priv;

	TRACE_ENTRY();

	TRACE_MEM("kfree for disk: %p", disk);
	kfree(disk);
	dev->dh_priv = NULL;

	TRACE_EXIT();
	return;
}

/********************************************************************
 *  Function:  disk_parse
 *
 *  Argument:  
 *
 *  Returns :  The state of the command
 *
 *  Description:  This does the parsing of the command
 *
 *  Note:  Not all states are allowed on return
 ********************************************************************/
int disk_parse(struct scst_cmd *cmd, const struct scst_info_cdb *info_cdb)
{
	int res = SCST_CMD_STATE_DEFAULT;
	struct disk_params *disk;
	int fixed;

	TRACE_ENTRY();

	/*
	 * SCST sets good defaults for cmd->data_direction and cmd->bufflen
	 * based on info_cdb, therefore change them only if necessary
	 */

	if (info_cdb->flags & SCST_SMALL_TIMEOUT) {
		cmd->timeout = DISK_SMALL_TIMEOUT;
	} else if (info_cdb->flags & SCST_LONG_TIMEOUT) {
		cmd->timeout = DISK_LONG_TIMEOUT;
	} else {
		cmd->timeout = DISK_REG_TIMEOUT;
	}

	TRACE_DBG("op_name <%s> direct %d flags %d transfer_len %d",
	      info_cdb->op_name,
	      info_cdb->direction, info_cdb->flags, info_cdb->transfer_len);

	fixed = info_cdb->flags & SCST_TRANSFER_LEN_TYPE_FIXED;
	switch (cmd->cdb[0]) {
	case READ_CAPACITY:
		cmd->bufflen = READ_CAP_LEN;
		cmd->data_direction = SCST_DATA_READ;
		break;
#if 0
	case SYNCHRONIZE_CACHE:
		cmd->underflow = 0;
		break;
#endif
	case VERIFY_6:
	case VERIFY:
	case VERIFY_12:
	case VERIFY_16:
		if ((cmd->cdb[1] & BYTCHK) == 0) {
			cmd->bufflen = 0;
			cmd->data_direction = SCST_DATA_NONE;
			fixed = 0;
		}
		break;
	default:
		/* It's all good */
		break;
	}

	if (fixed) {
		/* 
		 * No need for locks here, since *_detach() can not be
		 * called, when there are existing commands.
		 */
		disk = (struct disk_params *)cmd->dev->dh_priv;
		cmd->bufflen = info_cdb->transfer_len * disk->sector_size;
	}

	TRACE_DBG("res %d bufflen %zd direct %d",
	      res, cmd->bufflen, cmd->data_direction);

	TRACE_EXIT_RES(res);
	return res;
}

/********************************************************************
 *  Function:  disk_done
 *
 *  Argument:  
 *
 *  Returns :  
 *
 *  Description:  This is the completion routine for the command,
 *                it is used to extract any necessary information
 *                about a command. 
 ********************************************************************/
int disk_done(struct scst_cmd *cmd)
{
	int opcode = cmd->cdb[0];
	int masked_status = cmd->masked_status;
	struct disk_params *disk;
	int res = SCST_CMD_STATE_DEFAULT;

	TRACE_ENTRY();

	if (unlikely(cmd->sg == NULL))
		goto out;

	/*
	 * SCST sets good defaults for cmd->tgt_resp_flags and cmd->resp_data_len
	 * based on cmd->masked_status and cmd->data_direction, therefore change
	 * them only if necessary
	 */

	if ((masked_status == GOOD) || (masked_status == CONDITION_GOOD)) {
		switch (opcode) {
		case READ_CAPACITY:
		{
			/* Always keep track of disk capacity */
			int buffer_size;
			/* 
			 * To force the compiler not to optimize it out to keep
			 * disk->sector_size access atomic
			 */
			volatile int sector_size;
			uint8_t *buffer;
			buffer_size = scst_get_buf_first(cmd, &buffer);
			if (unlikely(buffer_size <= 0)) {
				PRINT_ERROR_PR("%s: Unable to get the buffer",
					__FUNCTION__);
				scst_set_busy(cmd);
				goto out;
			}

			/* 
			 * No need for locks here, since *_detach() can not be
			 * called, when there are existing commands.
			 */
			disk = (struct disk_params *)cmd->dev->dh_priv;
			sector_size =
			    ((buffer[4] << 24) | (buffer[5] << 16) |
			     (buffer[6] << 8) | (buffer[7] << 0));
			if (!sector_size)
				sector_size = 512;
			disk->sector_size = sector_size;
			TRACE_DBG("Sector size is %i", disk->sector_size);
			
			scst_put_buf(cmd, buffer);
			break;
		}
		default:
			/* It's all good */
			break;
		}
	}

	TRACE_DBG("cmd->tgt_resp_flags=%x, cmd->resp_data_len=%d, "
	      "res=%d", cmd->tgt_resp_flags, cmd->resp_data_len, res);

out:
	TRACE_EXIT_RES(res);
	return res;
}

/********************************************************************
 *  Function:  disk_exec
 *
 *  Argument:  
 *
 *  Returns :  
 *
 *  Description:  Make SCST do nothing for data READs and WRITES.
 *                Intended for raw line performance testing
 ********************************************************************/
int disk_exec(struct scst_cmd *cmd)
{
	int res = SCST_EXEC_NOT_COMPLETED;
	int opcode = cmd->cdb[0];

	TRACE_ENTRY();

	switch (opcode) {
	case WRITE_6:
	case WRITE_10:
	case WRITE_12:
	case WRITE_16:
	case READ_6:
	case READ_10:
	case READ_12:
	case READ_16:
		res = SCST_EXEC_COMPLETED;
		cmd->status = 0;
		cmd->masked_status = 0;
		cmd->msg_status = 0;
		cmd->host_status = DID_OK;
		cmd->driver_status = 0;
		cmd->completed = 1;
		cmd->scst_cmd_done(cmd, SCST_CMD_STATE_DEFAULT);
		break;
	}

	TRACE_EXIT_RES(res);
	return res;
}

MODULE_LICENSE("GPL");
