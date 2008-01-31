/*
 * QLogic Fibre Channel HBA Driver
 * Copyright (c)  2003-2005 QLogic Corporation
 *
 * See LICENSE.qla2xxx for copyright and licensing details.
 */
#include "qla_def.h"

#include <linux/vmalloc.h>
#include <linux/delay.h>
#include <linux/version.h>

#ifdef FC_TARGET_SUPPORT
#include "qla2x_tgt.h"
#include <linux/ctype.h>
#endif

/* SYSFS attributes --------------------------------------------------------- */

#if defined(FC_TARGET_SUPPORT)

int
qla2x00_mailbox_command(scsi_qla_host_t *ha, mbx_cmd_t *mcp);

static ssize_t
qla2x00_show_tgt_enabled(struct class_device *cdev, char *buffer)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	ulong max_size = PAGE_SIZE;
	ulong size;

	size = snprintf(buffer, max_size, "%d\n", 
			ha->flags.enable_target_mode);

	return size;
}

static ssize_t
qla2x00_store_tgt_enabled(struct class_device *cdev,
			  const char *buffer, size_t size)
{
	struct scsi_qla_host *ha = to_qla_host(class_to_shost(cdev));
	int force = 0;

	if (buffer == NULL) {
		return size;
	}

	if (qla_target.tgt_host_action == NULL) {
		printk(KERN_INFO "%s: not acting for lack of target driver\n",
		       __func__);
		return size;
	}

	if ((size > 1) && (buffer[1] == 'f')) {
		force = 1;
		printk(KERN_DEBUG "%s: forcing the matter\n", __func__);
	}

	switch (buffer[0]) {
	case '0' : 
		if ((ha->flags.enable_target_mode) || force) {
			qla_target.tgt_host_action(ha, DISABLE_TARGET_MODE);
			msleep_interruptible(10*1000);
		}
		break;
	case '1' :
		if ((ha->flags.enable_target_mode == 0) || force) {
			qla_target.tgt_host_action(ha, ENABLE_TARGET_MODE);
			msleep_interruptible(10*1000);
		}
		break;
	default:
		printk("%s: Requested action not understood: %s\n",
		       __func__, buffer);
		break;
	}

	if ((size > 2) && (buffer[2] == 'r')) {
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	}
	
	return size;
}

static CLASS_DEVICE_ATTR(target_mode_enabled, 
			 S_IRUGO|S_IWUSR, 
			 qla2x00_show_tgt_enabled,
			 qla2x00_store_tgt_enabled);

static ssize_t
qla2x00_show_resource_counts(struct class_device *cdev, char *buffer)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	ulong max_size = PAGE_SIZE;
	ulong size;
	mbx_cmd_t mc;
	int rval;

	mc.mb[0] = MBC_GET_RESOURCE_COUNTS;
	mc.out_mb = MBX_0;
	mc.in_mb = MBX_0|MBX_1|MBX_2;
        mc.tov = 30;
        mc.flags = 0;

	rval = qla2x00_mailbox_command(ha, &mc);

	if (rval != QLA_SUCCESS) {
		size = snprintf(buffer, max_size, 
				"Mailbox Command failed %d, mb %#x", 
				rval, mc.mb[0]);
		goto out;
	}

	size = snprintf(buffer, max_size, 
			"immed_notify\t%d\ncommand\t\t%d\n",
			mc.mb[2], mc.mb[1]);

out:
	return size;
}

static CLASS_DEVICE_ATTR(resource_counts,
			 S_IRUGO,
			 qla2x00_show_resource_counts,
			 NULL);

typedef struct {
	uint8_t port_name[WWN_SIZE];
	uint16_t loop_id;
} port_data_t;

static ssize_t
qla2x00_show_port_database(struct class_device *cdev, char *buffer)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	ulong max_size = PAGE_SIZE;
	ulong size = 0;
	int rval, i;
	uint16_t entries;

	mbx_cmd_t mc;
	dma_addr_t pmap_dma;
	port_data_t *pmap;
	ulong dma_size = 0x100*sizeof(*pmap);
	pmap = (port_data_t*)dma_alloc_coherent(&ha->pdev->dev, dma_size, 
						&pmap_dma, GFP_KERNEL);
	if (pmap == NULL) {
		size = snprintf(buffer, max_size, "DMA Alloc failed of %ld",
				dma_size);
		goto out;
	}

	mc.mb[0] = MBC_PORT_NODE_NAME_LIST;
	mc.mb[1] = BIT_1;
	mc.mb[2] = MSW(pmap_dma);
	mc.mb[3] = LSW(pmap_dma);
	mc.mb[6] = MSW(MSD(pmap_dma));
	mc.mb[7] = LSW(MSD(pmap_dma));
	mc.out_mb = MBX_0|MBX_1|MBX_2|MBX_3|MBX_6|MBX_7;
	mc.in_mb = MBX_0|MBX_1;
        mc.tov = 30;
        mc.flags = MBX_DMA_IN;

	rval = qla2x00_mailbox_command(ha, &mc);

	if (rval != QLA_SUCCESS) {
		size = snprintf(buffer, max_size, 
				"Mailbox Command failed %d, mb0 %#x mb1 %#x\n", 
				rval, mc.mb[0], mc.mb[1]);
		goto out_free;
	}

	entries = le16_to_cpu(mc.mb[1])/sizeof(*pmap);
	
	size += snprintf(buffer+size, max_size-size, 
			 "Port Name List (%#04x) returned %d bytes\nL_ID WWPN\n",
			 MBC_PORT_NODE_NAME_LIST, le16_to_cpu(mc.mb[1]));

	for (i = 0; (i < entries) && (size < max_size); ++i) {
		size += snprintf(buffer+size, max_size-size, 
				 "%04x %02x%02x%02x%02x%02x%02x%02x%02x\n",
				 le16_to_cpu(pmap[i].loop_id),
				 pmap[i].port_name[7], pmap[i].port_name[6], 
				 pmap[i].port_name[5], pmap[i].port_name[4], 
				 pmap[i].port_name[3], pmap[i].port_name[2], 
				 pmap[i].port_name[1], pmap[i].port_name[0]);
	}

out_free:
	dma_free_coherent(&ha->pdev->dev, dma_size, pmap, pmap_dma);	


	if (size < max_size) {
		/*id_list_t *pc; */
		char *id_iter;
		int flags;
		struct gid_list_info *gid;

		spin_lock_irqsave(&ha->hardware_lock, flags);
		/* Get list of logged in devices. */
		memset(ha->gid_list, 0, GID_LIST_SIZE);
		spin_unlock_irqrestore(&ha->hardware_lock, flags);
		rval = qla2x00_get_id_list(ha, ha->gid_list, ha->gid_list_dma,
					   &entries);
		if (rval != QLA_SUCCESS) {
			size += snprintf(buffer+size, max_size-size, 
					 "qla2x00_get_id_list failed: %d",
					rval);
			goto get_id_failed;
		}
		
		size += snprintf(buffer+size, max_size-size, 
				 "\nGet ID List (0x007C) returned %d entries\n"
				 "L_ID PortID\n",
				 entries);
		
		id_iter = (char *)ha->gid_list;
		for (i = 0; (i < entries) && (size < max_size); ++i) {
			gid = (struct gid_list_info *)id_iter;
			if (IS_QLA2100(ha) || IS_QLA2200(ha)) {
				size += snprintf(buffer+size, max_size-size,
						 " %02x  %02x%02x%02x\n",
						 gid->loop_id_2100,
						 gid->domain,
						 gid->area,
						 gid->al_pa);

			} else {
				size += snprintf(buffer+size, max_size-size,
						 "%04x %02x%02x%02x %02x\n",
						 le16_to_cpu(gid->loop_id),
						 gid->domain,
						 gid->area,
						 gid->al_pa,
						 gid->loop_id_2100);
				
			}
			id_iter += ha->gid_list_info_size;
		}
	}
get_id_failed:

	if (size < max_size) {
		fc_port_t *fcport;
		char * state;
		char port_type[] = "URSBIT";
		
		size += snprintf(buffer+size, max_size-size, 
				 "\nfc_ports database\n");

		list_for_each_entry(fcport, &ha->fcports, list) {
			if (size >= max_size)
				goto out;
			switch (atomic_read(&fcport->state)) {
			case FCS_UNCONFIGURED : state = "Unconfigured"; break;
			case FCS_DEVICE_DEAD : state = "Dead"; break;
			case FCS_DEVICE_LOST : state = "Lost"; break;
			case FCS_ONLINE	: state = "Online"; break;
			case FCS_NOT_SUPPORTED : state = "Not Supported"; break;
			case FCS_FAILOVER : state = "Failover"; break;
			case FCS_FAILOVER_FAILED : state = "Failover Failed"; break;
			default: state = "Unknown"; break;
			}
			
			size += snprintf(buffer+size, max_size-size, 
					 "%04x %02x%02x%02x "
					 "%02x%02x%02x%02x%02x%02x%02x%02x "
					 "%c %s\n",
					 fcport->loop_id,
					 fcport->d_id.b.domain,
					 fcport->d_id.b.area,
					 fcport->d_id.b.al_pa,
					 fcport->port_name[0], fcport->port_name[1], 
					 fcport->port_name[2], fcport->port_name[3], 
					 fcport->port_name[4], fcport->port_name[5], 
					 fcport->port_name[6], fcport->port_name[7],
					 port_type[fcport->port_type], state);
		}
	}
out:
	return size;
}

extern int qla2x00_configure_loop(scsi_qla_host_t *);
extern int qla2x00_configure_local_loop(scsi_qla_host_t *);
extern int qla2x00_configure_fabric(scsi_qla_host_t *);

static ssize_t
qla2x00_update_portdb(struct class_device *cdev, const char *buffer, size_t size)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	unsigned char reading = '0';
	
	switch (reading) {
	case '2':
		qla2x00_configure_loop(ha);
		break;

	case 'l':
	case 'L':
		qla2x00_configure_local_loop(ha);
		break;

	case 'f':
	case 'F':
		qla2x00_configure_fabric(ha);

	default:
		set_bit(LOOP_RESYNC_NEEDED, &ha->dpc_flags);
		break;
	}

	return size;
}


static CLASS_DEVICE_ATTR(port_database,
			 S_IRUGO|S_IWUSR,
			 qla2x00_show_port_database,
			 qla2x00_update_portdb);
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_read_fw_dump(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_read_fw_dump(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (ha->fw_dump_reading == 0)
		return 0;
	if (off > ha->fw_dump_buffer_len)
		return 0;
	if (off + count > ha->fw_dump_buffer_len)
		count = ha->fw_dump_buffer_len - off;

	memcpy(buf, &ha->fw_dump_buffer[off], count);

	return (count);
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_write_fw_dump(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_write_fw_dump(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int reading;
	uint32_t dump_size;

	if (off != 0)
		return (0);

	reading = simple_strtol(buf, NULL, 10);
	switch (reading) {
	case 0:
		if (ha->fw_dump_reading == 1) {
			qla_printk(KERN_INFO, ha,
			    "Firmware dump cleared on (%ld).\n",
			    ha->host_no);

			vfree(ha->fw_dump_buffer);
			if (!IS_QLA24XX(ha) && !IS_QLA54XX(ha))
				free_pages((unsigned long)ha->fw_dump,
				    ha->fw_dump_order);

			ha->fw_dump_reading = 0;
			ha->fw_dump_buffer = NULL;
			ha->fw_dump = NULL;
			ha->fw_dumped = 0;
		}
		break;
	case 1:
		if ((ha->fw_dump == NULL) && (ha->isp_ops.fw_dump != NULL))
			ha->isp_ops.fw_dump(ha, 0);	

		if ((ha->fw_dump || ha->fw_dumped) && !ha->fw_dump_reading) {
			ha->fw_dump_reading = 1;

			if (IS_QLA24XX(ha) || IS_QLA54XX(ha))
				dump_size = FW_DUMP_SIZE_24XX;
			else {
				dump_size = FW_DUMP_SIZE_1M;
				if (ha->fw_memory_size < 0x20000)
					dump_size = FW_DUMP_SIZE_128K;
				else if (ha->fw_memory_size < 0x80000)
					dump_size = FW_DUMP_SIZE_512K;
			}
			ha->fw_dump_buffer = (char *)vmalloc(dump_size);
			if (ha->fw_dump_buffer == NULL) {
				qla_printk(KERN_WARNING, ha,
				    "Unable to allocate memory for firmware "
				    "dump buffer (%d).\n", dump_size);

				ha->fw_dump_reading = 0;
				return (count);
			}
			qla_printk(KERN_INFO, ha,
			    "Firmware dump ready for read on (%ld).\n",
			    ha->host_no);
			memset(ha->fw_dump_buffer, 0, dump_size);
			ha->isp_ops.ascii_fw_dump(ha);
			ha->fw_dump_buffer_len = strlen(ha->fw_dump_buffer);
		}
		break;
	}
	return (count);
}

static struct bin_attribute sysfs_fw_dump_attr = {
	.attr = {
		.name = "fw_dump",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_fw_dump,
	.write = qla2x00_sysfs_write_fw_dump,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_read_nvram(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_read_nvram(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	unsigned long	flags;

	if (!capable(CAP_SYS_ADMIN) || off != 0)
		return 0;

	/* Read NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->isp_ops.read_nvram(ha, (uint8_t *)buf, ha->nvram_base,
	    ha->nvram_size);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return ha->nvram_size;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_write_nvram(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_write_nvram(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	unsigned long	flags;
	uint16_t	cnt;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->nvram_size)
		return 0;

	/* Checksum NVRAM. */
	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		uint32_t *iter;
		uint32_t chksum;

		iter = (uint32_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < ((count >> 2) - 1); cnt++)
			chksum += le32_to_cpu(*iter++);
		chksum = ~chksum + 1;
		*iter = cpu_to_le32(chksum);
	} else {
		uint8_t *iter;
		uint8_t chksum;

		iter = (uint8_t *)buf;
		chksum = 0;
		for (cnt = 0; cnt < count - 1; cnt++)
			chksum += *iter++;
		chksum = ~chksum + 1;
		*iter = chksum;
	}

	/* Write NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->isp_ops.write_nvram(ha, (uint8_t *)buf, ha->nvram_base, count);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return (count);
}

static struct bin_attribute sysfs_nvram_attr = {
	.attr = {
		.name = "nvram",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 512,
	.read = qla2x00_sysfs_read_nvram,
	.write = qla2x00_sysfs_write_nvram,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_read_optrom(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_read_optrom(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (ha->optrom_state != QLA_SREADING)
		return 0;
	if (off > ha->optrom_size)
		return 0;
	if (off + count > ha->optrom_size)
		count = ha->optrom_size - off;

	memcpy(buf, &ha->optrom_buffer[off], count);

	return count;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_write_optrom(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_write_optrom(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));

	if (ha->optrom_state != QLA_SWRITING)
		return -EINVAL;
	if (off > ha->optrom_size)
		return -ERANGE;
	if (off + count > ha->optrom_size)
		count = ha->optrom_size - off;

	memcpy(&ha->optrom_buffer[off], buf, count);

	return count;
}

static struct bin_attribute sysfs_optrom_attr = {
	.attr = {
		.name = "optrom",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = OPTROM_SIZE_24XX,
	.read = qla2x00_sysfs_read_optrom,
	.write = qla2x00_sysfs_write_optrom,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_write_optrom_ctl(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_write_optrom_ctl(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	int val;

	if (off)
		return 0;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	switch (val) {
	case 0:
		if (ha->optrom_state != QLA_SREADING &&
		    ha->optrom_state != QLA_SWRITING)
			break;

		ha->optrom_state = QLA_SWAITING;
		vfree(ha->optrom_buffer);
		ha->optrom_buffer = NULL;
		break;
	case 1:
		if (ha->optrom_state != QLA_SWAITING)
			break;

		ha->optrom_state = QLA_SREADING;
		ha->optrom_buffer = (uint8_t *)vmalloc(ha->optrom_size);
		if (ha->optrom_buffer == NULL) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to allocate memory for optrom retrieval "
			    "(%x).\n", ha->optrom_size);

			ha->optrom_state = QLA_SWAITING;
			return count;
		}

		memset(ha->optrom_buffer, 0, ha->optrom_size);
		ha->isp_ops.read_optrom(ha, ha->optrom_buffer, 0,
		    ha->optrom_size);
		break;
	case 2:
		if (ha->optrom_state != QLA_SWAITING)
			break;

		ha->optrom_state = QLA_SWRITING;
		ha->optrom_buffer = (uint8_t *)vmalloc(ha->optrom_size);
		if (ha->optrom_buffer == NULL) {
			qla_printk(KERN_WARNING, ha,
			    "Unable to allocate memory for optrom update "
			    "(%x).\n", ha->optrom_size);

			ha->optrom_state = QLA_SWAITING;
			return count;
		}
		memset(ha->optrom_buffer, 0, ha->optrom_size);
		break;
	case 3:
		if (ha->optrom_state != QLA_SWRITING)
			break;

		ha->isp_ops.write_optrom(ha, ha->optrom_buffer, 0,
		    ha->optrom_size);
		break;
	}
	return count;
}

static struct bin_attribute sysfs_optrom_ctl_attr = {
	.attr = {
		.name = "optrom_ctl",
		.mode = S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.write = qla2x00_sysfs_write_optrom_ctl,
};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_read_vpd(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_read_vpd(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	unsigned long flags;

	if (!capable(CAP_SYS_ADMIN) || off != 0)
		return 0;

	if (!IS_QLA24XX(ha) && !IS_QLA54XX(ha))
		return -ENOTSUPP;

	/* Read NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->isp_ops.read_nvram(ha, (uint8_t *)buf, ha->vpd_base, ha->vpd_size);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return ha->vpd_size;
}

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23))
static ssize_t
qla2x00_sysfs_write_vpd(struct kobject *kobj, char *buf, loff_t off,
    size_t count)
#else
static ssize_t
qla2x00_sysfs_write_vpd(struct kobject *kobj, struct bin_attribute *attr,
    char *buf, loff_t off, size_t count)
#endif
{
	struct scsi_qla_host *ha = to_qla_host(dev_to_shost(container_of(kobj,
	    struct device, kobj)));
	unsigned long flags;

	if (!capable(CAP_SYS_ADMIN) || off != 0 || count != ha->vpd_size)
		return 0;

	if (!IS_QLA24XX(ha) && !IS_QLA54XX(ha))
		return -ENOTSUPP;

	/* Write NVRAM. */
	spin_lock_irqsave(&ha->hardware_lock, flags);
	ha->isp_ops.write_nvram(ha, (uint8_t *)buf, ha->vpd_base, count);
	spin_unlock_irqrestore(&ha->hardware_lock, flags);

	return count;
}

static struct bin_attribute sysfs_vpd_attr = {
	.attr = {
		.name = "vpd",
		.mode = S_IRUSR | S_IWUSR,
		.owner = THIS_MODULE,
	},
	.size = 0,
	.read = qla2x00_sysfs_read_vpd,
	.write = qla2x00_sysfs_write_vpd,
};

void
qla2x00_alloc_sysfs_attr(scsi_qla_host_t *ha)
{
	struct Scsi_Host *host = ha->host;
	int ret;

	ret = sysfs_create_bin_file(&host->shost_gendev.kobj, &sysfs_fw_dump_attr);
	if (ret)
		qla_printk(KERN_INFO, ha, "sysfs_create_bin_file() failed: "
			"%d\n", ret);
	ret = sysfs_create_bin_file(&host->shost_gendev.kobj, &sysfs_nvram_attr);
	if (ret)
		qla_printk(KERN_INFO, ha, "sysfs_create_bin_file() failed: "
			"%d\n", ret);
	ret = sysfs_create_bin_file(&host->shost_gendev.kobj, &sysfs_optrom_attr);
	if (ret)
		qla_printk(KERN_INFO, ha, "sysfs_create_bin_file() failed: "
			"%d\n", ret);
	ret = sysfs_create_bin_file(&host->shost_gendev.kobj,
	    &sysfs_optrom_ctl_attr);
	if (ret)
		qla_printk(KERN_INFO, ha, "sysfs_create_bin_file() failed: "
			"%d\n", ret);
	ret = sysfs_create_bin_file(&host->shost_gendev.kobj, &sysfs_vpd_attr);
	if (ret)
		qla_printk(KERN_INFO, ha, "sysfs_create_bin_file() failed: "
			"%d\n", ret);
}

void
qla2x00_free_sysfs_attr(scsi_qla_host_t *ha)
{
	struct Scsi_Host *host = ha->host;

	sysfs_remove_bin_file(&host->shost_gendev.kobj, &sysfs_fw_dump_attr);
	sysfs_remove_bin_file(&host->shost_gendev.kobj, &sysfs_nvram_attr);
	sysfs_remove_bin_file(&host->shost_gendev.kobj, &sysfs_optrom_attr);
	sysfs_remove_bin_file(&host->shost_gendev.kobj,
	    &sysfs_optrom_ctl_attr);
	sysfs_remove_bin_file(&host->shost_gendev.kobj, &sysfs_vpd_attr);

	if (ha->beacon_blink_led == 1)
		ha->isp_ops.beacon_off(ha);
}

/* Scsi_Host attributes. */

static ssize_t
qla2x00_drvr_version_show(struct class_device *cdev, char *buf)
{
	return snprintf(buf, PAGE_SIZE, "%s\n", qla2x00_version_str);
}

static ssize_t
qla2x00_fw_version_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	char fw_str[30];

	return snprintf(buf, PAGE_SIZE, "%s\n",
	    ha->isp_ops.fw_version_str(ha, fw_str));
}

static ssize_t
qla2x00_serial_num_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	uint32_t sn;

	sn = ((ha->serial0 & 0x1f) << 16) | (ha->serial2 << 8) | ha->serial1;
	return snprintf(buf, PAGE_SIZE, "%c%05d\n", 'A' + sn / 100000,
	    sn % 100000);
}

static ssize_t
qla2x00_isp_name_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "ISP%04X\n", ha->pdev->device);
}

static ssize_t
qla2x00_isp_id_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "%04x %04x %04x %04x\n",
	    ha->product_id[0], ha->product_id[1], ha->product_id[2],
	    ha->product_id[3]);
}

static ssize_t
qla2x00_model_name_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "%s\n", ha->model_number);
}

static ssize_t
qla2x00_model_desc_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	return snprintf(buf, PAGE_SIZE, "%s\n",
	    ha->model_desc ? ha->model_desc: "");
}

static ssize_t
qla2x00_pci_info_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	char pci_info[30];

	return snprintf(buf, PAGE_SIZE, "%s\n",
	    ha->isp_ops.pci_info_str(ha, pci_info));
}

static ssize_t
qla2x00_state_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	if (atomic_read(&ha->loop_state) == LOOP_DOWN ||
	    atomic_read(&ha->loop_state) == LOOP_DEAD)
		len = snprintf(buf, PAGE_SIZE, "Link Down\n");
	else if (atomic_read(&ha->loop_state) != LOOP_READY ||
	    test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags) ||
	    test_bit(ISP_ABORT_NEEDED, &ha->dpc_flags))
		len = snprintf(buf, PAGE_SIZE, "Unknown Link State\n");
	else {
		len = snprintf(buf, PAGE_SIZE, "Link Up - ");

		switch (ha->current_topology) {
		case ISP_CFG_NL:
			len += snprintf(buf + len, PAGE_SIZE-len, "Loop\n");
			break;
		case ISP_CFG_FL:
			len += snprintf(buf + len, PAGE_SIZE-len, "FL_Port\n");
			break;
		case ISP_CFG_N:
			len += snprintf(buf + len, PAGE_SIZE-len,
			    "N_Port to N_Port\n");
			break;
		case ISP_CFG_F:
			len += snprintf(buf + len, PAGE_SIZE-len, "F_Port\n");
			break;
		default:
			len += snprintf(buf + len, PAGE_SIZE-len, "Loop\n");
			break;
		}
	}
	return len;
}

static ssize_t
qla2x00_zio_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	switch (ha->zio_mode) {
	case QLA_ZIO_MODE_6:
		len += snprintf(buf + len, PAGE_SIZE-len, "Mode 6\n");
		break;
	case QLA_ZIO_DISABLED:
		len += snprintf(buf + len, PAGE_SIZE-len, "Disabled\n");
		break;
	}
	return len;
}

static ssize_t
qla2x00_zio_store(struct class_device *cdev, const char *buf, size_t count)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int val = 0;
	uint16_t zio_mode;

	if (!IS_ZIO_SUPPORTED(ha))
		return -ENOTSUPP;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val)
		zio_mode = QLA_ZIO_MODE_6;
	else
		zio_mode = QLA_ZIO_DISABLED;

	/* Update per-hba values and queue a reset. */
	if (zio_mode != QLA_ZIO_DISABLED || ha->zio_mode != QLA_ZIO_DISABLED) {
		ha->zio_mode = zio_mode;
		set_bit(ISP_ABORT_NEEDED, &ha->dpc_flags);
	}
	return strlen(buf);
}

static ssize_t
qla2x00_zio_timer_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));

	return snprintf(buf, PAGE_SIZE, "%d us\n", ha->zio_timer * 100);
}

static ssize_t
qla2x00_zio_timer_store(struct class_device *cdev, const char *buf,
    size_t count)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int val = 0;
	uint16_t zio_timer;

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;
	if (val > 25500 || val < 100)
		return -ERANGE;

	zio_timer = (uint16_t)(val / 100);
	ha->zio_timer = zio_timer;

	return strlen(buf);
}

static ssize_t
qla2x00_beacon_show(struct class_device *cdev, char *buf)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int len = 0;

	if (ha->beacon_blink_led)
		len += snprintf(buf + len, PAGE_SIZE-len, "Enabled\n");
	else
		len += snprintf(buf + len, PAGE_SIZE-len, "Disabled\n");
	return len;
}

static ssize_t
qla2x00_beacon_store(struct class_device *cdev, const char *buf,
    size_t count)
{
	scsi_qla_host_t *ha = to_qla_host(class_to_shost(cdev));
	int val = 0;
	int rval;

	if (IS_QLA2100(ha) || IS_QLA2200(ha))
		return -EPERM;

	if (test_bit(ABORT_ISP_ACTIVE, &ha->dpc_flags)) {
		qla_printk(KERN_WARNING, ha,
		    "Abort ISP active -- ignoring beacon request.\n");
		return -EBUSY;
	}

	if (sscanf(buf, "%d", &val) != 1)
		return -EINVAL;

	if (val)
		rval = ha->isp_ops.beacon_on(ha);
	else
		rval = ha->isp_ops.beacon_off(ha);

	if (rval != QLA_SUCCESS)
		count = 0;

	return count;
}

static CLASS_DEVICE_ATTR(driver_version, S_IRUGO, qla2x00_drvr_version_show,
	NULL);
static CLASS_DEVICE_ATTR(fw_version, S_IRUGO, qla2x00_fw_version_show, NULL);
static CLASS_DEVICE_ATTR(serial_num, S_IRUGO, qla2x00_serial_num_show, NULL);
static CLASS_DEVICE_ATTR(isp_name, S_IRUGO, qla2x00_isp_name_show, NULL);
static CLASS_DEVICE_ATTR(isp_id, S_IRUGO, qla2x00_isp_id_show, NULL);
static CLASS_DEVICE_ATTR(model_name, S_IRUGO, qla2x00_model_name_show, NULL);
static CLASS_DEVICE_ATTR(model_desc, S_IRUGO, qla2x00_model_desc_show, NULL);
static CLASS_DEVICE_ATTR(pci_info, S_IRUGO, qla2x00_pci_info_show, NULL);
static CLASS_DEVICE_ATTR(state, S_IRUGO, qla2x00_state_show, NULL);
static CLASS_DEVICE_ATTR(zio, S_IRUGO | S_IWUSR, qla2x00_zio_show,
    qla2x00_zio_store);
static CLASS_DEVICE_ATTR(zio_timer, S_IRUGO | S_IWUSR, qla2x00_zio_timer_show,
    qla2x00_zio_timer_store);
static CLASS_DEVICE_ATTR(beacon, S_IRUGO | S_IWUSR, qla2x00_beacon_show,
    qla2x00_beacon_store);

struct class_device_attribute *qla2x00_host_attrs[] = {
	&class_device_attr_driver_version,
	&class_device_attr_fw_version,
	&class_device_attr_serial_num,
	&class_device_attr_isp_name,
	&class_device_attr_isp_id,
	&class_device_attr_model_name,
	&class_device_attr_model_desc,
	&class_device_attr_pci_info,
	&class_device_attr_state,
	&class_device_attr_zio,
	&class_device_attr_zio_timer,
	&class_device_attr_beacon,
#if defined(FC_TARGET_SUPPORT)
	&class_device_attr_target_mode_enabled,
	&class_device_attr_resource_counts,
	&class_device_attr_port_database,	
#endif
	NULL,
};

/* Host attributes. */

static void
qla2x00_get_host_port_id(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);

	fc_host_port_id(shost) = ha->d_id.b.domain << 16 |
	    ha->d_id.b.area << 8 | ha->d_id.b.al_pa;
}

static void
qla2x00_get_host_speed(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);
	uint32_t speed = 0;

	switch (ha->link_data_rate) {
	case LDR_1GB:
		speed = 1;
		break;
	case LDR_2GB:
		speed = 2;
		break;
	case LDR_4GB:
		speed = 4;
		break;
	}
	fc_host_speed(shost) = speed;
}

static void
qla2x00_get_host_port_type(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);
	uint32_t port_type = FC_PORTTYPE_UNKNOWN;

	switch (ha->current_topology) {
	case ISP_CFG_NL:
		port_type = FC_PORTTYPE_LPORT;
		break;
	case ISP_CFG_FL:
		port_type = FC_PORTTYPE_NLPORT;
		break;
	case ISP_CFG_N:
		port_type = FC_PORTTYPE_PTP;
		break;
	case ISP_CFG_F:
		port_type = FC_PORTTYPE_NPORT;
		break;
	}
	fc_host_port_type(shost) = port_type;
}

static void
qla2x00_get_starget_node_name(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = to_qla_host(host);
	fc_port_t *fcport;
	u64 node_name = 0;

	list_for_each_entry(fcport, &ha->fcports, list) {
		if (starget->id == fcport->os_target_id) {
			node_name = wwn_to_u64(fcport->node_name);
			break;
		}
	}

	fc_starget_node_name(starget) = node_name;
}

static void
qla2x00_get_starget_port_name(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = to_qla_host(host);
	fc_port_t *fcport;
	u64 port_name = 0;

	list_for_each_entry(fcport, &ha->fcports, list) {
		if (starget->id == fcport->os_target_id) {
			port_name = wwn_to_u64(fcport->port_name);
			break;
		}
	}

	fc_starget_port_name(starget) = port_name;
}

static void
qla2x00_get_starget_port_id(struct scsi_target *starget)
{
	struct Scsi_Host *host = dev_to_shost(starget->dev.parent);
	scsi_qla_host_t *ha = to_qla_host(host);
	fc_port_t *fcport;
	uint32_t port_id = ~0U;

	list_for_each_entry(fcport, &ha->fcports, list) {
		if (starget->id == fcport->os_target_id) {
			port_id = fcport->d_id.b.domain << 16 |
			    fcport->d_id.b.area << 8 | fcport->d_id.b.al_pa;
			break;
		}
	}

	fc_starget_port_id(starget) = port_id;
}

static void
qla2x00_get_rport_loss_tmo(struct fc_rport *rport)
{
	struct Scsi_Host *host = rport_to_shost(rport);
	scsi_qla_host_t *ha = to_qla_host(host);

	rport->dev_loss_tmo = ha->port_down_retry_count + 5;
}

static void
qla2x00_set_rport_loss_tmo(struct fc_rport *rport, uint32_t timeout)
{
	struct Scsi_Host *host = rport_to_shost(rport);
	scsi_qla_host_t *ha = to_qla_host(host);

	if (timeout)
		ha->port_down_retry_count = timeout;
	else
		ha->port_down_retry_count = 1;

	rport->dev_loss_tmo = ha->port_down_retry_count + 5;
}

static int
qla2x00_issue_lip(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);

	set_bit(LOOP_RESET_NEEDED, &ha->dpc_flags);
	return 0;
}

static struct fc_host_statistics *
qla2x00_get_fc_host_stats(struct Scsi_Host *shost)
{
	scsi_qla_host_t *ha = to_qla_host(shost);
	int rval;
	uint16_t mb_stat[1];
	link_stat_t stat_buf;
	struct fc_host_statistics *pfc_host_stat;

	pfc_host_stat = &ha->fc_host_stat;
	memset(pfc_host_stat, -1, sizeof(struct fc_host_statistics));

	if (IS_QLA24XX(ha) || IS_QLA54XX(ha)) {
		rval = qla24xx_get_isp_stats(ha, (uint32_t *)&stat_buf,
		    sizeof(stat_buf) / 4, mb_stat);
	} else {
		rval = qla2x00_get_link_status(ha, ha->loop_id, &stat_buf,
		    mb_stat);
	}
	if (rval != 0) {
		qla_printk(KERN_WARNING, ha,
		    "Unable to retrieve host statistics (%d).\n", mb_stat[0]);
		return pfc_host_stat;
	}

	pfc_host_stat->link_failure_count = stat_buf.link_fail_cnt;
	pfc_host_stat->loss_of_sync_count = stat_buf.loss_sync_cnt;
	pfc_host_stat->loss_of_signal_count = stat_buf.loss_sig_cnt;
	pfc_host_stat->prim_seq_protocol_err_count = stat_buf.prim_seq_err_cnt;
	pfc_host_stat->invalid_tx_word_count = stat_buf.inval_xmit_word_cnt;
	pfc_host_stat->invalid_crc_count = stat_buf.inval_crc_cnt;

	return pfc_host_stat;
}

struct fc_function_template qla2xxx_transport_functions = {

	.show_host_node_name = 1,
	.show_host_port_name = 1,
	.show_host_supported_classes = 1,

	.get_host_port_id = qla2x00_get_host_port_id,
	.show_host_port_id = 1,
	.get_host_speed = qla2x00_get_host_speed,
	.show_host_speed = 1,
	.get_host_port_type = qla2x00_get_host_port_type,
	.show_host_port_type = 1,

	.dd_fcrport_size = sizeof(struct fc_port *),
	.show_rport_supported_classes = 1,

	.get_starget_node_name = qla2x00_get_starget_node_name,
	.show_starget_node_name = 1,
	.get_starget_port_name = qla2x00_get_starget_port_name,
	.show_starget_port_name = 1,
	.get_starget_port_id  = qla2x00_get_starget_port_id,
	.show_starget_port_id = 1,

	.get_rport_dev_loss_tmo = qla2x00_get_rport_loss_tmo,
	.set_rport_dev_loss_tmo = qla2x00_set_rport_loss_tmo,
	.show_rport_dev_loss_tmo = 1,

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
	.issue_fc_host_lip = qla2x00_issue_lip,
	.get_fc_host_stats = qla2x00_get_fc_host_stats,
#endif
};

void
qla2x00_init_host_attr(scsi_qla_host_t *ha)
{
	fc_host_node_name(ha->host) = wwn_to_u64(ha->node_name);
	fc_host_port_name(ha->host) = wwn_to_u64(ha->port_name);
	fc_host_supported_classes(ha->host) = FC_COS_CLASS3;
}
