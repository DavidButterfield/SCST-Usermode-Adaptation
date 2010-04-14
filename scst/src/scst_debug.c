/*
 *  scst_debug.c
 *
 *  Copyright (C) 2004 - 2010 Vladislav Bolkhovitin <vst@vlnb.net>
 *  Copyright (C) 2004 - 2005 Leonid Stoljar
 *  Copyright (C) 2007 - 2010 ID7 Ltd.
 *
 *  Contains helper functions for execution tracing and error reporting.
 *  Intended to be included in main .c file.
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

#include "scst.h"
#include "scst_debug.h"

#if defined(CONFIG_SCST_DEBUG) || defined(CONFIG_SCST_TRACING)

#define TRACE_BUF_SIZE    512

static char trace_buf[TRACE_BUF_SIZE];
static DEFINE_SPINLOCK(trace_buf_lock);

static inline int get_current_tid(void)
{
	/* Code should be the same as in sys_gettid() */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
	return current->pid;
#else
	if (in_interrupt()) {
		/*
		 * Unfortunately, task_pid_vnr() isn't IRQ-safe, so otherwise
		 * it can oops. ToDo.
		 */
		return 0;
	}
	return task_pid_vnr(current);
#endif
}

int debug_print_prefix(unsigned long trace_flag,
	const char *prefix, const char *func, int line)
{
	int i = 0;
	unsigned long flags;
	int pid = get_current_tid();

	spin_lock_irqsave(&trace_buf_lock, flags);

	trace_buf[0] = '\0';

	if (trace_flag & TRACE_PID)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE, "[%d]: ", pid);
	if (prefix != NULL)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%s: ",
			      prefix);
	if (trace_flag & TRACE_FUNCTION)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%s:", func);
	if (trace_flag & TRACE_LINE)
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%i:", line);

	PRINTN(KERN_INFO, "%s", trace_buf);

	spin_unlock_irqrestore(&trace_buf_lock, flags);

	return i;
}
EXPORT_SYMBOL(debug_print_prefix);

void debug_print_buffer(const void *data, int len)
{
	int z, z1, i;
	const unsigned char *buf = (const unsigned char *) data;
	unsigned long flags;

	if (buf == NULL)
		return;

	spin_lock_irqsave(&trace_buf_lock, flags);

	PRINT(KERN_INFO, " (h)___0__1__2__3__4__5__6__7__8__9__A__B__C__D__E__F");
	for (z = 0, z1 = 0, i = 0; z < len; z++) {
		if (z % 16 == 0) {
			if (z != 0) {
				i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i,
					      " ");
				for (; (z1 < z) && (i < TRACE_BUF_SIZE - 1);
				     z1++) {
					if ((buf[z1] >= 0x20) &&
					    (buf[z1] < 0x80))
						trace_buf[i++] = buf[z1];
					else
						trace_buf[i++] = '.';
				}
				trace_buf[i] = '\0';
				PRINT(KERN_INFO, "%s", trace_buf);
				i = 0;
			}
			i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i,
				      "%4x: ", z);
		}
		i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "%02x ",
			      buf[z]);
	}

	i += snprintf(&trace_buf[i], TRACE_BUF_SIZE - i, "  ");
	for (; (z1 < z) && (i < TRACE_BUF_SIZE - 1); z1++) {
		if ((buf[z1] > 0x20) && (buf[z1] < 0x80))
			trace_buf[i++] = buf[z1];
		else
			trace_buf[i++] = '.';
	}
	trace_buf[i] = '\0';

	PRINT(KERN_INFO, "%s", trace_buf);

	spin_unlock_irqrestore(&trace_buf_lock, flags);
	return;
}
EXPORT_SYMBOL(debug_print_buffer);

#ifdef CONFIG_SCST_DEBUG

const char *debug_transport_id_to_initiator_name(const uint8_t *transport_id)
{
	/*
	 * No external protection, because it's acceptable if the name
	 * corrupted in the debug logs because of the race for this
	 * buffer.
	 */
	static char name_bufs[NR_CPUS][256];
	char *name_buf;
	unsigned long flags;

	sBUG_ON(transport_id == NULL); /* better to catch it not under lock */

	spin_lock_irqsave(&trace_buf_lock, flags);

	name_buf = name_bufs[smp_processor_id()];

	/*
	 * To prevent external racing with us users from accidentally
	 * missing their NULL terminator.
	 */
	memset(name_buf, 0, sizeof(name_buf));
	smp_mb();

	switch (transport_id[0] & 0x0f) {
	case SCSI_TRANSPORTID_PROTOCOLID_ISCSI:
		scnprintf(name_buf, sizeof(name_buf), "%s",
			&transport_id[4]);
		break;
	case SCSI_TRANSPORTID_PROTOCOLID_FCP2:
		scnprintf(name_buf, sizeof(name_buf),
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			transport_id[8], transport_id[9],
			transport_id[10], transport_id[11],
			transport_id[12], transport_id[13],
			transport_id[14], transport_id[15]);
		break;
	case SCSI_TRANSPORTID_PROTOCOLID_SPI5:
		scnprintf(name_buf, sizeof(name_buf),
			"%x:%x", be16_to_cpu((uint16_t)transport_id[2]),
			be16_to_cpu((uint16_t)transport_id[6]));
		break;
	case SCSI_TRANSPORTID_PROTOCOLID_SRP:
		scnprintf(name_buf, sizeof(name_buf),
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			transport_id[8], transport_id[9],
			transport_id[10], transport_id[11],
			transport_id[12], transport_id[13],
			transport_id[14], transport_id[15],
			transport_id[16], transport_id[17],
			transport_id[18], transport_id[19],
			transport_id[20], transport_id[21],
			transport_id[22], transport_id[23]);
		break;
	case SCSI_TRANSPORTID_PROTOCOLID_SAS:
		scnprintf(name_buf, sizeof(name_buf),
			"%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
			transport_id[4], transport_id[5],
			transport_id[6], transport_id[7],
			transport_id[8], transport_id[9],
			transport_id[10], transport_id[11]);
		break;
	default:
		scnprintf(name_buf, sizeof(name_buf),
			"(Not known protocol ID %x)", transport_id[0] & 0x0f);
		break;
	}

	spin_unlock_irqrestore(&trace_buf_lock, flags);

	return name_buf;
}

#endif /* CONFIG_SCST_DEBUG */

#endif /* CONFIG_SCST_DEBUG || CONFIG_SCST_TRACING */
