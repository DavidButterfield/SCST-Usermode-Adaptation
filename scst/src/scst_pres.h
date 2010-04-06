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

#ifndef SCST_PRES_H_
#define SCST_PRES_H_

#define PR_REGISTER				0x00
#define PR_RESERVE				0x01
#define PR_RELEASE				0x02
#define PR_CLEAR				0x03
#define PR_PREEMPT				0x04
#define PR_PREEMPT_AND_ABORT			0x05
#define PR_REGISTER_AND_IGNORE			0x06
#define PR_REGISTER_AND_MOVE			0x07

#define PR_READ_KEYS				0x00
#define PR_READ_RESERVATION			0x01
#define PR_REPORT_CAPS				0x02
#define PR_READ_FULL_STATUS			0x03

#define TYPE_UNSPECIFIED			(-1)
#define TYPE_WRITE_EXCLUSIVE			0x01
#define TYPE_EXCLUSIVE_ACCESS 			0x03
#define TYPE_WRITE_EXCLUSIVE_REGONLY		0x05
#define TYPE_EXCLUSIVE_ACCESS_REGONLY		0x06
#define TYPE_WRITE_EXCLUSIVE_ALL		0x07
#define TYPE_EXCLUSIVE_ACCESS_ALL		0x08

/* if (1 << TYPE) is in the mask then this is a valid type */
#define PR_TYPE_SHIFT_MASK	((1 << TYPE_WRITE_EXCLUSIVE) | \
				 (1 << TYPE_EXCLUSIVE_ACCESS) | \
				 (1 << TYPE_WRITE_EXCLUSIVE_REGONLY) | \
				 (1 << TYPE_EXCLUSIVE_ACCESS_REGONLY) | \
				 (1 << TYPE_WRITE_EXCLUSIVE_ALL))

#define SCOPE_LU				0x00

#ifndef CONFIG_SCST_PROC
int scst_pr_check_pr_path(void);
#endif

void scst_pr_init_dev(struct scst_device *dev);
void scst_pr_clear_dev(struct scst_device *dev);

void scst_pr_init_tgt_dev(struct scst_tgt_dev *tgt_dev);
void scst_pr_clear_tgt_dev(struct scst_tgt_dev *tgt_dev);

bool scst_pr_crh_case(struct scst_cmd *cmd);
bool scst_pr_is_cmd_allowed(struct scst_cmd *cmd);

void scst_pr_register(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_register_and_ignore(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);
void scst_pr_register_and_move(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);
void scst_pr_reserve(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_release(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_clear(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_preempt(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_preempt_and_abort(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);

void scst_pr_read_keys(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_read_reservation(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);
void scst_pr_report_caps(struct scst_cmd *cmd, uint8_t *buffer, int buffer_size);
void scst_pr_read_full_status(struct scst_cmd *cmd, uint8_t *buffer,
	int buffer_size);

#endif /* SCST_PRES_H_ */
