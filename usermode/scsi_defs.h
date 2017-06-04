/*
 * Additional values not defined by other headers, they
 * seem a little incomplete.
 *
 * Find codes in the various SCSI specs.
 * BTW sense codes are at www.t10.org/lists/asc-num.txt
 *
 */
#ifndef __TCMU_SCSI_DEFS
#define __TCMU_SCSI_DEFS
#undef WRITE_VERIFY_16

/*
 * SCSI Opcodes
 */
#define READ_FORMAT_CAPACITIES          0x23
#define UNMAP                           0x42
#define GET_CONFIGURATION               0x46
#define READ_DISC_INFORMATION           0x51
#define MODE_SELECT_10                  0x55
#define MODE_SENSE_10                   0x5a
#define READ_16                         0x88
#define COMPARE_AND_WRITE               0x89
#define WRITE_16                        0x8a
#define WRITE_VERIFY_16                 0x8e
#define SYNCHRONIZE_CACHE_16            0x91
#define WRITE_SAME_16                   0x93
#define SERVICE_ACTION_IN_16            0x9e
#define READ_DVD_STRUCTURE              0xad
#define MECHANISM_STATUS                0xbd
#define MAINTENANCE_IN			0xa3
#define MAINTENANCE_OUT			0xa4
#define MI_REPORT_TARGET_PGS		0x0a
#define MO_SET_TARGET_PGS		0x0a

/*
 * Service action opcodes
 */
#define READ_CAPACITY_16		0x10

#ifndef _SCSI_PROTO_H_	// else error: redeclaration of ‘enum scsi_protocol’
/* SCSI protocols; these are taken from SPC-3 section 7.5 */
enum scsi_protocol {
	SCSI_PROTOCOL_FCP = 0,	/* Fibre Channel */
	SCSI_PROTOCOL_SPI = 1,	/* parallel SCSI */
	SCSI_PROTOCOL_SSA = 2,	/* Serial Storage Architecture - Obsolete */
	SCSI_PROTOCOL_SBP = 3,	/* firewire */
	SCSI_PROTOCOL_SRP = 4,	/* Infiniband RDMA */
	SCSI_PROTOCOL_ISCSI = 5,
	SCSI_PROTOCOL_SAS = 6,
	SCSI_PROTOCOL_ADT = 7,	/* Media Changers */
	SCSI_PROTOCOL_ATA = 8,
	SCSI_PROTOCOL_UNSPEC = 0xf, /* No specific protocol */
};
#endif

/*
 *  SCSI Architecture Model (SAM) Status codes. Taken from SAM-3 draft
 *  T10/1561-D Revision 4 Draft dated 7th November 2002.
 */
#define SAM_STAT_GOOD			0x00
#define SAM_STAT_CHECK_CONDITION	0x02
#define SAM_STAT_CONDITION_MET		0x04
#define SAM_STAT_BUSY			0x08
#define SAM_STAT_INTERMEDIATE		0x10
#define SAM_STAT_INTERMEDIATE_CONDITION_MET 0x14
#define SAM_STAT_RESERVATION_CONFLICT	0x18
#define SAM_STAT_COMMAND_TERMINATED	0x22        /* obsolete in SAM-3 */
#define SAM_STAT_TASK_SET_FULL		0x28
#define SAM_STAT_ACA_ACTIVE		0x30
#define SAM_STAT_TASK_ABORTED		0x40

/*
 * Sense codes
 */
#define ASC_NOT_READY_FORMAT_IN_PROGRESS        0x0404
#define ASC_PORT_IN_STANDBY			0x040B
#define ASC_READ_ERROR                          0x1100
#define ASC_WRITE_ERROR                         0x0C00
#define ASC_PARAMETER_LIST_LENGTH_ERROR         0x1a00
#define ASC_MISCOMPARE_DURING_VERIFY_OPERATION  0x1d00
#define ASC_LBA_OUT_OF_RANGE                    0x2100
#define ASC_INVALID_FIELD_IN_CDB                0x2400
#define ASC_INVALID_FIELD_IN_PARAMETER_LIST     0x2600
#define ASC_CANT_WRITE_INCOMPATIBLE_FORMAT      0x3005
#define ASC_SAVING_PARAMETERS_NOT_SUPPORTED     0x3900
#define ASC_INTERNAL_TARGET_FAILURE             0x4400
#define ASC_STPG_CMD_FAILED			0x670A


#define ALUA_ACCESS_STATE_OPTIMIZED		0x0
#define ALUA_ACCESS_STATE_NON_OPTIMIZED		0x1
#define ALUA_ACCESS_STATE_STANDBY		0x2
#define ALUA_ACCESS_STATE_UNAVAILABLE		0x3
#define ALUA_ACCESS_STATE_LBA_DEPENDENT		0x4
#define ALUA_ACCESS_STATE_OFFLINE		0xe
#define ALUA_ACCESS_STATE_TRANSITIONING		0xf

#define ALUA_SUP_OPTIMIZED	0x01
#define ALUA_SUP_NON_OPTIMIZED	0x02
#define ALUA_SUP_STANDBY	0x04
#define ALUA_SUP_UNAVAILABLE	0x08
#define ALUA_SUP_LBA_DEPENDENT	0x10
#define ALUA_SUP_OFFLINE	0x40
#define ALUA_SUP_TRANSITIONING	0x80

#define TPGS_ALUA_NONE		0x00
#define TPGS_ALUA_IMPLICIT	0x10
#define TPGS_ALUA_EXPLICIT	0x20

#define ALUA_STAT_NONE				0x00
#define ALUA_STAT_ALTERED_BY_EXPLICIT_STPG	0x01
#define ALUA_STAT_ALTERED_BY_IMPLICIT_ALUA	0x02

#endif
