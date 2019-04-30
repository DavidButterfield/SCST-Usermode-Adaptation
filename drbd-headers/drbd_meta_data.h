#ifndef DRBD_META_DATA_H
#define DRBD_META_DATA_H

#ifdef __KERNEL__
#define be_u64 __be64
#define be_u32 __be32
#define be_s32 __be32
#define be_u16 __be16
#else
#define be_u64 struct { uint64_t be; }
#define be_u32 struct { uint32_t be; }
#define be_s32 struct { int32_t be; }
#define be_u16 struct { uint16_t be; }
#endif

struct peer_dev_md_on_disk_9 {
	be_u64 bitmap_uuid;
	be_u64 bitmap_dagtag;
	be_u32 flags;
	be_s32 bitmap_index;
	be_u32 reserved_u32[2];
} __packed;

struct meta_data_on_disk_9 {
	be_u64 effective_size;    /* last agreed size */
	be_u64 current_uuid;
	be_u64 reserved_u64[4];   /* to have the magic at the same position as in v07, and v08 */
	be_u64 device_uuid;
	be_u32 flags;             /* MDF */
	be_u32 magic;
	be_u32 md_size_sect;
	be_u32 al_offset;         /* offset to this block */
	be_u32 al_nr_extents;     /* important for restoring the AL */
	be_u32 bm_offset;         /* offset to the bitmap, from here */
	be_u32 bm_bytes_per_bit;  /* BM_BLOCK_SIZE */
	be_u32 la_peer_max_bio_size;   /* last peer max_bio_size */
	be_u32 bm_max_peers;
	be_s32 node_id;

	/* see al_tr_number_to_on_disk_sector() */
	be_u32 al_stripes;
	be_u32 al_stripe_size_4k;

	be_u32 reserved_u32[2];

	struct peer_dev_md_on_disk_9 peers[DRBD_PEERS_MAX];
	be_u64 history_uuids[HISTORY_UUIDS];

	char padding[0] __attribute__((aligned(4096)));
} __packed;

/* Attention, these two are defined in drbd_int.h as well! */
#define AL_UPDATES_PER_TRANSACTION 64
#define AL_CONTEXT_PER_TRANSACTION 919

enum al_transaction_types {
	AL_TR_UPDATE = 0,
	AL_TR_INITIALIZED = 0xffff
};
/* all fields on disc in big endian */
struct __packed al_transaction_on_disk {
	/* don't we all like magic */
	be_u32	magic;

	/* to identify the most recent transaction block
	 * in the on disk ring buffer */
	be_u32	tr_number;

	/* checksum on the full 4k block, with this field set to 0. */
	be_u32	crc32c;

	/* type of transaction, special transaction types like:
	 * purge-all, set-all-idle, set-all-active, ... to-be-defined
	 * see also enum al_transaction_types */
	be_u16	transaction_type;

	/* we currently allow only a few thousand extents,
	 * so 16bit will be enough for the slot number. */

	/* how many updates in this transaction */
	be_u16	n_updates;

	/* maximum slot number, "al-extents" in drbd.conf speak.
	 * Having this in each transaction should make reconfiguration
	 * of that parameter easier. */
	be_u16	context_size;

	/* slot number the context starts with */
	be_u16	context_start_slot_nr;

	/* Some reserved bytes.  Expected usage is a 64bit counter of
	 * sectors-written since device creation, and other data generation tag
	 * supporting usage */
	be_u32	__reserved[4];

	/* --- 36 byte used --- */

	/* Reserve space for up to AL_UPDATES_PER_TRANSACTION changes
	 * in one transaction, then use the remaining byte in the 4k block for
	 * context information.  "Flexible" number of updates per transaction
	 * does not help, as we have to account for the case when all update
	 * slots are used anyways, so it would only complicate code without
	 * additional benefit.
	 */
	be_u16	update_slot_nr[AL_UPDATES_PER_TRANSACTION];

	/* but the extent number is 32bit, which at an extent size of 4 MiB
	 * allows to cover device sizes of up to 2**54 Byte (16 PiB) */
	be_u32	update_extent_nr[AL_UPDATES_PER_TRANSACTION];

	/* --- 420 bytes used (36 + 64*6) --- */

	/* 4096 - 420 = 3676 = 919 * 4 */
	be_u32	context[AL_CONTEXT_PER_TRANSACTION];
};

#undef be_u64
#undef be_u32
#undef be_s32
#undef be_u16

#endif
