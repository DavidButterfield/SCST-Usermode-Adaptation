#ifndef _SCST_BACKPORT_H_
#define _SCST_BACKPORT_H_

/*
 *  Copyright (C) 2015 SanDisk Corporation
 *
 *  Backports of functions introduced in recent kernel versions.
 *
 *  Please keep the functions in this file sorted according to the name of the
 *  header file in which these have been defined.
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

#include <linux/slab.h>		/* kmalloc() */
#include <linux/writeback.h>	/* sync_page_range() */

/* <asm-generic/barrier.h> */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 16, 0)
#define smp_mb__after_atomic_inc smp_mb__after_atomic
#define smp_mb__after_clear_bit smp_mb__after_atomic
#define smp_mb__before_atomic_dec smp_mb__before_atomic
#define smp_mb__after_atomic_dec smp_mb__after_atomic
#endif

/* <asm-generic/fcntl.h> */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
#ifndef O_DSYNC
#define O_DSYNC O_SYNC
#endif
#endif

/* <linux/blkdev.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 31)
static inline unsigned int queue_max_hw_sectors(struct request_queue *q)
{
	return q->max_hw_sectors;
}
#endif

/* <linux/compiler.h> */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20)
#ifndef __printf
#define __printf(a, b) __attribute__((format(printf,a,b)))
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 21)
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
/*
 * See also patch "Move ACCESS_ONCE() to <linux/compiler.h>" (commit ID
 * 9c3cdc1f83a6e07092392ff4aba6466517dbd1d0).
 */
#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

/* <linux/cpumask.h> */

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 20) && !defined(BACKPORT_LINUX_CPUMASK_H)
#define nr_cpu_ids NR_CPUS
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28) && defined(__LINUX_CPUMASK_H)
/*
 * See also patch "cpumask: introduce new API, without changing anything"
 * (commit ID 2d3854a37e8b).
 */
typedef cpumask_t cpumask_var_t[1];
#define cpumask_bits(maskp) ((maskp)->bits)
#ifdef CONFIG_CPUMASK_OFFSTACK
/* Assuming NR_CPUS is huge, a runtime limit is more efficient.  Also,
 * not all bits may be allocated. */
#define nr_cpumask_bits nr_cpu_ids
#else
#define nr_cpumask_bits NR_CPUS
#endif

#ifdef CONFIG_CPUMASK_OFFSTACK
bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags);
void free_cpumask_var(cpumask_var_t mask);
#else
static inline void free_cpumask_var(cpumask_var_t mask)
{
}

static inline bool alloc_cpumask_var(cpumask_var_t *mask, gfp_t flags)
{
	return true;
}
#endif

/* verify cpu argument to cpumask_* operators */
static inline unsigned int cpumask_check(unsigned int cpu)
{
#ifdef CONFIG_DEBUG_PER_CPU_MAPS
	WARN_ON_ONCE(cpu >= nr_cpumask_bits);
#endif /* CONFIG_DEBUG_PER_CPU_MAPS */
	return cpu;
}

/**
 * cpumask_next - get the next cpu in a cpumask
 * @n: the cpu prior to the place to search (ie. return will be > @n)
 * @srcp: the cpumask pointer
 *
 * Returns >= nr_cpu_ids if no further cpus set.
 */
static inline unsigned int cpumask_next(int n, const cpumask_t *srcp)
{
	/* -1 is a legal arg here. */
	if (n != -1)
		cpumask_check(n);
	return find_next_bit(cpumask_bits(srcp), nr_cpumask_bits, n+1);
}

/**
 * for_each_cpu - iterate over every cpu in a mask
 * @cpu: the (optionally unsigned) integer iterator
 * @mask: the cpumask pointer
 *
 * After the loop, cpu is >= nr_cpu_ids.
 */
#define for_each_cpu(cpu, mask)                         \
	for ((cpu) = -1;                                \
		(cpu) = cpumask_next((cpu), (mask)),    \
		(cpu) < nr_cpu_ids;)

/**
 * cpumask_set_cpu - set a cpu in a cpumask
 * @cpu: cpu number (< nr_cpu_ids)
 * @dstp: the cpumask pointer
 */
static inline void cpumask_set_cpu(unsigned int cpu, cpumask_t *dstp)
{
	set_bit(cpu, cpumask_bits(dstp));
}

/**
 * cpumask_copy - *dstp = *srcp
 * @dstp: the result
 * @srcp: the input cpumask
 */
static inline void cpumask_copy(cpumask_t *dstp,
				const cpumask_t *srcp)
{
	bitmap_copy(cpumask_bits(dstp), cpumask_bits(srcp), nr_cpumask_bits);
}

/**
 * cpumask_setall - set all cpus (< nr_cpu_ids) in a cpumask
 * @dstp: the cpumask pointer
 */
static inline void cpumask_setall(cpumask_t *dstp)
{
	bitmap_fill(cpumask_bits(dstp), nr_cpumask_bits);
}

/**
 * cpumask_equal - *src1p == *src2p
 * @src1p: the first input
 * @src2p: the second input
 */
static inline bool cpumask_equal(const cpumask_t *src1p,
				 const cpumask_t *src2p)
{
	return bitmap_equal(cpumask_bits(src1p), cpumask_bits(src2p),
			    nr_cpumask_bits);
}
#endif

/* <linux/dlm.h> */

/* See also commit 0f8e0d9a317406612700426fad3efab0b7bbc467 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
enum {
	DLM_LSFL_NEWEXCL = 0
};
#endif

/* <linux/fs.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 9, 0) && \
	!defined(CONFIG_COMPAT_KERNEL_3_12)
/*
 * See also patch "new helper: file_inode(file)" (commit ID
 * 496ad9aa8ef448058e36ca7a787c61f2e63f0f54). See also patch
 * "kill f_dentry macro" (commit ID 78d28e651f97).
 */
static inline struct inode *file_inode(const struct file *f)
{
	return f->f_dentry->d_inode;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
static inline int vfs_fsync_backport(struct file *file, int datasync)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
	struct inode *inode = file_inode(file);

	return sync_page_range(inode, file->f_mapping, 0, i_size_read(inode));
#else
	return vfs_fsync(file, file->f_path.dentry, datasync);
#endif
}

#define vfs_fsync vfs_fsync_backport
#endif

/* <linux/kernel.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19)
#ifndef RHEL_RELEASE_CODE
typedef _Bool bool;
#endif
#define true  1
#define false 0
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
#ifndef swap
#define swap(a, b) \
	do { typeof(a) __tmp = (a); (a) = (b); (b) = __tmp; } while (0)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6 ||	\
	 RHEL_MAJOR -0 == 6 && RHEL_MINOR -0 < 1)
extern int hex_to_bin(char ch);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 38)
/*
 * See also "lib: hex2bin converts ascii hexadecimal string to binary" (commit
 * dc88e46029486ed475c71fe1bb696d39511ac8fe).
 */
static inline void hex2bin(u8 *dst, const char *src, size_t count)
{
	while (count--) {
		*dst = hex_to_bin(*src++) << 4;
		*dst += hex_to_bin(*src++);
		dst++;
	}
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 39) &&		\
	LINUX_VERSION_CODE != KERNEL_VERSION(2, 6, 38) &&	\
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
static inline int __must_check kstrtoull(const char *s, unsigned int base,
					 unsigned long long *res)
{
	return strict_strtoull(s, base, res);
}

static inline int __must_check kstrtoll(const char *s, unsigned int base,
					long long *res)
{
	return strict_strtoll(s, base, res);
}

static inline int __must_check kstrtoul(const char *s, unsigned int base,
					unsigned long *res)
{
	return strict_strtoul(s, base, res);
}

static inline int __must_check kstrtol(const char *s, unsigned int base,
				       long *res)
{
	return strict_strtol(s, base, res);
}
#endif

/* <linux/kmod.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23)
enum umh_wait {
	UMH_NO_WAIT = -1,       /* don't wait at all */
	UMH_WAIT_EXEC = 0,      /* wait for the exec, but not the process */
	UMH_WAIT_PROC = 1,      /* wait for the process to complete */
};
#endif

/* <linux/list.h> */

#ifndef __list_for_each
/* ToDo: cleanup when both are the same for all relevant kernels */
#define __list_for_each list_for_each
#endif

/*
 * Returns true if entry is in its list. Entry must be deleted from the
 * list by using list_del_init()!
 */
static inline bool list_entry_in_list(const struct list_head *entry)
{
	return !list_empty(entry);
}

/* <linux/lockdep.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32)
#define lockdep_assert_held(l) do { (void)(l); } while (0)
#endif

/* <linux/preempt.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37)
/*
 * See also patch "sched: Fix softirq time accounting" (commit ID
 * 75e1056f5c57050415b64cb761a3acc35d91f013).
 */
#ifndef in_serving_softirq
#define in_serving_softirq() in_softirq()
#endif
#endif

/* <linux/printk.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#ifndef pr_err
#define pr_err(fmt, ...) printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 35)
/*
 * See also patch "kernel.h: add pr_warn for symmetry to dev_warn,
 * netdev_warn" (commit fc62f2f19edf46c9bdbd1a54725b56b18c43e94f).
 */
#ifndef pr_warn
#define pr_warn pr_warning
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
/*
 * See also patch "Add a dummy printk function for the maintenance of unused
 * printks" (commit 12fdff3fc2483f906ae6404a6e8dcf2550310b6f).
 */
static inline __attribute__ ((format (printf, 1, 2)))
int no_printk(const char *s, ...) { return 0; }
#endif

/* <linux/rcupdate.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 0, 0) && !defined(kfree_rcu)
typedef void (*rcu_callback_t)(struct rcu_head *);
#define __is_kfree_rcu_offset(offset) ((offset) < 4096)
#define kfree_call_rcu(head, rcb) call_rcu(head, rcb)
#define __kfree_rcu(head, offset)				\
	do {							\
		BUILD_BUG_ON(!__is_kfree_rcu_offset(offset));	\
		kfree_call_rcu(head, (rcu_callback_t)(unsigned long)(offset)); \
	} while (0)
#define kfree_rcu(ptr, rcu_head)				\
	__kfree_rcu(&((ptr)->rcu_head), offsetof(typeof(*(ptr)), rcu_head))
#endif

/* <linux/sched.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
#define set_cpus_allowed_ptr(p, new_mask) set_cpus_allowed((p), *(new_mask))
#endif

/* <linux/scatterlist.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/*
 * The macro's sg_page(), sg_virt(), sg_init_table(), sg_assign_page() and
 * sg_set_page() have been introduced in the 2.6.24 kernel. The definitions
 * below are backports of the 2.6.24 macro's for older kernels. There is one
 * exception however: when compiling SCST on a system with a pre-2.6.24 kernel
 * (e.g. RHEL 5.x) where the OFED kernel headers have been installed, do not
 * define the backported macro's because OFED has already defined these.
 */

static inline bool sg_is_chain(struct scatterlist *sg)
{
	return false;
}

static inline struct scatterlist *sg_chain_ptr(struct scatterlist *sg)
{
	return NULL;
}

#define sg_is_last(sg) false

#ifndef sg_page
static inline struct page *sg_page(struct scatterlist *sg)
{
	return sg->page;
}
#endif

static inline void *sg_virt(struct scatterlist *sg)
{
	return page_address(sg_page(sg)) + sg->offset;
}

static inline void sg_mark_end(struct scatterlist *sg)
{
}

#ifndef __BACKPORT_LINUX_SCATTERLIST_H_TO_2_6_23__

static inline void sg_init_table(struct scatterlist *sgl, unsigned int nents)
{
	memset(sgl, 0, sizeof(*sgl) * nents);
}

static inline void sg_assign_page(struct scatterlist *sg, struct page *page)
{
	sg->page = page;
}

static inline void sg_set_page(struct scatterlist *sg, struct page *page,
			       unsigned int len, unsigned int offset)
{
	sg_assign_page(sg, page);
	sg->offset = offset;
	sg->length = len;
}

#ifndef for_each_sg
/* See also commit 96b418c960af0d5c7185ff5c4af9376eb37ac9d3 */
#define for_each_sg(sglist, sg, nr, __i)       \
	for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next_inline(sg))
#endif /* for_each_sg */

#endif /* __BACKPORT_LINUX_SCATTERLIST_H_TO_2_6_23__ */
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24) */

/* <linux/slab.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
#define KMEM_CACHE(__struct, __flags) kmem_cache_create(#__struct,\
	sizeof(struct __struct), __alignof__(struct __struct),\
	(__flags), NULL, NULL)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 4, 0) &&	    \
	!(LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 52) && \
	  LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)) &&  \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 6)
static inline void *kmalloc_array(size_t n, size_t size, gfp_t flags)
{
	if (size != 0 && n > ULONG_MAX / size)
		return NULL;
	return kmalloc(n * size, flags);
}
#endif

/* <linux/t10-pi.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 18, 0)
struct t10_pi_tuple {
	__be16 guard_tag;
	__be16 app_tag;
	__be32 ref_tag;
};
#endif

/* <linux/types.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/*
 * See also patch "fix abuses of ptrdiff_t" (commit ID
 * 142956af525002c5378e7d91d81a01189841a785).
 */
typedef unsigned long uintptr_t;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 22)
char *kvasprintf(gfp_t gfp, const char *fmt, va_list ap);
#endif

/* <linux/vmalloc.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 37) && \
	(!defined(RHEL_MAJOR) || RHEL_MAJOR -0 < 5 || \
	 RHEL_MAJOR -0 == 5 && RHEL_MINOR -0 < 10 || \
	 RHEL_MAJOR -0 == 6 && RHEL_MINOR -0 < 1)
/*
 * See also patch "mm: add vzalloc() and vzalloc_node() helpers" (commit
 * e1ca7788dec6773b1a2bce51b7141948f2b8bccf).
 */
static inline void *vzalloc(unsigned long size)
{
	return __vmalloc(size, GFP_KERNEL | __GFP_HIGHMEM | __GFP_ZERO,
			 PAGE_KERNEL);
}
#endif

/* <linux/workqueue.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 23) && !defined(BACKPORT_LINUX_WORKQUEUE_TO_2_6_19)
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 20))
static inline int cancel_delayed_work_sync(struct delayed_work *work)
{
	int res;

	res = cancel_delayed_work(work);
	flush_scheduled_work();
	return res;
}
#else
/*
 * While cancel_delayed_work_sync() has not been defined in the vanilla kernel
 * 2.6.18 nor in 2.6.19 nor in RHEL/CentOS 5.0..5.5, a definition is available
 * in RHEL/CentOS 5.6. Unfortunately that definition is incompatible with what
 * we need. So define cancel_delayed_work() as a macro such that it overrides
 * the RHEL/CentOS 5.6 inline function definition in <linux/workqueue.h>.
 */
#define cancel_delayed_work_sync(work)		\
({						\
	int res;				\
						\
	res = cancel_delayed_work((work));	\
	flush_scheduled_work();			\
	res;					\
})
#endif
#endif

/* <scsi/scsi_cmnd.h> */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 24)
/*
 * See also patch "[SCSI] bidirectional command support"
 * (commit ID 6f9a35e2dafa).
 */
static inline int scsi_bidi_cmnd(struct scsi_cmnd *cmd)
{
	return false;
}
#endif

#endif /* _SCST_BACKPORT_H_ */
