#ifndef __DRBD_INTERVAL_H
#define __DRBD_INTERVAL_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/rbtree.h>

/* Compatibility code for 2.6.16 (SLES10) */
#ifndef rb_parent
#define rb_parent(r)   ((r)->rb_parent)
#endif

/*
 * Kernels between mainline commit dd67d051 (v2.6.18-rc1) and 10fd48f2
 * (v2.6.19-rc1) have a broken version of RB_EMPTY_NODE().
 *
 * RHEL5 kernels until at least 2.6.18-238.12.1.el5 have the broken definition.
 */
#if !defined(RB_EMPTY_NODE) || LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,19)

#undef RB_EMPTY_NODE
#define RB_EMPTY_NODE(node)     (rb_parent(node) == node)

#endif

#ifndef RB_CLEAR_NODE
static inline void rb_set_parent(struct rb_node *rb, struct rb_node *p)
{
        rb->rb_parent = p;
}
#define RB_CLEAR_NODE(node)     (rb_set_parent(node, node))
#endif
/* /Compatibility code */

struct drbd_interval {
	struct rb_node rb;
	sector_t sector;		/* start sector of the interval */
	unsigned int size;		/* size in bytes */
	sector_t end;			/* highest interval end in subtree */
	unsigned int local:1		/* local or remote request? */;
	unsigned int waiting:1;		/* someone is waiting for completion */
	unsigned int completed:1;	/* this has been completed already;
					 * ignore for conflict detection */
};

static inline void drbd_clear_interval(struct drbd_interval *i)
{
	RB_CLEAR_NODE(&i->rb);
}

static inline bool drbd_interval_empty(struct drbd_interval *i)
{
	return RB_EMPTY_NODE(&i->rb);
}

extern bool drbd_insert_interval(struct rb_root *, struct drbd_interval *);
extern bool drbd_contains_interval(struct rb_root *, sector_t,
				   struct drbd_interval *);
extern void drbd_remove_interval(struct rb_root *, struct drbd_interval *);
extern struct drbd_interval *drbd_find_overlap(struct rb_root *, sector_t,
					unsigned int);
extern struct drbd_interval *drbd_next_overlap(struct drbd_interval *, sector_t,
					unsigned int);

#define drbd_for_each_overlap(i, root, sector, size)		\
	for (i = drbd_find_overlap(root, sector, size);		\
	     i;							\
	     i = drbd_next_overlap(i, sector, size))

#endif  /* __DRBD_INTERVAL_H */
