/*
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef MISC_H
#define MISC_H

struct qelem {
	struct qelem *q_forw;
	struct qelem *q_back;
};

/* stolen list stuff from Linux kernel */

#undef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE,MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) \
	struct qelem name = LIST_HEAD_INIT(name)

#define INIT_LIST_HEAD(ptr) do { \
	(ptr)->q_forw = (ptr); (ptr)->q_back = (ptr); \
} while (0)

static inline int list_empty(const struct qelem *head)
{
	return head->q_forw == head;
}

static inline int list_length_is_one(const struct qelem *head)
{
        return head->q_forw == head->q_back;
}

#define container_of(ptr, type, member) ({			\
        const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
        (type *)( (char *)__mptr - offsetof(type,member) );})

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->q_forw, typeof(*pos), member);	\
	     &pos->member != (head); 	\
	     pos = list_entry(pos->member.q_forw, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->q_forw, typeof(*pos), member),	\
		n = list_entry(pos->member.q_forw, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.q_forw, typeof(*n), member))

#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY	26
#endif

#endif
