#define ZZZ_genl_mcgrps		CONCAT_(GENL_MAGIC_FAMILY, _genl_mcgrps)
static const struct genl_multicast_group ZZZ_genl_mcgrps[] = {
#undef GENL_mc_group
#define GENL_mc_group(group) { .name = #group, },
#include GENL_MAGIC_INCLUDE_FILE
};

enum CONCAT_(GENL_MAGIC_FAMILY, group_ids) {
#undef GENL_mc_group
#define GENL_mc_group(group) CONCAT_(GENL_MAGIC_FAMILY, _group_ ## group),
#include GENL_MAGIC_INCLUDE_FILE
};

#undef GENL_mc_group
#define GENL_mc_group(group)						\
static int CONCAT_(GENL_MAGIC_FAMILY, _genl_multicast_ ## group)(	\
	struct sk_buff *skb, gfp_t flags)				\
{									\
	unsigned int group_id =						\
		CONCAT_(GENL_MAGIC_FAMILY, _group_ ## group);		\
	return genlmsg_multicast(&ZZZ_genl_family, skb, 0,		\
				 group_id, flags);			\
}

#include GENL_MAGIC_INCLUDE_FILE

#undef GENL_mc_group
#define GENL_mc_group(group)

int CONCAT_(GENL_MAGIC_FAMILY, _genl_register)(void)
{
#ifdef genl_register_family_with_ops_groups
	return genl_register_family_with_ops_groups(&ZZZ_genl_family,	\
						    ZZZ_genl_ops,	\
						    ZZZ_genl_mcgrps);
#else /* no more GENL_ID_GENERATE, no more register with groups */
	/* v4.10,
	 * 489111e5 genetlink: statically initialize families
	 * a07ea4d genetlink: no longer support using static family IDs
	 */
	return genl_register_family(&ZZZ_genl_family);
#endif
}

void CONCAT_(GENL_MAGIC_FAMILY, _genl_unregister)(void)
{
	genl_unregister_family(&ZZZ_genl_family);
}
