#ifndef _LINUX_DATASET_NAMESPACE_H
#define _LINUX_DATASET_NAMESPACE_H

#include <linux/kref.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>

struct user_namespace;

struct dataset_namespace {
	struct kref kref;
	struct list_head list;
	struct user_namespace *user_ns;
	struct ns_common ns;
};

struct dataset_operations {
	struct list_head list;
	int (*init)(struct dataset_namespace *ns);
	void (*exit)(struct dataset_namespace *ns);
};

extern struct dataset_namespace init_dataset_ns;

extern int register_dataset_provider(struct dataset_operations *ops);
extern void unregister_dataset_provider(struct dataset_operations *ops);

#ifdef CONFIG_DATASET_NS
extern struct dataset_namespace *copy_dataset_ns(unsigned long,
    struct user_namespace *, struct dataset_namespace *);
extern void free_dataset_ns(struct kref *);

static inline void get_dataset_ns(struct dataset_namespace *ns)
{
	kref_get(&ns->kref);
}

static inline void put_dataset_ns(struct dataset_namespace *ns)
{
	kref_put(&ns->kref, free_dataset_ns);
}
#else
static inline void get_dataset_ns(struct dataset_namespace *ns)
{
}
static inline void put_dataset_ns(struct dataset_namespace *ns)
{
}
#endif

#endif /* _LINUX_DATASET_NAMESPACE_H */
