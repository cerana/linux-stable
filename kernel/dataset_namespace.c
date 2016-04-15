/*
 * Copyright 2015 OmniTI Computer Consulting, Inc. All rights reserved.
 */
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/nsproxy.h>
#include <linux/proc_ns.h>
#include <linux/user_namespace.h>
#include <linux/dataset_namespace.h>

static LIST_HEAD(dataset_operations_list);
DEFINE_MUTEX(datasetns_mutex);

LIST_HEAD(dataset_namespace_list);
EXPORT_SYMBOL(dataset_namespace_list);

struct dataset_namespace init_dataset_ns = {
	.kref = {
		.refcount	= ATOMIC_INIT(2),
	},
	.user_ns = &init_user_ns,
	.ns.inum = PROC_DATASET_INIT_INO,
#ifdef CONFIG_DATASET_NS
	.ns.ops = &datasetns_operations,
#endif
};
EXPORT_SYMBOL(init_dataset_ns);

static int __init dataset_ns_init(void)
{
	mutex_lock(&datasetns_mutex);
	list_add_tail(&init_dataset_ns.list, &dataset_namespace_list);
	mutex_unlock(&datasetns_mutex);

	return 0;
}
__initcall(dataset_ns_init);

static struct dataset_namespace *create_dataset_ns(void)
{
	struct dataset_namespace *dsns;

	dsns = kmalloc(sizeof(struct dataset_namespace), GFP_KERNEL);
	if (dsns != NULL)
		kref_init(&dsns->kref);

	return dsns;
}

static struct dataset_namespace *clone_dataset_ns(struct user_namespace *user_ns,
					  struct dataset_namespace *old_ns)
{
	struct dataset_namespace *dsns;
	int err;

	dsns = create_dataset_ns();
	if (dsns == NULL)
		return ERR_PTR(-ENOMEM);

	err = ns_alloc_inum(&dsns->ns);
	if (err != 0) {
		kfree(dsns);
		return ERR_PTR(err);
	}

	dsns->ns.ops = &datasetns_operations;
	dsns->user_ns = get_user_ns(user_ns);

	return dsns;
}

struct dataset_namespace *copy_dataset_ns(unsigned long flags,
	struct user_namespace *user_ns, struct dataset_namespace *old_ns)
{
	struct dataset_namespace *new_ns;

	get_dataset_ns(old_ns);

	if (!(flags & CLONE_NEWDATASET))
		return old_ns;

	mutex_lock(&datasetns_mutex);
	new_ns = clone_dataset_ns(user_ns, old_ns);
	if (!IS_ERR(new_ns))
		list_add_tail(&new_ns->list, &dataset_namespace_list);
	mutex_unlock(&datasetns_mutex);
	put_dataset_ns(old_ns);

	return new_ns;
}

void free_dataset_ns(struct kref *kref)
{
	struct dataset_namespace *dsns;
	struct dataset_operations *ops;

	dsns = container_of(kref, struct dataset_namespace, kref);
	mutex_lock(&datasetns_mutex);
	list_del(&dsns->list);
	list_for_each_entry(ops, &dataset_operations_list, list)
	    ops->exit(dsns);
	mutex_unlock(&datasetns_mutex);
	put_user_ns(dsns->user_ns);
	ns_free_inum(&dsns->ns);
	kfree(dsns);
}

static int register_dataset_operations(struct dataset_operations *ops)
{
	struct dataset_namespace *dsns;
	int error;

	list_add_tail(&ops->list, &dataset_operations_list);
	list_for_each_entry(dsns, &dataset_namespace_list, list) {
	    error = ops->init(dsns);
	    if (error < 0)
		    goto out_undo;
	}
out:
	return error;
out_undo:
	list_for_each_entry_continue_reverse(dsns, &dataset_namespace_list, list)
		ops->exit(dsns);
	goto out;
}

static void unregister_dataset_operations(struct dataset_operations *ops)
{
	struct dataset_namespace *dsns;

	list_for_each_entry(dsns, &dataset_namespace_list, list)
		ops->exit(dsns);
	list_del(&ops->list);
}

int register_dataset_provider(struct dataset_operations *ops)
{
	int error = 0;

	mutex_lock(&datasetns_mutex);
	error = register_dataset_operations(ops);
	mutex_unlock(&datasetns_mutex);

	return error;
}
EXPORT_SYMBOL(register_dataset_provider);

void unregister_dataset_provider(struct dataset_operations *ops)
{
	mutex_lock(&datasetns_mutex);
	unregister_dataset_operations(ops);
	mutex_unlock(&datasetns_mutex);
}
EXPORT_SYMBOL(unregister_dataset_provider);

static inline struct dataset_namespace *to_dataset_ns(struct ns_common *ns)
{
	return container_of(ns, struct dataset_namespace, ns);
}

static struct ns_common *datasetns_get(struct task_struct *task)
{
	struct dataset_namespace *dsns = NULL;
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy != NULL) {
		dsns = nsproxy->dataset_ns;
		get_dataset_ns(dsns);
	}
	task_unlock(task);

	return &dsns->ns;
}

static void datasetns_put(struct ns_common *ns)
{
	put_dataset_ns(to_dataset_ns(ns));
}

static int datasetns_install(struct nsproxy *nsproxy, struct ns_common *ns)
{
	struct dataset_namespace *dsns = to_dataset_ns(ns);

	if (!ns_capable(dsns->user_ns, CAP_SYS_ADMIN) ||
	    !ns_capable(current_user_ns(), CAP_SYS_ADMIN))
		return -EPERM;

	get_dataset_ns(dsns);
	put_dataset_ns(nsproxy->dataset_ns);
	nsproxy->dataset_ns = dsns;

	return 0;
}

const struct proc_ns_operations datasetns_operations = {
	.name		= "dataset",
	.type		= CLONE_NEWDATASET,
	.get		= datasetns_get,
	.put		= datasetns_put,
	.install	= datasetns_install,
};
