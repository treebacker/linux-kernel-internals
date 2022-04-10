### Linux Namespace Part 4

#### 前言

​		[Part1]()部分主要介绍了namespace的各种类型，以及在userspace使用namespace能够达到的对各种资源的隔离，在[Part2]()部分从kernel space的角度剖析namespace的实现机制，并剖析了**user namespace**的相关细节，在[Part3]()里主要介绍了**pid namespace**的实现细节，在本篇文章中将继续剖析另一个namespace即`mount namespaces`的实现细节。

#### 相关基础结构

`mnt_namespace`也是`task_struct->nsproxy`结构中的一个成员

```c
struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
};
```

`mnt_namespace`结构

```c
struct mnt_namespace {
	atomic_t		count;				// 引用次数
	unsigned int		proc_inum;		
	struct mount *	root;				// 当前namespace下的 root filesystem
	struct list_head	list;			// 当前namespace下的文件系统链表
	struct user_namespace	*user_ns; 	// 
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
};

```

`struct mount`结构：一个已安装的文件系统描述符

```c
struct mount {
	struct hlist_node mnt_hash;
	struct mount *mnt_parent;					// 挂载的父mount节点
	struct dentry *mnt_mountpoint;				// 挂载点目录
	struct vfsmount mnt;						// 
	union {
		struct rcu_head mnt_rcu;
		struct llist_node mnt_llist;
	};
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;		// 构成mnt_namespace->list
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts  所有slave mount 组成的链表*/
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace 	所属的mnt_namespace*/
	struct mountpoint *mnt_mp;	/* where is it mounted */
	struct hlist_node mnt_mp_list;	/* list mounts with the same mountpoint */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	struct hlist_head mnt_pins;
	struct path mnt_ex_mountpoint;
};

```



#### create_mnt_ns | clone

`mnt_namespace`的创建方式有两种

通过`create_mnt_ns`创建一个`private mount namespace`，并添加root文件系统

```c
/**
 * create_mnt_ns - creates a private namespace and adds a root filesystem
 * @mnt: pointer to the new root filesystem mountpoint
 */
static struct mnt_namespace *create_mnt_ns(struct vfsmount *m)
{
	struct mnt_namespace *new_ns = alloc_mnt_ns(&init_user_ns);
	if (!IS_ERR(new_ns)) {
		struct mount *mnt = real_mount(m);
		mnt->mnt_ns = new_ns;
		new_ns->root = mnt;
		list_add(&mnt->mnt_list, &new_ns->list);
	} else {
		mntput(m);
	}
	return new_ns;
}
```

主要工作由`alloc_mnt_ns`分配并初始化一个`mnt_namespace`

```c
static struct mnt_namespace *alloc_mnt_ns(struct user_namespace *user_ns)
{
	struct mnt_namespace *new_ns;
	int ret;

	new_ns = kmalloc(sizeof(struct mnt_namespace), GFP_KERNEL);
	if (!new_ns)
		return ERR_PTR(-ENOMEM);
	ret = proc_alloc_inum(&new_ns->proc_inum);
	if (ret) {
		kfree(new_ns);
		return ERR_PTR(ret);
	}
	new_ns->seq = atomic64_add_return(1, &mnt_ns_seq);
	atomic_set(&new_ns->count, 1);				// 初始化 mnt_namespace.count = 1
	new_ns->root = NULL;						// 初始化 mnt_namespace.root = NULL
	INIT_LIST_HEAD(&new_ns->list);				// 初始化 mnt_namespace.list 链表
	init_waitqueue_head(&new_ns->poll);			// 初始化 mnt_namespace.poll
	new_ns->event = 0;							// 初始化 mnt_namespace.event = 0
	new_ns->user_ns = get_user_ns(user_ns);		// 初始化 mnt_namespace.user_ns
	return new_ns;
}
```

值得注意的是，通过这种方式新建的`mnt_namespace`的`user_ns`是`init_user_ns`。

另一种途径：调用链`clone`->`copy_namespaces`->`create_new_namespaces`->`copy_mnt_ns`为新进程创建新的`mnt_namespace`（继承自父进程的`mnt_namespace`）

```c
struct mnt_namespace *copy_mnt_ns(unsigned long flags, struct mnt_namespace *ns,
		struct user_namespace *user_ns, struct fs_struct *new_fs)
{
	struct mnt_namespace *new_ns;
	struct vfsmount *rootmnt = NULL, *pwdmnt = NULL;
	struct mount *p, *q;
	struct mount *old;
	struct mount *new;
	int copy_flags;

	BUG_ON(!ns);

	if (likely(!(flags & CLONE_NEWNS))) {
		get_mnt_ns(ns);
		return ns;
	}

	old = ns->root;

	new_ns = alloc_mnt_ns(user_ns);
	if (IS_ERR(new_ns))
		return new_ns;

	namespace_lock();
	/* First pass: copy the tree topology */
	copy_flags = CL_COPY_UNBINDABLE | CL_EXPIRE;
	if (user_ns != ns->user_ns)
		copy_flags |= CL_SHARED_TO_SLAVE | CL_UNPRIVILEGED;
	new = copy_tree(old, old->mnt.mnt_root, copy_flags);
	if (IS_ERR(new)) {
		namespace_unlock();
		free_mnt_ns(new_ns);
		return ERR_CAST(new);
	}
	new_ns->root = new;
	list_add_tail(&new_ns->list, &new->mnt_list);

	/*
	 * Second pass: switch the tsk->fs->* elements and mark new vfsmounts
	 * as belonging to new namespace.  We have already acquired a private
	 * fs_struct, so tsk->fs->lock is not needed.
	 */
	p = old;
	q = new;
	while (p) {
		q->mnt_ns = new_ns;
		if (new_fs) {
			if (&p->mnt == new_fs->root.mnt) {
				new_fs->root.mnt = mntget(&q->mnt);
				rootmnt = &p->mnt;
			}
			if (&p->mnt == new_fs->pwd.mnt) {
				new_fs->pwd.mnt = mntget(&q->mnt);
				pwdmnt = &p->mnt;
			}
		}
		p = next_mnt(p, old);
		q = next_mnt(q, new);
		if (!q)
			break;
		while (p->mnt.mnt_root != q->mnt.mnt_root)
			p = next_mnt(p, old);
	}
	namespace_unlock();

	if (rootmnt)
		mntput(rootmnt);
	if (pwdmnt)
		mntput(pwdmnt);

	return new_ns;
}

```

在通过`alloc_mnt_ns`新建初始化`mnt_namespace`之后，调用`copy_tree`复制父`mnt_namespace`的根文件系统`mount`到新的`mnt_namespace`，其中`copy_flags`决定了两个`mnt_namespace`下的`mount`继承关系。

将新建的根文件系统`new->mnt_list`添加到`new_ns->list`

之后，遍历`mnt_list`，如果新建的namespace指定了`fs_struct`，将所有新的`mount`标记属于新建的namespace。



