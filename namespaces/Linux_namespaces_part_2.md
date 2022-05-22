### Linux Namespace Part 2

#### 前言

​		[Part1](./Linux_namespaces_part_1.md)部分主要介绍了namespace的各种类型，以及在userspace使用namespace能够达到的对各种资源的隔离，接下来的部分将从kernel space的角度剖析namespace的实现机制。这篇主要介绍**User namespace**的实现细节。


#### nsproxy

​	在`task_struct`结构中，有一个`nsproxy`字段，关联该进程的所有`namespace`

```c
/* namespaces */
	struct nsproxy *nsproxy;
```

`nsproxy`结构体原型：

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

`count`字段表引用该`nsproxy`示例的`task`数目，因为在默认情况下，一个`nsproxy`被多个进程共享，在`clone`/`unshare`的情况下，才会新生成一个`nsproxy`实例（复制旧的`nsproxy`得到）

值得注意的是，在`nsproxy`里并没有`user namespace`，这是因为`user namespace`其实属于`credentails`的范畴，在`task_struct`中单独抽象了一个结构`struct cred`，`task->cred`表当前task的credentials，事实上，task还有一个`real_cred`，两者的区别在于`cred`用于该`task`作用于其他`object`时的security认证，`real_cred`用于其他`task`作用于当前`task`时的security认证。一般情况下，两者是一致的。

在`struct cred`结构里，`cred->user_ns`表当前进程的namespace。

#### user namespace

User namespace结构的原型：

```c
struct user_namespace {
	struct uid_gid_map	uid_map;
	struct uid_gid_map	gid_map;
	struct uid_gid_map	projid_map;
	atomic_t		count;
	struct user_namespace	*parent;
	int			level;
	kuid_t			owner;
	kgid_t			group;
	unsigned int		proc_inum;
	unsigned long		flags;

	/* Register of per-UID persistent keyrings for this namespace */
#ifdef CONFIG_PERSISTENT_KEYRINGS
	struct key		*persistent_keyring_register;
	struct rw_semaphore	persistent_keyring_register_sem;
#endif
};
```

其中，`uid_gid_map`定义了该命名空间下的`uid/gid`和子命名空间的`uid/gid`的映射关系。

可以看到在namespace结构下，也有一个`count`字段，不同的是namespace下的`count`字段表引用该`namespace`的`nsproxy`的数量，而不是进程数量，换言之，不同的`nsproxy`实例可以共享同一个`namespace`示例。

`parent`字段指向当前namespace的父namespace，即namespace之间是存在层级关系的；

`level`字段就是表层级的；

`owner`/`group`表当前namespace下进程的`euid/egid`；



#### uid gid map

​	user namespace实现不同namespace下的user id的隔离的关键在于`struct uid_gid_map`，原型如下

```c
struct uid_gid_map {	/* 64 bytes -- 1 cache line */
	u32 nr_extents;
	struct uid_gid_extent {
		u32 first;
		u32 lower_first;
		u32 count;
	} extent[UID_GID_MAP_MAX_EXTENTS];
};
```

进程文件`/proc/PID/uid_map`的格式如下：

```
    ID-inside-ns   ID-outside-ns   length
```

` ID-inside-ns`是`uid_gid_extent`里的`first`；

`ID-outside-ns`是`uid_gid_extent`里的`lower_first`；

`length`是`uid_gid_extent`里的`count`

最多允许定义`UID_GID_MAP_MAX_EXTENTS`组映射关系。

例如：

```

tree@tree-ubt:~/work$ cat /proc/self/uid_map 
         0          0 4294967295
```

相关数据结构的关系

![](images\namespace_main.png)

#### Related syscalls

##### clone

`clone`经常用于创建新的namespace（包括user namespace）

主要的工作由`do_fork->copy_process`完成，其中由于`user namespace`实质是由`cred`管理，所以实现在`copy_creds`中，其余的namespace则是由`copy_namespaces`创建。

```c
/*
 * Copy credentials for the new process created by fork()
 *
 * We share if we can, but under some circumstances we have to generate a new
 * set.
 *
 * The new process gets the current process's subjective credentials as its
 * objective and subjective credentials
 */
int copy_creds(struct task_struct *p, unsigned long clone_flags)
{
	struct cred *new;
	int ret;

	...

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	if (clone_flags & CLONE_NEWUSER) {
		ret = create_user_ns(new);
		if (ret < 0)
			goto error_put;
	}
	...
	atomic_inc(&new->user->processes);
	p->cred = p->real_cred = get_cred(new);
	alter_cred_subscribers(new, 2);
	validate_creds(new);
	return 0;

error_put:
	put_cred(new);
	return ret;
}
```

通过`prepare_creds`新建一个`cred`结构，当指定了`CLONE_NEWUSER`时，通过`create_user_ns`创建一个新的user namespace实例：

```c
int create_user_ns(struct cred *new)
{
	struct user_namespace *ns, *parent_ns = new->user_ns;
	kuid_t owner = new->euid;
	kgid_t group = new->egid;
	int ret;

	if (parent_ns->level > 32)
		return -EUSERS;

	/*
	 * Verify that we can not violate the policy of which files
	 * may be accessed that is specified by the root directory,
	 * by verifing that the root directory is at the root of the
	 * mount namespace which allows all files to be accessed.
	 */
	if (current_chrooted())
		return -EPERM;

	/* The creator needs a mapping in the parent user namespace
	 * or else we won't be able to reasonably tell userspace who
	 * created a user_namespace.
	 */
	if (!kuid_has_mapping(parent_ns, owner) ||
	    !kgid_has_mapping(parent_ns, group))
		return -EPERM;

	ns = kmem_cache_zalloc(user_ns_cachep, GFP_KERNEL);
	if (!ns)
		return -ENOMEM;

	ret = proc_alloc_inum(&ns->proc_inum);
	if (ret) {
		kmem_cache_free(user_ns_cachep, ns);
		return ret;
	}

	atomic_set(&ns->count, 1);
	/* Leave the new->user_ns reference with the new user namespace. */
	ns->parent = parent_ns;
	ns->level = parent_ns->level + 1;
	ns->owner = owner;
	ns->group = group;

	/* Inherit USERNS_SETGROUPS_ALLOWED from our parent */
	mutex_lock(&userns_state_mutex);
	ns->flags = parent_ns->flags;
	mutex_unlock(&userns_state_mutex);

	set_cred_user_ns(new, ns);

#ifdef CONFIG_PERSISTENT_KEYRINGS
	init_rwsem(&ns->persistent_keyring_register_sem);
#endif
	return 0;
}

```

这个函数在创建namespace前，有一定的check：

1、namespace的层级（level）最多32

2、chrooted进程不能新建namespace

3、creator需要有parent namespace的mapping关系，不然无法关联uid/gid的映射关系

```c
static inline bool kuid_has_mapping(struct user_namespace *ns, kuid_t uid)
{
	return from_kuid(ns, uid) != (uid_t) -1;
}
/**
 *	from_kuid - Create a uid from a kuid user-namespace pair.
 *	@targ: The user namespace we want a uid in.
 *	@kuid: The kernel internal uid to start with.
 *
 *	Map @kuid into the user-namespace specified by @targ and
 *	return the resulting uid.
 *
 *	There is always a mapping into the initial user_namespace.
 *
 *	If @kuid has no mapping in @targ (uid_t)-1 is returned.
 */
uid_t from_kuid(struct user_namespace *targ, kuid_t kuid)
{
	/* Map the uid from a global kernel uid */
	return map_id_up(&targ->uid_map, __kuid_val(kuid));
}
static u32 map_id_up(struct uid_gid_map *map, u32 id)
{
	unsigned idx, extents;
	u32 first, last;

	/* Find the matching extent */
	extents = map->nr_extents;
	smp_rmb();
	for (idx = 0; idx < extents; idx++) {
		first = map->extent[idx].lower_first;
		last = first + map->extent[idx].count - 1;
		if (id >= first && id <= last)
			break;
	}
	/* Map the id or note failure */
	if (idx < extents)
		id = (id - first) + map->extent[idx].first;
	else
		id = (u32) -1;

	return id;
}
```

之后，分配得到`user_namespace`结构，设置`parent`为`parent_ns`，`level`为`parent_ns->level + 1`，

`onwer`和`group`来自新建的`cred`的`euid/egid`字段，继承`parent_ns->flag`。

最后，通过`set_cred_user_ns`初始化`cred`的`user_ns`字段。

其中`from_kuid`的逻辑简述如下

```
uid_t from_kuid(struct user_namespace *targ, kuid_t kuid)

在targ namespace下，遍历uid_gid_extent 数组， 直到kuid在[extent[i].lower_first, extent[i].lower_first + count - 1]区间
返回新的uid：
kuid - extent[i].lower_first + extent[idx].first
```



##### unshare

​		除`clone`外，unshare也常用于新建namespace，但是该函数不会创建新的进程，所以相比较`clone`更清晰

```c
int unshare_userns(unsigned long unshare_flags, struct cred **new_cred)
{
	struct cred *cred;
	int err = -ENOMEM;

	if (!(unshare_flags & CLONE_NEWUSER))
		return 0;

	cred = prepare_creds();
	if (cred) {
		err = create_user_ns(cred);
		if (err)
			put_cred(cred);
		else
			*new_cred = cred;
	}

	return err;
}

```

类似`clone`里，首先`prepare_creds`新建一个`cred`，再`create_user_ns`新建一个`user namespace`，并将两者关联。

##### setns

上述`clone`或者`unshare`都通过新建namespacce的方式改变（子）进程的`user namespace`，而`setns`系统调用则用于将当前进程的`namespace`修改为已经存在的一个`namespace`

```c
 int setns(int fd, int nstype);
```

`fd`参数指向`/proc/[pid]/ns/xxx`，即进程文件下的`namespace`link文件，`nstype`和`clone`/`unshare`指定的namespace的类型是一致的。

```c
SYSCALL_DEFINE2(setns, int, fd, int, nstype)
{
	const struct proc_ns_operations *ops;
	struct task_struct *tsk = current;
	struct nsproxy *new_nsproxy;
	struct proc_ns *ei;
	struct file *file;
	int err;

	file = proc_ns_fget(fd);
	if (IS_ERR(file))
		return PTR_ERR(file);

	err = -EINVAL;
	ei = get_proc_ns(file_inode(file));
	ops = ei->ns_ops;
	if (nstype && (ops->type != nstype))
		goto out;

	new_nsproxy = create_new_namespaces(0, tsk, current_user_ns(), tsk->fs);
	if (IS_ERR(new_nsproxy)) {
		err = PTR_ERR(new_nsproxy);
		goto out;
	}

	err = ops->install(new_nsproxy, ei->ns);
	if (err) {
		free_nsproxy(new_nsproxy);
		goto out;
	}
	switch_task_namespaces(tsk, new_nsproxy);
out:
	fput(file);
	return err;
}

```

`setns`系统调用首先通过`proc_ns_fget`、`get_proc_ns`获得`fd`参数指定的namespace的`proc_ns`结构。

```c
struct proc_ns_operations {
	const char *name;
	int type;
	void *(*get)(struct task_struct *task);
	void (*put)(void *ns);
	int (*install)(struct nsproxy *nsproxy, void *ns);
	unsigned int (*inum)(void *ns);
};

struct proc_ns {
	void *ns;
	const struct proc_ns_operations *ns_ops;
};
```

通过`create_new_namespaces`新建一个没有`attach`到任何`task`的`nsproxy`结构；

`proc_ns`结构包含`proc_ns_operations`，定义了一些namespace的操作方法，通过`proc_ns->ns_ops->install`将一个已经存在的`namespace`关联到新建的`nsproxy`.

对于`user namespace`，对应的方法是`userns_install`:

```c
static int userns_install(struct nsproxy *nsproxy, void *ns)
{
	struct user_namespace *user_ns = ns;
	struct cred *cred;

	/* Don't allow gaining capabilities by reentering
	 * the same user namespace.
	 */
	if (user_ns == current_user_ns())
		return -EINVAL;

	/* Threaded processes may not enter a different user namespace */
	if (atomic_read(&current->mm->mm_users) > 1)
		return -EINVAL;

	if (current->fs->users != 1)
		return -EINVAL;

	if (!ns_capable(user_ns, CAP_SYS_ADMIN))
		return -EPERM;

	cred = prepare_creds();
	if (!cred)
		return -ENOMEM;

	put_user_ns(cred->user_ns);
	set_cred_user_ns(cred, get_user_ns(user_ns));

	return commit_creds(cred);
}
```

同样有一些检查：

1、`fd`指定的namespace不能是当前进程的user namespace

2、多线程进程不能不同的线程进入不同的user namespace

3、需要`CAP_SYS_ADMIN`权限

最后通过`prepare_creds`->`set_cred_user_ns`->`commit_creds`更新当前进程的`cred->user_ns`字段为`fd`指向的user namespace。

##### getuid

`getuid`获取当前用户的`uid`，也是从`task->cred->user_ns`获取

```c
SYSCALL_DEFINE0(getuid)
{
	/* Only we change this so SMP safe */
	return from_kuid_munged(current_user_ns(), current_uid());
}

uid_t from_kuid_munged(struct user_namespace *targ, kuid_t kuid)
{
	uid_t uid;
	uid = from_kuid(targ, kuid);

	if (uid == (uid_t) -1)
		uid = overflowuid;
	return uid;
}
```

`current_uid`返回当前用户的`uid`，`from_kuid`返回user namespace `targ`下`kuid`的映射uid，

如果不存杂，返回`overflowuid`，因此，如果只是新建`user namespace`，没有设置`/proc/PID/uid_map`，返回的uid值是`overflowuid`：

```c
tree@tree-ubt:~/work/mount_test$ unshare -U
nobody@tree-ubt:~/work/mount_test$ id
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
```

##### User namespace 层级结构

`user namespace`都是有一个`parent`，所有的`user namespace`的根是`init_user_ns`，`init_user_ns`是硬编码定义的

```c
struct user_namespace init_user_ns = {
	.uid_map = {
		.nr_extents = 1,
		.extent[0] = {
			.first = 0,
			.lower_first = 0,
			.count = 4294967295U,
		},
	},
	.gid_map = {
		.nr_extents = 1,
		.extent[0] = {
			.first = 0,
			.lower_first = 0,
			.count = 4294967295U,
		},
	},
	.projid_map = {
		.nr_extents = 1,
		.extent[0] = {
			.first = 0,
			.lower_first = 0,
			.count = 4294967295U,
		},
	},
	.count = ATOMIC_INIT(3),
	.owner = GLOBAL_ROOT_UID,
	.group = GLOBAL_ROOT_GID,
	.proc_inum = PROC_USER_INIT_INO,
	.flags = USERNS_INIT_FLAGS,
#ifdef CONFIG_PERSISTENT_KEYRINGS
	.persistent_keyring_register_sem =
	__RWSEM_INITIALIZER(init_user_ns.persistent_keyring_register_sem),
#endif
};
```

##### /proc/pid/uid_map

`uid_map`文件定义了`pid`进程所属namespace和open该文件的进程所属namespace的`User ID`的mapping关系。

基本的内容格式
```
Start-In	Start-Ou	Length
        0          0 	4294967295
```
表示前两个字段分别表示在两个namespace下映射关系的起始`User ID`，最后一个字段表示这一关系的映射长度。
例如`100	100		2`表示在两个namespace下`100-100`,`101-101`相互映射。


`/proc/pid/uid_map`文件的相关操作函数定义在`seq->operation`结构下

```c
const struct seq_operations proc_uid_seq_operations = {
	.start = uid_m_start,
	.stop = m_stop,
	.next = m_next,
	.show = uid_m_show,
};
```

当userspace进程读取 /proc/pid/uid_map文件时，将调用`proc_id_map_open`函数构造`seq_file`文件结构

```c
static int proc_id_map_open(struct inode *inode, struct file *file,
	const struct seq_operations *seq_ops)
{
	struct user_namespace *ns = NULL;
	struct task_struct *task;
	struct seq_file *seq;
	int ret = -EINVAL;

	task = get_proc_task(inode);
	if (task) {
		rcu_read_lock();
		ns = get_user_ns(task_cred_xxx(task, user_ns));
		rcu_read_unlock();
		put_task_struct(task);
	}
	if (!ns)
		goto err;

	ret = seq_open(file, seq_ops);
	if (ret)
		goto err_put_ns;

	seq = file->private_data;
	seq->private = ns;

	return 0;
err_put_ns:
	put_user_ns(ns);
err:
	return ret;
}

```

其中`seq`由`file->private_data`初始化而来，`seq->private`存着`/proc/pid/uid_map` pid进程的user namespace。

`uid_m_show`定义了显示文件内容的方法

```c
static int uid_m_show(struct seq_file *seq, void *v)
{
	struct user_namespace *ns = seq->private;
	struct uid_gid_extent *extent = v;
	struct user_namespace *lower_ns;
	uid_t lower;

	lower_ns = seq_user_ns(seq);
	if ((lower_ns == ns) && lower_ns->parent)
		lower_ns = lower_ns->parent;

	lower = from_kuid(lower_ns, KUIDT_INIT(extent->lower_first));

	seq_printf(seq, "%10u %10u %10u\n",
		extent->first,
		lower,
		extent->count);

	return 0;
}

static inline struct user_namespace *seq_user_ns(struct seq_file *seq)
{
#ifdef CONFIG_USER_NS
	return seq->user_ns;
#else
	extern struct user_namespace init_user_ns;
	return &init_user_ns;
#endif
}
```

其中`lower_ns`是根据`open`的`seq_file`文件获取的访问该文件的进程`user namespace`；

`ns`是`open(/proc/pid/uid_map)`进程的`user namespace`，`extent`是被open的pid进程user namespace下的`uid_gid_extent`。
当`opener`和`opened`属于同一个namespace时，`lower_ns = lower_ns->parent`获取父namespace，在`open(/proc/self/uid_map)`时就是这种情况。

因此，（在不同usernamespace下）不同的进程读取同一个/proc/pid/uid_map获取的内容可能会不同。





