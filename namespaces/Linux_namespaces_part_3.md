### Linux Namespace Part 3

#### 前言

​		[Part1](./Linux_namespaces_part_1.md)部分主要介绍了namespace的各种类型，以及在userspace使用namespace能够达到的对各种资源的隔离，在[Part2](./Linux_namespaces_part_2.md)部分从kernel space的角度剖析namespace的实现机制，并剖析了**user namespace**的相关细节，在这篇里将主要介绍**pid namespace**的实现细节。


PID namespace隔离Process ID空间，意味着在不同的PID namespaces下允许存在相同的PID。
在容器中，PID namespaces可以实现挂起/恢复容器中的一组进程、并将容器迁移到另一个host中而容器内的进程保持原PIDs。

#### 相关基础数据结构

`pid_namespace`在前面已经提到在`stask_struct -> nsproxy`中

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

`pid_namespace`结构

```c
struct pid_namespace {
	struct kref kref;
	struct pidmap pidmap[PIDMAP_ENTRIES];
	struct rcu_head rcu;
	int last_pid;
	unsigned int nr_hashed;
	struct task_struct *child_reaper;
	struct kmem_cache *pid_cachep;
	unsigned int level;
	struct pid_namespace *parent;
#ifdef CONFIG_PROC_FS
	struct vfsmount *proc_mnt;
	struct dentry *proc_self;
	struct dentry *proc_thread_self;
#endif
#ifdef CONFIG_BSD_PROCESS_ACCT
	struct bsd_acct_struct *bacct;
#endif
	struct user_namespace *user_ns;
	struct work_struct proc_work;
	kgid_t pid_gid;
	int hide_pid;
	int reboot;	/* group exit code if this pidns was rebooted */
	unsigned int proc_inum;
};
```

其中`pidmap`是一个用于管理当前`pid_namespace`下的pid value的bitmap结构，即`struct pidmap`结构

```c
struct pidmap {
       atomic_t nr_free;
       void *page;
};
```

`last_pid`记录着最后一个被使用的`pid value`；`child_reaper`是当前`pid_namespace`下的初始`init`进程；

`parent`指向当前`pid_namespace`继承的父`pid_namespace`；`user_ns`指向该`pid namespace`所在的`user namesapce`；

#### clone

调用链`clone`->`copy_namespaces`->`create_new_namespaces`->`copy_pid_ns`->`create_pid_namespace`为子进程创建新的`pid namespace`

```c
static struct pid_namespace *create_pid_namespace(struct user_namespace *user_ns,
	struct pid_namespace *parent_pid_ns)
{
	struct pid_namespace *ns;
	unsigned int level = parent_pid_ns->level + 1;		// 新建的pid_namespace level +1
	int i;
	int err;

	if (level > MAX_PID_NS_LEVEL) {
		err = -EINVAL;
		goto out;
	}

	err = -ENOMEM;		// 从pid_ns_cachep 中分配 pid_namespace
	ns = kmem_cache_zalloc(pid_ns_cachep, GFP_KERNEL);
	if (ns == NULL)
		goto out;
						// 分配pidmap 
	ns->pidmap[0].page = kzalloc(PAGE_SIZE, GFP_KERNEL);
	if (!ns->pidmap[0].page)
		goto out_free;
						// 分配 pid_chachp
	ns->pid_cachep = create_pid_cachep(level + 1);
	if (ns->pid_cachep == NULL)
		goto out_free_map;

	err = proc_alloc_inum(&ns->proc_inum);
	if (err)
		goto out_free_map;

	kref_init(&ns->kref);
	ns->level = level;
	ns->parent = get_pid_ns(parent_pid_ns);
	ns->user_ns = get_user_ns(user_ns);
	ns->nr_hashed = PIDNS_HASH_ADDING;
	INIT_WORK(&ns->proc_work, proc_cleanup_work);

	set_bit(0, ns->pidmap[0].page);
	atomic_set(&ns->pidmap[0].nr_free, BITS_PER_PAGE - 1);

	for (i = 1; i < PIDMAP_ENTRIES; i++)
		atomic_set(&ns->pidmap[i].nr_free, BITS_PER_PAGE);

	return ns;

out_free_map:
	kfree(ns->pidmap[0].page);
out_free:
	kmem_cache_free(pid_ns_cachep, ns);
out:
	return ERR_PTR(err);
}
```

`create_pid_cachep`函数 分配用于分配`struct pid`的缓存。

```c
struct upid {
	/* Try to keep pid_chain in the same cacheline as nr for find_vpid */
	int nr;
	struct pid_namespace *ns;
	struct hlist_node pid_chain;
};

struct pid
{
	atomic_t count;
	unsigned int level;
	/* lists of tasks that use this pid */
	struct hlist_head tasks[PIDTYPE_MAX];
	struct rcu_head rcu;
	struct upid numbers[1];
};
```

`struct pid`是内核中标识进程唯一性的一个概念结构，可以表一个task、或者process groups、或者sessions

分别对应三种`PIDTYPE`：

```c
enum pid_type
{
	PIDTYPE_PID,					// task
	PIDTYPE_PGID,					// process group
	PIDTYPE_SID,					// session
	PIDTYPE_MAX
};
```

由`tasks`链表结构管理。

较于`pid_t`值 或者 `task_struct`进程结构，`struct pid`有两个优势：

1、`pid_t`存在复用情况：pid_t 为 xxx的进程退出后，新起的进程的pid_t值可能也是pid_t，造成混淆错误。

2、用户进程退出后，内核中的`task_struct`结构较于`struct pid`过大，浪费空间

​	这里需要注意的是，由于每一个进程都有`level + 1`个 pid value：1个进程自身，level个`parent pid namespace`，所以分配的空间是一个`struct pid`和`level`个`struct upid`

```c
static struct kmem_cache *create_pid_cachep(int nr_ids)
{
	struct pid_cache *pcache;
	struct kmem_cache *cachep;

	mutex_lock(&pid_caches_mutex);
	list_for_each_entry(pcache, &pid_caches_lh, list)
		if (pcache->nr_ids == nr_ids)
			goto out;

	pcache = kmalloc(sizeof(struct pid_cache), GFP_KERNEL);
	if (pcache == NULL)
		goto err_alloc;

	snprintf(pcache->name, sizeof(pcache->name), "pid_%d", nr_ids);
	cachep = kmem_cache_create(pcache->name,
			sizeof(struct pid) + (nr_ids - 1) * sizeof(struct upid),
			0, SLAB_HWCACHE_ALIGN, NULL);
	if (cachep == NULL)
		goto err_cachep;

	pcache->nr_ids = nr_ids;
	pcache->cachep = cachep;
	list_add(&pcache->list, &pid_caches_lh);
out:
	mutex_unlock(&pid_caches_mutex);
	return pcache->cachep;

err_cachep:
	kfree(pcache);
err_alloc:
	mutex_unlock(&pid_caches_mutex);
	return NULL;
}
```

#### pid management

`struct pid`结构由`copy_process`->`alloc_pid`调用链创建

```c
struct pid *alloc_pid(struct pid_namespace *ns)
{
	struct pid *pid;
	enum pid_type type;
	int i, nr;
	struct pid_namespace *tmp;
	struct upid *upid;

	pid = kmem_cache_alloc(ns->pid_cachep, GFP_KERNEL);
	if (!pid)
		goto out;

	tmp = ns;
	pid->level = ns->level;
	for (i = ns->level; i >= 0; i--) {
		nr = alloc_pidmap(tmp);
		if (nr < 0)
			goto out_free;

		pid->numbers[i].nr = nr;
		pid->numbers[i].ns = tmp;
		tmp = tmp->parent;
	}

	if (unlikely(is_child_reaper(pid))) {
		if (pid_ns_prepare_proc(ns))
			goto out_free;
	}

	get_pid_ns(ns);
	atomic_set(&pid->count, 1);
	for (type = 0; type < PIDTYPE_MAX; ++type)
		INIT_HLIST_HEAD(&pid->tasks[type]);

	upid = pid->numbers + ns->level;
	spin_lock_irq(&pidmap_lock);
	if (!(ns->nr_hashed & PIDNS_HASH_ADDING))
		goto out_unlock;
	for ( ; upid >= pid->numbers; --upid) {
		hlist_add_head_rcu(&upid->pid_chain,
				&pid_hash[pid_hashfn(upid->nr, upid->ns)]);
		upid->ns->nr_hashed++;
	}
	spin_unlock_irq(&pidmap_lock);

out:
	return pid;

out_unlock:
	spin_unlock_irq(&pidmap_lock);
	put_pid_ns(ns);

out_free:
	while (++i <= ns->level)
		free_pidmap(pid->numbers + i);

	kmem_cache_free(ns->pid_cachep, pid);
	pid = NULL;
	goto out;
}
```

在第一个`for`循环中，根据`pid_namespace`下的`parent`字段遍历相关的每一个`pid_namespace (tmp)`，

`alloc_pidmap`获取进程pid value，设置当前`pid_namespace->numbers[i].nr/ns`。

在最后一个循环中，以`upid->nr`和 `upid->ns`为`key`，将`struct pid`结构存储在对应的`pid_hash`中。

在第二个循环中，初始化`pid->tasks`链表结构，该结构用于link 所有使用该`struct pid`结构的`task`，相对应的，在`task_struct`结构中的`pid_link`是用于 link `task_struct`和`pid`的

```c
struct pid_link
{
	struct hlist_node node;
	struct pid *pid;
};
```

其中`node`字段指向`pid->tasks`，`pid`字段指向`struct pid`结构。

在`copy_process`函数中，有以下代码块

```c
if (likely(p->pid)) {
		ptrace_init_task(p, (clone_flags & CLONE_PTRACE) || trace);

		init_task_pid(p, PIDTYPE_PID, pid);
		if (thread_group_leader(p)) {
			init_task_pid(p, PIDTYPE_PGID, task_pgrp(current));
			init_task_pid(p, PIDTYPE_SID, task_session(current));

			if (is_child_reaper(pid)) {
				ns_of_pid(pid)->child_reaper = p;
				p->signal->flags |= SIGNAL_UNKILLABLE;
			}

			p->signal->leader_pid = pid;
			p->signal->tty = tty_kref_get(current->signal->tty);
			list_add_tail(&p->sibling, &p->real_parent->children);
			list_add_tail_rcu(&p->tasks, &init_task.tasks);
			attach_pid(p, PIDTYPE_PGID);
			attach_pid(p, PIDTYPE_SID);
			__this_cpu_inc(process_counts);
		} else {
			current->signal->nr_threads++;
			atomic_inc(&current->signal->live);
			atomic_inc(&current->signal->sigcnt);
			list_add_tail_rcu(&p->thread_group,
					  &p->group_leader->thread_group);
			list_add_tail_rcu(&p->thread_node,
					  &p->signal->thread_head);
		}
		attach_pid(p, PIDTYPE_PID);
		nr_threads++;
	}
```

当当前新建的`task`是`thread group leader`时，初始化`task->pids[type].pid`为`current->group_leader->pids[type]`，并且attach新建的`task`到`group leader`'s->pid->tasks。

#### all releationships

梳理上述相关结构之间的关系图如下

![](images\namespace_pid.png)


### Refer
[man-pid-namespace](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html)