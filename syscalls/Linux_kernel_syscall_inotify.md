### 					Linux Kernel Syscall inotify

#### 简述

inotify是Linux提供的用于监视filesystem的一种机制，可用于监视文件、目录；当监视的是目录时，该目录下的文件的也会被监听。

#### User Space

##### 一个简单的使用inotify的示例：

```c
int main(int argc, char** argv)
{

	int fd, wd;
	int i, length;
	
	char buffer[BUF_LEN];
	struct inotify_event* event = NULL;

	fd = inotify_init();
	if(fd < 0){
		perror("inotify_init");
	}

	wd = inotify_add_watch(fd, "/tmp",
					 IN_MODIFY | IN_CREATE | IN_DELETE );

	if(wd < 0)
	{
		perror("inotify_add_watch");
	}


	while(1)
	{
		i = 0;
		length = read(fd, buffer, BUF_LEN);
		if(length < 0){
			perror("read");
		}

		while(i < length)
		{
			event = (struct inotify_event*)&buffer[i];

			if(event -> len)
			{
				switch(event -> mask)
				{
					case IN_MODIFY:
						log_event(event->name, "modified");
						break;
					case IN_CREATE:
						log_event(event->name, "created");
						break;
					case IN_DELETE:
						log_event(event->name, "deleted");
						break;
				}
			}

			i += (event->len + EVENT_SIZE);
		}
	}
	inotify_rm_watch(fd, wd);
	close(fd);
	return 0;
}
```

主要的流程：

**inotify_init**创建一个监控实例，本质是一个文件描述符`file descriptor`，用于对inotify事件的读取。

**inotify_add_watch**用于添加想要监控的目录/文件，可以指定以下监听的事件：

```
 IN_ACCESS    文件被访问  （读、写、执行）
 IN_ATTRIB	  文件元数据被修改 （时间戳、权限属性等）
 IN_CLOSE_WRITE  以write打开的文件被关闭
 IN_CLOSE_NOWRITE 以非write打开的文件被关闭
 IN_CREATE 		在监控的目录下新建了文件/目录
 IN_DELETE 		在监控的目录下删除了文件/目录
 IN_DELETE_SELF	被监控的文件/目录自身被删除
 IN_MODIFY 		文件被修改  （write | truncate）
 IN_MOVE_SELF	被监控的文件/目录 被移动
 IN_MOVED_FROM  被移动的文件的原文件名
 IN_MOVED_TO 	被移动的文件的目的文件名
 IN_OPEN 		文件/目录 被 open
```

##### 注意点

inotify的监控基于`inode`，对于监控的文件（非目录），该文件的任何link的事件也会被监控。

对于监控的目录；目录本身和目录下的文件都会被监控。

#### Kernel Space

inotify的linux kernel 实现在`fs/notify/inotify/`下，分析的主要文件`inotify_user.c`。

##### 结构体

###### fsnotify_group

实际的inotify实例，每次`inotify_init`都会创建一个`fsnotify_group`，并与返回的文件描述符对应的`strcut file`关联。

###### fsnotify_mark

实际的inotify watch实例，每调用`inotfy_add_watch`时新建一个fsnotify_mark，用于辅助inofity实例管理监听的事件以及文件inode，例如监听CREATE、DELETE事件。

mask  该fsnotify_mark下监听的事件类型；

obj_list保存着所有被监听的文件inode列表；

group记录着该fsnotify_mark属于的inofity实例

```c
struct fsnotify_mark {
	/* Mask this mark is for [mark->lock, group->mark_mutex] */
	__u32 mask;
	/* We hold one for presence in g_list. Also one ref for each 'thing'
	 * in kernel that found and may be using this mark. */
	refcount_t refcnt;
	/* Group this mark is for. Set on mark creation, stable until last ref
	 * is dropped */
	struct fsnotify_group *group;
	/* List of marks by group->marks_list. Also reused for queueing
	 * mark into destroy_list when it's waiting for the end of SRCU period
	 * before it can be freed. [group->mark_mutex] */
	struct list_head g_list;
	/* Protects inode / mnt pointers, flags, masks */
	spinlock_t lock;
	/* List of marks for inode / vfsmount [connector->lock, mark ref] */
	struct hlist_node obj_list;
	/* Head of list of marks for an object [mark ref] */
	struct fsnotify_mark_connector *connector;
	/* Events types to ignore [mark->lock, group->mark_mutex] */
	__u32 ignored_mask;
#define FSNOTIFY_MARK_FLAG_IGNORED_SURV_MODIFY	0x01
#define FSNOTIFY_MARK_FLAG_ALIVE		0x02
#define FSNOTIFY_MARK_FLAG_ATTACHED		0x04
	unsigned int flags;		/* flags [mark->lock] */
};
```

###### inode

inode->i_fsnotify_marks保存了监听该inode的所有watch实例(fsnotify_mark）；

```c
struct inode {
	umode_t			i_mode;
	unsigned short		i_opflags;
	kuid_t			i_uid;
	kgid_t			i_gid;
	unsigned int		i_flags;
....

#ifdef CONFIG_FSNOTIFY
	__u32			i_fsnotify_mask; /* all events this inode cares about */
	struct fsnotify_mark_connector __rcu	*i_fsnotify_marks;
#endif
...
} __randomize_layout;
```

###### 

`fsnotify_mark`是连接`fsnotify_group`和`inode`的桥梁：`fsnotify_group->mark_list`维护了所有的`fsnotify_mark`（一个group可以为不同的文件/目录有不同的监听类型mask，每种mask下被监听的文件/目录由一个fsnotify_mark维护）；

`fsnotify_mark.obj_list`维护了mask类型下被监听的inode列表，`inode->i_fsnotify_marks`保存了监听该inode的所有inotify实例。

##### 代码细节

这一部分的分析主要对照上述user space使用inotify的实现。

###### inotify_init

```c
/* inotify syscalls */
static int do_inotify_init(int flags)
{
	struct fsnotify_group *group;
	int ret;

	/* Check the IN_* constants for consistency.  */
	BUILD_BUG_ON(IN_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON(IN_NONBLOCK != O_NONBLOCK);

	if (flags & ~(IN_CLOEXEC | IN_NONBLOCK))
		return -EINVAL;

	/* fsnotify_obtain_group took a reference to group, we put this when we kill the file in the end */
	group = inotify_new_group(inotify_max_queued_events);
	if (IS_ERR(group))
		return PTR_ERR(group);
	// group as the file_ops's private data
	ret = anon_inode_getfd("inotify", &inotify_fops, group,
				  O_RDONLY | flags);
	if (ret < 0)
		fsnotify_destroy_group(group);

	return ret;
}
```

在这里主要创建一个`fsnotify_group`，即inotify监听实例；

之后创建一个inotify实例的文件描述符，指定文件描述符的函数指针

```c
// group as the file_ops's private data
ret = anon_inode_getfd("inotify", &inotify_fops, group,
	O_RDONLY | flags);
	
static const struct file_operations inotify_fops = {
	.show_fdinfo	= inotify_show_fdinfo,
	.poll		= inotify_poll,
	.read		= inotify_read,
	.fasync		= fsnotify_fasync,
	.release	= inotify_release,
	.unlocked_ioctl	= inotify_ioctl,
	.compat_ioctl	= inotify_ioctl,
	.llseek		= noop_llseek,
};
```

这里创建了inode、struct file关联文件描述符，并将inotify_fops初始化为`file_operations`，用于对inotify实例的读写等文件操作。

```c
inode =	anon_inode_inode;
...

file = alloc_file_pseudo(inode, anon_inode_mnt, name,
				 flags & (O_ACCMODE | O_NONBLOCK), fops);
	if (IS_ERR(file))
		goto err_iput;
	file->f_mapping = inode->i_mapping;
	file->private_data = priv;				// inotify实例 group
	return file;
```

###### inotify_add_watch

添加用户指定的pathname到inotify 实例监控。

```
struct path {
	struct vfsmount *mnt;					// 挂载点
	struct dentry *dentry;					// 目录
} __randomize_layout;

SYSCALL_DEFINE3(inotify_add_watch, int, fd, const char __user *, pathname,
		u32, mask)
{
	struct fsnotify_group *group;
	struct inode *inode;
	struct path path;
	struct fd f;
	int ret;
	unsigned flags = 0;
...
	/* verify that this is indeed an inotify instance */
	if (unlikely(f.file->f_op != &inotify_fops)) {
		ret = -EINVAL;
		goto fput_and_out;
	}
...
}
```

首先检查了给定的fd是否是一个inotify实例（f_op是否是inotify_fops）、

之后根据给定的pathname得到具体的inode

```c
	ret = inotify_find_inode(pathname, &path, flags,
			(mask & IN_ALL_EVENTS));
	if (ret)
		goto fput_and_out;

	/* inode held in place by reference to path; group by fget on fd */
	inode = path.dentry->d_inode;
	group = f.file->private_data;
```

实际实现由`user_path_at`解析，最终调用`filename_lookup`实现路径的解析。

并对指定的文件权限做了检查，是否相应的权限。

```c
/*
 * find_inode - resolve a user-given path to a specific inode
 */
static int inotify_find_inode(const char __user *dirname, struct path *path,
						unsigned int flags, __u64 mask)
{
	int error;

	error = user_path_at(AT_FDCWD, dirname, flags, path);
	if (error)
		return error;
	/* you can only watch an inode if you have read permissions on it */
	error = path_permission(path, MAY_READ);
	if (error) {
		path_put(path);
		return error;
	}
	error = security_path_notify(path, mask,
				FSNOTIFY_OBJ_TYPE_INODE);
	if (error)
		path_put(path);

	return error;
}
```

正确的解析指定的文件/目录之后获取inode后，在inotify实例中添加该inode监控

```c
	/* create/update an inode mark */
	ret = inotify_update_watch(group, inode, mask);
```

```c
static int inotify_update_watch(struct fsnotify_group *group, struct inode *inode, u32 arg)
{
	int ret = 0;

	mutex_lock(&group->mark_mutex);
	/* try to update and existing watch with the new arg */
	ret = inotify_update_existing_watch(group, inode, arg);
	/* no mark present, try to add a new one */
	if (ret == -ENOENT)
		ret = inotify_new_watch(group, inode, arg);
	mutex_unlock(&group->mark_mutex);

	return ret;
}
```

调用inotify_add_watch时，可能该inode已经被当前inotify实例监控，只是需要调整监听的类型。

此时只需要inotify_update_existing_watch更新mask即可。

反之，需要添加一个watch，inotify_new_watch新建一个fsnotify_mark关联group和inode。

##### Why

上面描述的都是inotify的user space使用和在内核态的实现，但是一直忽略了一个问题，就是为什么fs上的文件变化产生的event可以被这里创建的inofity实例监听到。

在`fs/notify/fsnotify`下定义的函数`fsnotifys就是关键

```c
/*
 * fsnotify - This is the main call to fsnotify.
 *
 * The VFS calls into hook specific functions in linux/fsnotify.h.
 * Those functions then in turn call here.  Here will call out to all of the
 * registered fsnotify_group.  Those groups can then use the notification event
 * in whatever means they feel necessary.
 *
 * @mask:	event type and flags
 * @data:	object that event happened on
 * @data_type:	type of object for fanotify_data_XXX() accessors
 * @dir:	optional directory associated with event -
 *		if @file_name is not NULL, this is the directory that
 *		@file_name is relative to
 * @file_name:	optional file name associated with event
 * @inode:	optional inode associated with event -
 *		either @dir or @inode must be non-NULL.
 *		if both are non-NULL event may be reported to both.
 * @cookie:	inotify rename cookie
 */
int fsnotify(__u32 mask, const void *data, int data_type, struct inode *dir,
	     const struct qstr *file_name, struct inode *inode, u32 cookie)
{
	...
}
```

VFS对inode操作时会调用fsnotify_xx函数，最终将会调用`fsnotify`函数，后者将调用所有注册的fsnotify实例（这里是inotify），进而获得各种监听事件。



#### 参考

[man-syscall-inotify](https://man7.org/linux/man-pages/man7/inotify.7.html)

[dive-into-inotify](https://hustcat.github.io/dive-into-inotify-and-overlayfs/)