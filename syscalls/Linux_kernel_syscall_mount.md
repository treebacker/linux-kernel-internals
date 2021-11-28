### 							Linux Kernel Syscall  mount

​		众所周知，数据在磁盘上存储，格式上只是一些原始的字节码，对于用户，希望以文件的形式访问获取内容。因此，需要一个抽象层来完成这些，这就是文件系统Filesystem.

​		Linux支持很多格式的文件系统，例如ext2/3/4，proc/sys （存储系统运行时信息），nfs （网络文件系统）

当要使用一块新的磁盘（存储区）时，首先需要做的就是将它格式化为某种文件系统格式，之后需要将它挂载(mount)到操作系统上，之后，才可以访问到新的磁盘（存储区）的数据。

这篇文章主要记录mount系统调用在linux内核的实现原理。

#### mount definition

```c
       #include <sys/mount.h>

       int mount(const char *source, const char *target,
                 const char *filesystemtype, unsigned long mountflags,
                 const void *data);
```

参数`source`指定存储设备的路径，`target`指定`source`将被attach的位置路径，``filesystemtype`可以是Linux支持的文件格式的任一种（位于**/proc/filesystem**下），一个mount系统调用根据`mountflags`可以完成不同的操作，如下：

```c
MS_BIND: 	  创建一个bind mount
MS_REMOUNT:   重新挂载一个已经存在的mount
MS_SHARED / MS_PRIVATE / MS_SLAVE / MS_UNBINDABLE: 可以修改一个mount的propagation type
MS_MOVE: 	  将一个mount移动到新的location
```

值得注意的是，`source`字段虽然常见的用法是指定一个设备路径，但是也允许是一个文件/目录路径。

#### Syscall Internals

mount的内核代码实现位于`fs/namespace.c`:

```c
SYSCALL_DEFINE5(mount, char __user *, dev_name, char __user *, dir_name,
		char __user *, type, unsigned long, flags, void __user *, data)
{
	int ret;
	char *kernel_type;
	char *kernel_dev;
	unsigned long data_page;

	kernel_type = copy_mount_string(type);
	ret = PTR_ERR(kernel_type);
	if (IS_ERR(kernel_type))
		goto out_type;

	kernel_dev = copy_mount_string(dev_name);
	ret = PTR_ERR(kernel_dev);
	if (IS_ERR(kernel_dev))
		goto out_dev;

	ret = copy_mount_options(data, &data_page);
	if (ret < 0)
		goto out_data;

	ret = do_mount(kernel_dev, dir_name, kernel_type, flags,
		(void *) data_page);

	free_page(data_page);
out_data:
	kfree(kernel_dev);
out_dev:
	kfree(kernel_type);
out_type:
	return ret;
}
```

这里是将userspace的函数参数拷贝到kernel space，转而交给`do_mount`完成。

```c
long do_mount(const char *dev_name, const char __user *dir_name,
		const char *type_page, unsigned long flags, void *data_page)
{
	struct path path;
	int retval = 0;
	int mnt_flags = 0;

	/* Discard magic */
	if ((flags & MS_MGC_MSK) == MS_MGC_VAL)
		flags &= ~MS_MGC_MSK;

	/* Basic sanity checks */
	if (data_page)
		((char *)data_page)[PAGE_SIZE - 1] = 0;

	/* ... and get the mountpoint */
	retval = user_path(dir_name, &path);
	if (retval)
		return retval;

	retval = security_sb_mount(dev_name, &path,
				   type_page, flags, data_page);
	if (!retval && !may_mount())
		retval = -EPERM;
	if (retval)
		goto dput_out;

	/* Default to relatime unless overriden */
	if (!(flags & MS_NOATIME))
		mnt_flags |= MNT_RELATIME;

	/* Separate the per-mountpoint flags */
	if (flags & MS_NOSUID)
		mnt_flags |= MNT_NOSUID;
	if (flags & MS_NODEV)
		mnt_flags |= MNT_NODEV;
	if (flags & MS_NOEXEC)
		mnt_flags |= MNT_NOEXEC;
	if (flags & MS_NOATIME)
		mnt_flags |= MNT_NOATIME;
	if (flags & MS_NODIRATIME)
		mnt_flags |= MNT_NODIRATIME;
	if (flags & MS_STRICTATIME)
		mnt_flags &= ~(MNT_RELATIME | MNT_NOATIME);
	if (flags & MS_RDONLY)
		mnt_flags |= MNT_READONLY;

	/* The default atime for remount is preservation */
	if ((flags & MS_REMOUNT) &&
	    ((flags & (MS_NOATIME | MS_NODIRATIME | MS_RELATIME |
		       MS_STRICTATIME)) == 0)) {
		mnt_flags &= ~MNT_ATIME_MASK;
		mnt_flags |= path.mnt->mnt_flags & MNT_ATIME_MASK;
	}

	flags &= ~(MS_NOSUID | MS_NOEXEC | MS_NODEV | MS_ACTIVE | MS_BORN |
		   MS_NOATIME | MS_NODIRATIME | MS_RELATIME| MS_KERNMOUNT |
		   MS_STRICTATIME);

	if (flags & MS_REMOUNT)
		retval = do_remount(&path, flags & ~MS_REMOUNT, mnt_flags,
				    data_page);
	else if (flags & MS_BIND)
		retval = do_loopback(&path, dev_name, flags & MS_REC);
	else if (flags & (MS_SHARED | MS_PRIVATE | MS_SLAVE | MS_UNBINDABLE))
		retval = do_change_type(&path, flags);
	else if (flags & MS_MOVE)
		retval = do_move_mount(&path, dev_name);
	else
		retval = do_new_mount(&path, type_page, flags, mnt_flags,
				      dev_name, data_page);
dput_out:
	path_put(&path);
	return retval;
}
```

`do_mount`根据userspace指定的`dev_name`（source）和`dir_name`（target）构造一个`struct path`

```c
struct path {
	struct vfsmount *mnt;				// dev_name
	struct dentry *dentry;				// dir_name
};
```

之后根据userspace指定的`mountflags`调用不同的`do_xxx_`完成，例如`do_remount`重新挂载一个已经存在的mountpoint，`do_change_type`修改已经存在的mountpoint的propagation type，指定了`MS_BIND`时，由`do_loopback`完成。

默认情况下调用`do_new_mount`创建一个新的mountpoint

```c
/*
 * create a new mount for userspace and request it to be added into the
 * namespace's tree
 */
static int do_new_mount(struct path *path, const char *fstype, int flags,
			int mnt_flags, const char *name, void *data)
{
	struct file_system_type *type;
	struct user_namespace *user_ns = current->nsproxy->mnt_ns->user_ns;
	struct vfsmount *mnt;
	int err;

	if (!fstype)
		return -EINVAL;

	type = get_fs_type(fstype);
	if (!type)
		return -ENODEV;

	if (user_ns != &init_user_ns) {
		if (!(type->fs_flags & FS_USERNS_MOUNT)) {
			put_filesystem(type);
			return -EPERM;
		}
		/* Only in special cases allow devices from mounts
		 * created outside the initial user namespace.
		 */
		if (!(type->fs_flags & FS_USERNS_DEV_MOUNT)) {
			flags |= MS_NODEV;
			mnt_flags |= MNT_NODEV | MNT_LOCK_NODEV;
		}
		if (type->fs_flags & FS_USERNS_VISIBLE) {
			if (!fs_fully_visible(type, &mnt_flags))
				return -EPERM;
		}
	}

	mnt = vfs_kern_mount(type, flags, name, data);
	if (!IS_ERR(mnt) && (type->fs_flags & FS_HAS_SUBTYPE) &&
	    !mnt->mnt_sb->s_subtype)
		mnt = fs_set_subtype(mnt, fstype);

	put_filesystem(type);
	if (IS_ERR(mnt))
		return PTR_ERR(mnt);

	err = do_add_mount(real_mount(mnt), path, mnt_flags);
	if (err)
		mntput(mnt);
	return err;
}
```

`do_new_mount`调用`vfs_kern_mount`在userspace指定的`dev_name`（source）创建一个mount

```c
vfs_kern_mount(struct file_system_type *type, int flags, const char *name, void *data)
{
	struct mount *mnt;
	struct dentry *root;

	if (!type)
		return ERR_PTR(-ENODEV);

	mnt = alloc_vfsmnt(name);
	if (!mnt)
		return ERR_PTR(-ENOMEM);

	if (flags & MS_KERNMOUNT)
		mnt->mnt.mnt_flags = MNT_INTERNAL;

	root = mount_fs(type, flags, name, data);
	if (IS_ERR(root)) {
		mnt_free_id(mnt);
		free_vfsmnt(mnt);
		return ERR_CAST(root);
	}

	mnt->mnt.mnt_root = root;
	mnt->mnt.mnt_sb = root->d_sb;
	mnt->mnt_mountpoint = mnt->mnt.mnt_root;
	mnt->mnt_parent = mnt;
	lock_mount_hash();
	list_add_tail(&mnt->mnt_instance, &root->d_sb->s_mounts);
	unlock_mount_hash();
	return &mnt->mnt;
}
```

这里的`mount_fs`调用`struct file_system_type`即文件系统注册的mount函数，返回dev_name的super_block的dentry结构，用于初始化新建的mount。

最后调用`do_add_mount`将新建的mount 添加到当前namespace下的mount tree中

```c
/*
 * add a mount into a namespace's mount tree
 */
static int do_add_mount(struct mount *newmnt, struct path *path, int mnt_flags)
{
	struct mountpoint *mp;
	struct mount *parent;
	int err;

	mnt_flags &= ~MNT_INTERNAL_FLAGS;

	mp = lock_mount(path);
	if (IS_ERR(mp))
		return PTR_ERR(mp);

	parent = real_mount(path->mnt);
	err = -EINVAL;
	if (unlikely(!check_mnt(parent))) {
		/* that's acceptable only for automounts done in private ns */
		if (!(mnt_flags & MNT_SHRINKABLE))
			goto unlock;
		/* ... and for those we'd better have mountpoint still alive */
		if (!parent->mnt_ns)
			goto unlock;
	}

	/* Refuse the same filesystem on the same mount point */
	err = -EBUSY;
	if (path->mnt->mnt_sb == newmnt->mnt.mnt_sb &&
	    path->mnt->mnt_root == path->dentry)
		goto unlock;

	err = -EINVAL;
	if (S_ISLNK(newmnt->mnt.mnt_root->d_inode->i_mode))
		goto unlock;

	newmnt->mnt.mnt_flags = mnt_flags;
	err = graft_tree(newmnt, parent, mp);

unlock:
	unlock_mount(mp);
	return err;
}
```

通过`real_mount`获取`path`本身的挂载点`parent`。

需要指出这里的`newmnt`是根据userspace指定的`dev_name`（source）创建的，`path`是userpsace指定的`dir_name`，也是`newmnt`将被挂载的location。

这里做了一些检查校验，例如不允许同一个目录下挂载两次相同的filesystem.

最终通过下面的代码路径设置`newmnt`和`parent mount`的结构关系。

```c
graft_tree(newmnt, parent, mp);
	--> attach_recursive_mnt(mnt, p, mp, NULL);
		--> 	mnt_set_mountpoint(dest_mnt, dest_mp, source_mnt);
				commit_tree(source_mnt, NULL);
```

#### Refer

[mount-man](https://man7.org/linux/man-pages/man2/mount.2.html)

[sharedsubtree](https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt)

[linux-syscall-mount](https://terenceli.github.io/%E6%8A%80%E6%9C%AF/2019/02/23/linux-system-call-mount)