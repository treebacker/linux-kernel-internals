### Description
`unshare`允许一个进程（线程）将它原本和其他进程（线程）共享的资源分离为独享。
例如：命名空间（fork创建时共享）、虚拟内存（clone创建时共享)。
主要用于允许进程将在`clone`进程创建时允许贡献的资源调整为独享，而不需要重新创建进程。

### Function and params
```
int unshare(int flags)
```
它只有一个`flags`参数用于指定需要`unshare`的资源类型,是和`clone`可允许共享的资源对应的.



### Syscall
实现代码在`kernel/fork.c` ksys_unshare中

首先根据给定的`flags`，增加其需要依赖的资源（注释里由说明）
```c
	/*
	 * If unsharing a user namespace must also unshare the thread group
	 * and unshare the filesystem root and working directories.
	 */
	if (unshare_flags & CLONE_NEWUSER)
		unshare_flags |= CLONE_THREAD | CLONE_FS;
	/*
	 * If unsharing vm, must also unshare signal handlers.
	 */
	if (unshare_flags & CLONE_VM)
		unshare_flags |= CLONE_SIGHAND;
	/*
	 * If unsharing a signal handlers, must also unshare the signal queues.
	 */
	if (unshare_flags & CLONE_SIGHAND)
		unshare_flags |= CLONE_THREAD;
	/*
	 * If unsharing namespace, must also unshare filesystem information.
	 */
	if (unshare_flags & CLONE_NEWNS)
		unshare_flags |= CLONE_FS;

```
然后根据给定的`flags`新建资源，修改当前进程的资源。
以`CLONE_FS`为例
```c
	err = unshare_fs(unshare_flags, &new_fs);

static int unshare_fs(unsigned long unshare_flags, struct fs_struct **new_fsp)
{
	struct fs_struct *fs = current->fs;

	if (!(unshare_flags & CLONE_FS) || !fs)
		return 0;

	/* don't need lock here; in the worst case we'll do useless copy */
	if (fs->users == 1)
		return 0;

	*new_fsp = copy_fs_struct(fs);
	if (!*new_fsp)
		return -ENOMEM;

	return 0;
}
```
如果指定了`CLONE_FS`，将当前进程的`fs_struct`copy一份，重新赋给当前进程
```c
		if (new_fs) {
			fs = current->fs;
			spin_lock(&fs->lock);
			current->fs = new_fs;
			if (--fs->users)
				new_fs = NULL;
			else
				new_fs = fs;
			spin_unlock(&fs->lock);
		}

```
这里在修改当前进程的`fs`之后，递减原`fs`的`users`引用，如果引用递减为0，将在退出前释放原`fs`实例
```c
	if (new_fs)
		free_fs_struct(new_fs);
```



#### Refer
`Kernel-Document-userspace-api/unshare.rst`
[man-unshare](https://man7.org/linux/man-pages/man2/unshare.2.html)
