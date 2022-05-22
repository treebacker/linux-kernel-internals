##              Syscall     Splice

Splice系统调用可以在两个`fd`之间移动数据而不需要在`kernel/userspace`之间多次copy，
这两个fd中必须有一个是`pipe`fd。

### 函数原型

```
      ssize_t splice(int fd_in, off64_t *off_in, int fd_out,
                      off64_t *off_out, size_t len, unsigned int flags);
```

对于`fd_in`和`off_in`:
* 如果`fd_in`是pipe fd，`off_in`必须是NULL
* 如果`fd_in`不是pipe fd，而`off_in`是NULL，则将从`fd_in`文件当前`offset`开始读取`len`长度的字符，并相应地更新文件`offset`
* 如果`fd_in`不是pipe fd，而`off_in`不是NULL，`off_in`是一个指定`offset`的指针，将从该`offset`开始读取`len`长度的字符，并且不会更新`fd_in`的offset

上述同样使用于`fd_out`和`off_out`



### splice

```
SYSCALL_DEFINE6(splice, int, fd_in, loff_t __user *, off_in,
		int, fd_out, loff_t __user *, off_out,
		size_t, len, unsigned int, flags)
{
	struct fd in, out;
	long error;

	if (unlikely(!len))
		return 0;

	if (unlikely(flags & ~SPLICE_F_ALL))
		return -EINVAL;

	error = -EBADF;
	in = fdget(fd_in);
	if (in.file) {
		out = fdget(fd_out);
		if (out.file) {
			error = __do_splice(in.file, off_in, out.file, off_out,
						len, flags);
			fdput(out);
		}
		fdput(in);
	}
	return error;
}
```
首先检查`flags`参数的合法性，`flags`只允许是以下值的组合:
```
#define SPLICE_F_ALL (SPLICE_F_MOVE|SPLICE_F_NONBLOCK|SPLICE_F_MORE|SPLICE_F_GIFT)
```
**SPLICE_F_MOVE**: 在允许的情况下，执行move page的操作而不需要copy。

**SPLICE_F_NONBLOCK**: 非阻塞

**SPLICE_F_MORE**: 当`fd_out`是socket描述符时使用

**SPLICE_F_GIFT**: 在vmsplice中使用

之后分别获取`fd_in`和`fd_out`的`struct file`，调用`__do_splice`。
#### __do_splice
首先检查是否存在某fd既是pipe fd，而相应的`off`非空的情况，执行失败返回
```
	if (ipipe && off_in)
		return -ESPIPE;
	if (opipe && off_out)
		return -ESPIPE;
```
接着获取用户态传递的`off_in`和`off_out`
```
	if (off_out) {
		if (copy_from_user(&offset, off_out, sizeof(loff_t)))
			return -EFAULT;
		__off_out = &offset;
	}
	if (off_in) {
		if (copy_from_user(&offset, off_in, sizeof(loff_t)))
			return -EFAULT;
		__off_in = &offset;
	}
```
再调用`do_splice`完成真正的splice的工作

##### do_splice
首先检查`in` | `out`文件的读写权限
```
	if (unlikely(!(in->f_mode & FMODE_READ) ||
		     !(out->f_mode & FMODE_WRITE)))
		return -EBADF;
```
然后处理一种特殊的case: in 和 out都是pipe fd
```
	if (ipipe && opipe) {
		if (off_in || off_out)
			return -ESPIPE;

		/* Splicing to self would be fun, but... */
		if (ipipe == opipe)
			return -EINVAL;

		if ((in->f_flags | out->f_flags) & O_NONBLOCK)
			flags |= SPLICE_F_NONBLOCK;

		return splice_pipe_to_pipe(ipipe, opipe, len, flags);
	}
```
但是pipe fd不允许指定off，且不能够 splice self pipe，最后调用`splice_pipe_to_pipe`处理这种情况。

如果`fd_in`是pipe fd，`fd_out`是file fd，根据`off_out`指定写入文件的offset或者使用`fd_out`当前的f_ops
```
		if (off_out) {
			if (!(out->f_mode & FMODE_PWRITE))
				return -EINVAL;
			offset = *off_out;
		} else {
			offset = out->f_pos;
		}
```
splice to file不允许被写入的文件是以`O_APPEND`（文件尾追加）打开的
```
		if (unlikely(out->f_flags & O_APPEND))
			return -EINVAL;
```
splice from pipe to file最后由`do_splice_from`完成（实际由file_operation->splice_write）完成
```
		file_start_write(out);
		ret = do_splice_from(ipipe, out, &offset, len, flags);
		file_end_write(out);
```
根据`off_out`决定是否更新out文件的offset
```
		if (!off_out)
			out->f_pos = offset;
		else
			*off_out = offset;
```



如果`fd_out`是pipe fd，`fd_in`是file fd，处理逻辑同上，最终由`splice_file_to_pipe`(file_ops->splice_read)完成。



最后，对于指定了`off_in`或`off_out`的，splice不会更新offset
```
	if (__off_out && copy_to_user(off_out, __off_out, sizeof(loff_t)))
		return -EFAULT;
	if (__off_in && copy_to_user(off_in, __off_in, sizeof(loff_t)))
		return -EFAULT;
```

### vmsplice

    vmsplice用于 user pages <-> pipe 之间的splice

#### 函数原型
```
   ssize_t vmsplice(int fd, const struct iovec *iov,
                        size_t nr_segs, unsigned int flags);
```
`fd`指向pipe fd
iov指向一个`iovec`结构体
```
       struct iovec {
               void  *iov_base;        /* Starting address */
               size_t iov_len;         /* Number of bytes */
           };
```
#### vmsplice

```
	f = fdget(fd);
	error = vmsplice_type(f, &type);
```
获取`fd`对应文件的type, read/write


如果是`write`，调用`vmsplice_to_pipe`将user uiov map到 pipe中
反之如果是`read`，将调用`vmsplice_to_user`从`pipe`读取内容并写入到user uiov中

##### vmsplice_to_pipe
在向pipe写入之前，等待pipe有可写的空间（not full）
```
	pipe_lock(pipe);
	ret = wait_for_space(pipe, flags);
```
```
static int wait_for_space(struct pipe_inode_info *pipe, unsigned flags)
{
	for (;;) {
		if (unlikely(!pipe->readers)) {
			send_sig(SIGPIPE, current, 0);
			return -EPIPE;
		}
		if (!pipe_full(pipe->head, pipe->tail, pipe->max_usage))
			return 0;
		if (flags & SPLICE_F_NONBLOCK)
			return -EAGAIN;
		if (signal_pending(current))
			return -ERESTARTSYS;
		pipe_wait_writable(pipe);
	}
}
```
在pipe非full时，调用`iter_to_pipe`将iovec内容写入到pipe中

### Refer
[man-splice](https://man7.org/linux/man-pages/man2/vmsplice.2.html)
