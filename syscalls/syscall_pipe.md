##          Syscall Pipe

pipe作为一种进程间通信的方式。每一个pipe有一个`read`和`write`端，在`write`端写入数据，在`read`端读取数据。

### 函数原型

```
    int pipe2(int pipefd[2], int flags);
    struct fd_pair {
        long fd[2];
    };
    struct fd_pair pipe(void);
```

`pipe2`创建一个新的pipe，并返回一对pipefd（文件描述符），其中pipefd[0]是pipe的`read`端，pipefd[1]是`write`端。


#### 示例代码

```
    int main(int argc, char** argv)
    {
        int fds[2];
        char msg[0x10] = { 0 };

        int r_fd = 0, w_fd = 0;
        pipe(fds);

        r_fd = fds[0];
        w_fd = fds[1];


        write(w_fd, "whoami", 6);
        read(r_fd, msg, 0x6);
        puts(msg);

        close(r_fd);
        close(w_fd);
    }
```
### Syscall实现

```
    SYSCALL_DEFINE2(pipe2, int __user *, fildes, int, flags)
    {
        return do_pipe2(fildes, flags);
    }

    SYSCALL_DEFINE1(pipe, int __user *, fildes)
    {
        return do_pipe2(fildes, 0);
}
```

当`flags = 0`时，`pipe2`和`pipe`是一样的：最终实现都是`do_pipe2`。
```
static int do_pipe2(int __user *fildes, int flags)
{
	struct file *files[2];
	int fd[2];
	int error;

	error = __do_pipe_flags(fd, files, flags);
	if (!error) {
		if (unlikely(copy_to_user(fildes, fd, sizeof(fd)))) {
			fput(files[0]);
			fput(files[1]);
			put_unused_fd(fd[0]);
			put_unused_fd(fd[1]);
			error = -EFAULT;
		} else {
			fd_install(fd[0], files[0]);
			fd_install(fd[1], files[1]);
		}
	}
	return error;
}
```

在建立pipe之前，`__do_pipe_flags`校验`flags`字段，`flags`只允许以下几个的组合
```
    if (flags & ~(O_CLOEXEC | O_NONBLOCK | O_DIRECT | O_NOTIFICATION_PIPE))
    return -EINVAL;
```

**O_CLOEXEC**: 即`close-on-exec`，新建的fd在执行`exec`函数后关闭。

**O_NONBLOCK**: 非阻塞模式

**O_DIRECT**: 新建的fd的IO操作不会使用缓存，而直接操作磁盘

**O_NOTIFICATION_PIPE**: 创建的pipe用于`notification`，`write`端不是`application`，`read`端可以传给`watch_xx`。


接着调用`create_pipe_files`为pipe分配两个`struct file`结构:
为pipe分配一个`inode`结构，并初始化inode相关数据结构
```
struct inode *inode = get_pipe_inode();
```
`alloc_pipe_info`分配一个pipe在内核中的结构体`pipe_inode_info`，

```
struct pipe_inode_info {
	struct mutex mutex;     // 互斥体
	wait_queue_head_t rd_wait, wr_wait; // reader | writer 在empty | full 情况下的等待
	unsigned int head;      // buffer 生产者
	unsigned int tail;      // buffer 消费者
	unsigned int max_usage; 
	unsigned int ring_size;
#ifdef CONFIG_WATCH_QUEUE
	bool note_loss;
#endif
	unsigned int nr_accounted;
	unsigned int readers;   // readers数目
	unsigned int writers;   // writers数目
	unsigned int files;     // 引用该pipe的 struct files数目
	unsigned int r_counter;
	unsigned int w_counter;
	unsigned int poll_usage; // 该pipe是否用于 epoll
	struct page *tmp_page;
	struct fasync_struct *fasync_readers;
	struct fasync_struct *fasync_writers;
	struct pipe_buffer *bufs;   // pipe buffers 数组
	struct user_struct *user;   // 创建该pipe的用户
#ifdef CONFIG_WATCH_QUEUE
	struct watch_queue *watch_queue;    // 在watch_queue时使用
#endif
};
```

接着调用`alloc_file_pseudo`创建writer的 `struct file`
```
	f = alloc_file_pseudo(inode, pipe_mnt, "",
				O_WRONLY | (flags & (O_NONBLOCK | O_DIRECT)),
				&pipefifo_fops);
    ...
    f->private_data = inode->i_pipe;
```

`alloc_file_clone`创建reader的`struct file`
```
	res[0] = alloc_file_clone(f, O_RDONLY | (flags & O_NONBLOCK),
				  &pipefifo_fops);
	if (IS_ERR(res[0])) {
		put_pipe_info(inode, inode->i_pipe);
		fput(f);
		return PTR_ERR(res[0]);
	}
```

这里指定的`file_operations`是`pipefifo_fops`:
```
const struct file_operations pipefifo_fops = {
	.open		= fifo_open,
	.llseek		= no_llseek,
	.read_iter	= pipe_read,
	.write_iter	= pipe_write,
	.poll		= pipe_poll,
	.unlocked_ioctl	= pipe_ioctl,
	.release	= pipe_release,
	.fasync		= pipe_fasync,
	.splice_write	= iter_file_splice_write,
};
```

在pipe的文件描述符创建完成后，调用两次`get_unused_fd_flags`分别得到reader/writer的文件描述符`fd`:
```
	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_read_pipe;
	fdr = error;

	error = get_unused_fd_flags(flags);
	if (error < 0)
		goto err_fdr;
	fdw = error;
    ...
    fd[0] = fdr;
	fd[1] = fdw;
```

最后，调用`copy_to_user`返回创建的`pipefds`，并将文件描述符和`struct file`关联起来
```
	if (!error) {
		if (unlikely(copy_to_user(fildes, fd, sizeof(fd)))) {
			fput(files[0]);
			fput(files[1]);
			put_unused_fd(fd[0]);
			put_unused_fd(fd[1]);
			error = -EFAULT;
		} else {
			fd_install(fd[0], files[0]);
			fd_install(fd[1], files[1]);
		}
	}
```

#### pipe write/read
* pipe_write
    计算写pipe的长度，长度为`0`直接执行成功返回
```
	size_t total_len = iov_iter_count(from);
	/* Null write succeeds. */
	if (unlikely(total_len == 0))
		return 0;

```

pipe在写时，上锁（pipe结构内有定义的mutex）
```
	__pipe_lock(pipe);
```

如果pipe没有了reader（全部被关闭），write操作将发送`SIGPIPE`信号，即在向pipe写的时候，必须存在reader等待消费。
```
	if (!pipe->readers) {
		send_sig(SIGPIPE, current, 0);
		ret = -EPIPE;
		goto out;
	}
```

判断当前pipe状态是否是`empty` (head == tail)
```
	head = pipe->head;
	was_empty = pipe_empty(head, pipe->tail);
	chars = total_len & (PAGE_SIZE-1);
```

优先处理写入的非`PAGE_SIZE`对齐的长度的数据(merge)，调用`copy_page_from_iter`将写入的数据拷贝到pipe缓冲区。
```
	if (chars && !was_empty) {
		unsigned int mask = pipe->ring_size - 1;
		struct pipe_buffer *buf = &pipe->bufs[(head - 1) & mask];
		int offset = buf->offset + buf->len;

		if ((buf->flags & PIPE_BUF_FLAG_CAN_MERGE) &&
		    offset + chars <= PAGE_SIZE) {
			ret = pipe_buf_confirm(pipe, buf);
			if (ret)
				goto out;

			ret = copy_page_from_iter(buf->page, offset, chars, from);
			if (unlikely(ret < chars)) {
				ret = -EFAULT;
				goto out;
			}

			buf->len += ret;
			if (!iov_iter_count(from))
				goto out;
		}
	}
```

处理完非对齐数据后，进入一个`for(;;)`循环，并在每一轮开始同样检查`reader`是否为空。
如果`pipe`没有`full`，判断`page`是否为空，为空时分配一个`page`，更新`pipe->head`递增加1，
调用`copy_page_from_iter`一次拷贝`PAGE_SIZE`到pipe缓冲区。

检查是否有更多的写入要同步到pipe缓冲区，没有就退出循环
```
    if (!iov_iter_count(from))
        break;

```

* pipe_read

pipe_read的处理流程和pipe_write基本一致（逻辑相反），有几点不同的:
  * 当没有writer时，不会产生SIGPIPE信号（允许writer被close，而reader仍然可以读取非空pipe）


### Refer

[man-pipe](https://man7.org/linux/man-pages/man7/pipe.7.html)

[watch_mount(), watch_sb(), and fsinfo() (again)](https://lwn.net/Articles/813172/)