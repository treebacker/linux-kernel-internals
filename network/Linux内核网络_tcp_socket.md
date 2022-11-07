Linux网络编程中，第一步就是创建一个`socket`，这里记录一下内核中`socket`的实现细节。
socket对应的源码`net/socket.c`
```c
int __sys_socket(int family, int type, int protocol)
{
	int retval;
	struct socket *sock;
	int flags;
    ...
	flags = type & ~SOCK_TYPE_MASK;
	if (flags & ~(SOCK_CLOEXEC | SOCK_NONBLOCK))
		return -EINVAL;
	type &= SOCK_TYPE_MASK;

	if (SOCK_NONBLOCK != O_NONBLOCK && (flags & SOCK_NONBLOCK))
		flags = (flags & ~SOCK_NONBLOCK) | O_NONBLOCK;

	retval = sock_create(family, type, protocol, &sock);
	if (retval < 0)
		return retval;

	return sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
}
```
在对传入的通信类型`type`做一定的校验后，由`sock_create`创建`socket`结构体，再由`sock_map_fd`为创建的socket结构分配一个文件描述符
#### sock_map_fd
```c
static int sock_map_fd(struct socket *sock, int flags)
{
	struct file *newfile;
	int fd = get_unused_fd_flags(flags);
	if (unlikely(fd < 0)) {
		sock_release(sock);
		return fd;
	}

	newfile = sock_alloc_file(sock, flags, NULL);
	if (!IS_ERR(newfile)) {
		fd_install(fd, newfile);
		return fd;
	}

	put_unused_fd(fd);
	return PTR_ERR(newfile);
}
```
该函数实现比较简单，大致流程：
* 获取一个未使用的文件描述符fd
* sock_alloc_file分配一个`struct file`结构体 `newfile`
* 将`fd`和`newfile`绑定，其实就是将`fd`加入到当前进程`current-files->fdt`中，并指定该fd对应的`struct file`就是`newfile`

其中`sock_alloc_file`实现
```c
struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
{
	struct file *file;

	if (!dname)
		dname = sock->sk ? sock->sk->sk_prot_creator->name : "";

	file = alloc_file_pseudo(SOCK_INODE(sock), sock_mnt, dname,
				O_RDWR | (flags & O_NONBLOCK),
				&socket_file_ops);
	if (IS_ERR(file)) {
		sock_release(sock);
		return file;
	}

	sock->file = file;
	file->private_data = sock;
	stream_open(SOCK_INODE(sock), file);
	return file;
}
EXPORT_SYMBOL(sock_alloc_file);
```
先通过`alloc_file_pseudo`分配`struct file`结构，再将`socket`结构设置为`file`、`file`的`private_data`结构设置为`sock`
这样内核可以通过`fd`找到`file`，再通过`file`找到对应的`socket`.

`alloc_file_pseudo`最终调用`alloc_file`分配并初始化`struct file`，这里需要关注的是`socket_file_ops`
就是`socket file`的文件操作函数集。
#### sock_create
该函数实现比较复杂，简化后的流程：
```c
int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;

	/*
	 *      Check protocol is in range
	 */
	if (family < 0 || family >= NPROTO)
		return -EAFNOSUPPORT;
	if (type < 0 || type >= SOCK_MAX)
		return -EINVAL;
    ...
	/*
	 *	Allocate the socket and allow the family to set things up. if
	 *	the protocol is 0, the family is instructed to select an appropriate
	 *	default.
	 */
	sock = sock_alloc();
	if (!sock) {
		net_warn_ratelimited("socket: no more sockets\n");
		return -ENFILE;	/* Not exactly a match, but its the
				   closest posix thing */
	}

	sock->type = type;
    ...
	rcu_read_lock();
	pf = rcu_dereference(net_families[family]);
	err = -EAFNOSUPPORT;
    ...
	err = pf->create(net, sock, protocol, kern);
    ...
	return err;
}
EXPORT_SYMBOL(__sock_create);
```
首先是对socket的家族协议、通信类型都做了范围校验；
之后调用`sock_alloc`完成实质的`socket`分配
```c
struct socket *sock_alloc(void)
{
	struct inode *inode;
	struct socket *sock;

	inode = new_inode_pseudo(sock_mnt->mnt_sb);
	if (!inode)
		return NULL;

	sock = SOCKET_I(inode);

	inode->i_ino = get_next_ino();
	inode->i_mode = S_IFSOCK | S_IRWXUGO;
	inode->i_uid = current_fsuid();
	inode->i_gid = current_fsgid();
	inode->i_op = &sockfs_inode_ops;

	return sock;
}
EXPORT_SYMBOL(sock_alloc);
```
之后设置socket的type字段，根据socket的家族协议`family`不同，由`net_families[family]`获得对应的`net_proto_family`，调用`create`方法初始化socket.

##### net_proto_family
该结构定义，分别为不同的家族协议提供了自定义的初始化方法、模块类型等（可扩展家族协议）
```c
struct net_proto_family {
	int		family;
	int		(*create)(struct net *net, struct socket *sock,
				  int protocol, int kern);
	struct module	*owner;
};
```
##### `sock_register`
sock_register注册一个socket协议，net_families数组的元素就是由该函数填充的
```c
int sock_register(const struct net_proto_family *ops)
{
	int err;

	if (ops->family >= NPROTO) {
		pr_crit("protocol %d >= NPROTO(%d)\n", ops->family, NPROTO);
		return -ENOBUFS;
	}

	spin_lock(&net_family_lock);
	if (rcu_dereference_protected(net_families[ops->family],
				      lockdep_is_held(&net_family_lock)))
		err = -EEXIST;
	else {
		rcu_assign_pointer(net_families[ops->family], ops);
		err = 0;
	}
	spin_unlock(&net_family_lock);

	pr_info("NET: Registered %s protocol family\n", pf_family_names[ops->family]);
	return err;
}
EXPORT_SYMBOL(sock_register);
```
在`net/ipv4/af_inet.c`的`inet_init`函数中，注册AF_INET的net_proto_family为inet_family_ops
```c
static const struct net_proto_family inet_family_ops = {
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};
```
因此我们创建的tcp/udp socket的初始化最终是由`inet_create`完成的

#### inet_create
简化后的流程
```c
static int inet_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	struct inet_protosw *answer;
	struct inet_sock *inet;
	struct proto *answer_prot;
	unsigned char answer_flags;
	int try_loading_module = 0;
	int err;

	if (protocol < 0 || protocol >= IPPROTO_MAX)
		return -EINVAL;

	sock->state = SS_UNCONNECTED;
	/* Look for the requested type/protocol pair. */
lookup_protocol:
	err = -ESOCKTNOSUPPORT;
	rcu_read_lock();
	list_for_each_entry_rcu(answer, &inetsw[sock->type], list) {

		err = 0;
		/* Check the non-wild match. */
		if (protocol == answer->protocol) {
			if (protocol != IPPROTO_IP)
				break;
		} else {
			/* Check for the two wild cases. */
			if (IPPROTO_IP == protocol) {
				protocol = answer->protocol;
				break;
			}
			if (IPPROTO_IP == answer->protocol)
				break;
		}
		err = -EPROTONOSUPPORT;
	}
	...
	sock->ops = answer->ops;
	answer_prot = answer->prot;
	answer_flags = answer->flags;
	....

	sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
	if (!sk)
		goto out;
}
```
  * 将新建的`struct socket`实例sock的状态sock->state初始化为`SS_UNCONNECTED`
  * 遍历inetsw[sock->type]，根据socket的type和protocol找到合适的inet_protosw实例，`answer`保存该实例
	对于ipv4的TCP，type一般为SOCK_STREAM、protocol为IPPROTO_TCP，对应的实例即
	```c
		{
			.type =       SOCK_STREAM,
			.protocol =   IPPROTO_TCP,
			.prot =       &tcp_prot,
			.ops =        &inet_stream_ops,
			.flags =      INET_PROTOSW_PERMANENT |
					INET_PROTOSW_ICSK,
		},
	```
  * 将初始化sock->ops为对应的inet_protosw的ops，即`inet_stream_ops`
  * 调用`sk_alloc`分配`struct sock`实例
	```c
	struct sock *sk_alloc(struct net *net, int family, gfp_t priority,
				struct proto *prot, int kern)
	{
		struct sock *sk;

		sk = sk_prot_alloc(prot, priority | __GFP_ZERO, family);
		if (sk) {
			sk->sk_family = family;
			/*
			* See comment in struct sock definition to understand
			* why we need sk_prot_creator -acme
			*/
			sk->sk_prot = sk->sk_prot_creator = prot;
			sk->sk_kern_sock = kern;
			...
		}

		return sk;
	}
	```
该方法会初始化sock->sk_port，即`inet_protosw`中的`&tcp_prot`

  * 调用`sock_init_data`初始化sock实例
	```c
	void sock_init_data(struct socket *sock, struct sock *sk)
	{
		sk_init_common(sk);
		sk->sk_send_head	=	NULL;

		timer_setup(&sk->sk_timer, NULL, 0);

		sk->sk_allocation	=	GFP_KERNEL;
		sk->sk_rcvbuf		=	sysctl_rmem_default;
		sk->sk_sndbuf		=	sysctl_wmem_default;
		sk->sk_state		=	TCP_CLOSE;
	...
		sk->sk_state_change	=	sock_def_wakeup;
		sk->sk_data_ready	=	sock_def_readable;
		sk->sk_write_space	=	sock_def_write_space;
		sk->sk_error_report	=	sock_def_error_report;
		sk->sk_destruct		=	sock_def_destruct;
	}
	```
	其中多个回调函数，分别是在sock状态变化、有可读数据、有可写空间、报错、释放时调用
  * 调用`sk->sk_prot->init`初始化，即`&tcp_prot->init`，该字段在`net/ipv4/tcp_ipv4.c`中定义为`tcp_v4_init_sock`
	```c
	static int tcp_v4_init_sock(struct sock *sk)
	{
		struct inet_connection_sock *icsk = inet_csk(sk);

		tcp_init_sock(sk);

		icsk->icsk_af_ops = &ipv4_specific;

	#ifdef CONFIG_TCP_MD5SIG
		tcp_sk(sk)->af_specific = &tcp_sock_ipv4_specific;
	#endif

		return 0;
	}
	```
	将`icsk->icsk_af_ops`设置为`&ipv4_specific`
	并调用`tcp_init_sock`方法对tcp逻辑做了部分初始化
	```c
	void tcp_init_sock(struct sock *sk)
	{
		struct inet_connection_sock *icsk = inet_csk(sk);
		struct tcp_sock *tp = tcp_sk(sk);

		tp->out_of_order_queue = RB_ROOT;
		sk->tcp_rtx_queue = RB_ROOT;

		tp->tsoffset = 0;
		tp->rack.reo_wnd_steps = 1;
		...
		sk->sk_write_space = sk_stream_write_space;
		sock_set_flag(sk, SOCK_USE_WRITE_QUEUE);

		icsk->icsk_sync_mss = tcp_sync_mss;

		WRITE_ONCE(sk->sk_sndbuf, sock_net(sk)->ipv4.sysctl_tcp_wmem[1]);
		WRITE_ONCE(sk->sk_rcvbuf, sock_net(sk)->ipv4.sysctl_tcp_rmem[1]);

		sk_sockets_allocated_inc(sk);
	}
	```
	注意这里将`sk->sk_write_space`回调修改为了`sk_stream_write_space`，而不再是默认的`sock_def_write_space`

#### 总结一下内核创建一个tcp socket的效果
* 返回一个文件描述符fd
* 根据fd可以找到对应的struct file实例
* file->f_op实际是`&socket_file_ops`
* file->privite_data保存了struct socket实例 sock
* 
* sock->ops即为`&inet_stream_ops`
* sock->sk对应类型是`struct sock`是内核内部实际存储socket的地方
* sk->sk_prot实际是`&tcp_prot`
* sk->sk_state字段为TCP_CLOSE
* sk状态变化回调函数