### 简介
TCP/IP模型的网络阐述基本都是通过`socket`系统调用将数据送入协议栈的，这里记录下通过socket完成tcp数据传输的内核层路径


### 最简单的tcp client 
```c
/*==============================================================================
# Author: lang lyi4ng@gmail.com
# Filetype: C source code
# Environment: Linux & Archlinux
# Tool: Vim & Gcc
# Date: 2019.10.14
# Descprition: Randomly written code
================================================================================*/
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define MAXLEN 1024

int main(void)
{
    /*socket file description*/
    int sockfd,connc;
    char *message = "This is test\n",buf[MAXLEN];
    struct sockaddr_in servaddr;


    sockfd = socket(AF_INET, SOCK_STREAM,0);
    if(sockfd == -1){
    perror("sock created");
    exit(-1);
    }


    /*set serverAddr default=0*/
    bzero(&servaddr, sizeof(servaddr));


    /*set serverAddr info*/
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(9999);
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");


    connc = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));


    if(connc == -1){
    perror("connect error");
    exit(-1);
    }
    write(sockfd, message, strlen(message));
    read(sockfd, buf, MAXLEN);
    close(sockfd);
    return 0;
}
```
一个最简单的tcp client流程：`socket->connect->write/read`

#### socket
socket相关实现在`net/socket.c`中
```c
int __sys_socket(int family, int type, int protocol)
{
	int retval;
	struct socket *sock;
	int flags;

	/* Check the SOCK_* constants for consistency.  */
	BUILD_BUG_ON(SOCK_CLOEXEC != O_CLOEXEC);
	BUILD_BUG_ON((SOCK_MAX | SOCK_TYPE_MASK) != SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_CLOEXEC & SOCK_TYPE_MASK);
	BUILD_BUG_ON(SOCK_NONBLOCK & SOCK_TYPE_MASK);

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
实际通过`sock_create`创建一个`struct socket`结构，为它分配一个`fd`描述符，并返回描述符。
最终通过`__sock_create`创建的`socket`结构，简化的创建流程
```c
int __sock_create(struct net *net, int family, int type, int protocol,
			 struct socket **res, int kern)
{
	int err;
	struct socket *sock;
	const struct net_proto_family *pf;
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
	if (!pf)
		goto out_release;

	/*
	 * We will call the ->create function, that possibly is in a loadable
	 * module, so we have to bump that loadable module refcnt first.
	 */
	if (!try_module_get(pf->owner))
		goto out_release;

	/* Now protected by module ref count */
	rcu_read_unlock();

	err = pf->create(net, sock, protocol, kern);
	if (err < 0)
		goto out_module_put;

	/*
	 * Now to bump the refcnt of the [loadable] module that owns this
	 * socket at sock_release time we decrement its refcnt.
	 */
	if (!try_module_get(sock->ops->owner))
		goto out_module_busy;

	/*
	 * Now that we're done with the ->create function, the [loadable]
	 * module can have its refcnt decremented
	 */
	module_put(pf->owner);
	err = security_socket_post_create(sock, family, type, protocol, kern);
	if (err)
		goto out_sock_release;
	*res = sock;

	return 0;

    ...
}
EXPORT_SYMBOL(__sock_create);
```
整个流程很清晰，先通过`sock_alloc`分配一个`socket`地址空间
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
这里实际是分配一个`inode`，通过`container_of`魔法拿到`socket`结构地址，实质上而这被绑定为`socket_alloc`
```c
struct socket_alloc {
	struct socket socket;
	struct inode vfs_inode;
};
```


就是根据`socket`指定的协议`family`，查询全局数组`net_families`得到一个`net_proto_family`指针
```c
struct net_proto_family {
	int		family;
	int		(*create)(struct net *net, struct socket *sock,
				  int protocol, int kern);
	struct module	*owner;
};
```
再调用`create`方法创建对应family的`socket`结构。
`net_families`数组是一个全局数组，保留了内核注册的所有协议族的`net_proto_family`结构
可以通过`sock_register`注册一个协议簇
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
在`net/ipv4/af_inet.c:inet_init`网络初始化中注册了`TCP/IP`协议簇
```c
static const struct net_proto_family inet_family_ops = {
	.family = PF_INET,
	.create = inet_create,
	.owner	= THIS_MODULE,
};

static int __init inet_init(void)
{
	struct inet_protosw *q;
	struct list_head *r;
	int rc;
    ...

	(void)sock_register(&inet_family_ops);
    ...
}
```
从这里可以知道了，最终`socket`的创建是`inet_create`完成的。

#### connect
一个TCP通信是从client发起`connect`开始的
```c
int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
{
	int ret = -EBADF;
	struct fd f;
    //获取struct fd
	f = fdget(fd);
	if (f.file) {
		struct sockaddr_storage address;
        // 将用户态传进来的`struct sockaddr`结构通过`copy_from_user`复制到内核
		ret = move_addr_to_kernel(uservaddr, addrlen, &address);
		if (!ret)
			ret = __sys_connect_file(f.file, &address, addrlen, 0);
		fdput(f);
	}

	return ret;
}
```
再由`__sys_connect_file`完成
```c
int __sys_connect_file(struct file *file, struct sockaddr_storage *address,
		       int addrlen, int file_flags)
{
	struct socket *sock;
	int err;
    // 通过struc file获取对应的struct socket结构
	sock = sock_from_file(file);
	if (!sock) {
		err = -ENOTSOCK;
		goto out;
	}

	err =
	    security_socket_connect(sock, (struct sockaddr *)address, addrlen);
	if (err)
		goto out;
    // 由socket->ops->connect完成connect
	err = sock->ops->connect(sock, (struct sockaddr *)address, addrlen,
				 sock->file->f_flags | file_flags);
out:
	return err;
}
```
最终由`struct socket`->ops->connect完成connect动作.
同样在`inet_init`函数中，初始化了一个全局链表`inetsw`
```c
/* Upon startup we insert all the elements in inetsw_array[] into
 * the linked list inetsw.
 */
static struct inet_protosw inetsw_array[] =
{
	{
		.type =       SOCK_STREAM,
		.protocol =   IPPROTO_TCP,
		.prot =       &tcp_prot,
		.ops =        &inet_stream_ops,
		.flags =      INET_PROTOSW_PERMANENT |
			      INET_PROTOSW_ICSK,
	},

	{
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_UDP,
		.prot =       &udp_prot,
		.ops =        &inet_dgram_ops,
		.flags =      INET_PROTOSW_PERMANENT,
       },

       {
		.type =       SOCK_DGRAM,
		.protocol =   IPPROTO_ICMP,
		.prot =       &ping_prot,
		.ops =        &inet_sockraw_ops,
		.flags =      INET_PROTOSW_REUSE,
       },

       {
	       .type =       SOCK_RAW,
	       .protocol =   IPPROTO_IP,	/* wild card */
	       .prot =       &raw_prot,
	       .ops =        &inet_sockraw_ops,
	       .flags =      INET_PROTOSW_REUSE,
       }
};
...
	/* Register the socket-side information for inet_create. */
	for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
		INIT_LIST_HEAD(r);

	for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
		inet_register_protosw(q);
```
因此最终`SOCK_STREAM`的TCP发起的connect由`inet_stream_ops->connect`即`inet_stream_connect->__inet_stream_connect`完成:
* 首先检查传入的`struct sockaddr`长度，针对`AF_UNSPEC`协议做了特殊检查：断开连接`disconnect`，柑橘返回值设置`struct sock`状态
* 根据`struct sock`的状态字段`state`做不同处理
  * 如果已经处于`SS_CONNECTED`连接状态，返回`EISCONN`
  * 如果处于正在连接状态`SS_CONNECTING`（多线程并发），返回对应的错误值
  * 正常情况下都是处于`SS_UNCONNECTED`未连接状态，调用`sk->sk_prot->connect(sk, uaddr, addr_len);`
并修改`struct sock`状态为`SS_CONNECTING`。
```c
/*
 *	Connect to a remote host. There is regrettably still a little
 *	TCP 'magic' in here.
 */
int __inet_stream_connect(struct socket *sock, struct sockaddr *uaddr,
			  int addr_len, int flags, int is_sendmsg)
{
	struct sock *sk = sock->sk;
	int err;
	long timeo;

	/*
	 * uaddr can be NULL and addr_len can be 0 if:
	 * sk is a TCP fastopen active socket and
	 * TCP_FASTOPEN_CONNECT sockopt is set and
	 * we already have a valid cookie for this socket.
	 * In this case, user can call write() after connect().
	 * write() will invoke tcp_sendmsg_fastopen() which calls
	 * __inet_stream_connect().
	 */
	if (uaddr) {
		if (addr_len < sizeof(uaddr->sa_family))
			return -EINVAL;

		if (uaddr->sa_family == AF_UNSPEC) {
			err = sk->sk_prot->disconnect(sk, flags);
			sock->state = err ? SS_DISCONNECTING : SS_UNCONNECTED;
			goto out;
		}
	}
    switch (sock->state) {
        default:
            err = -EINVAL;
            goto out;
        case SS_CONNECTED:
            err = -EISCONN;
            goto out;
        case SS_CONNECTING:
            if (inet_sk(sk)->defer_connect)
                err = is_sendmsg ? -EINPROGRESS : -EISCONN;
            else
                err = -EALREADY;
            /* Fall out of switch with err, set for this state */
            break;
        case SS_UNCONNECTED:
            err = -EISCONN;
            if (sk->sk_state != TCP_CLOSE)
                goto out;

            if (BPF_CGROUP_PRE_CONNECT_ENABLED(sk)) {
                err = sk->sk_prot->pre_connect(sk, uaddr, addr_len);
                if (err)
                    goto out;
            }

            err = sk->sk_prot->connect(sk, uaddr, addr_len);
            if (err < 0)
                goto out;

            sock->state = SS_CONNECTING;

            if (!err && inet_sk(sk)->defer_connect)
                goto out;

            /* Just entered SS_CONNECTING state; the only
            * difference is that return value in non-blocking
            * case is EINPROGRESS, rather than EALREADY.
            */
            err = -EINPROGRESS;
            break;
        }
    ...
}
```
`sk->sk_prot`即`struct sock`针对不同协议的`ops`指针，对于`tcp`协议，其为`tcp_prot`
```c
struct proto tcp_prot = {
	.name			= "TCP",
	.owner			= THIS_MODULE,
	.close			= tcp_close,
	.pre_connect		= tcp_v4_pre_connect,
	.connect		= tcp_v4_connect,
	.disconnect		= tcp_disconnect,
	.accept			= inet_csk_accept,
	.ioctl			= tcp_ioctl,
	.init			= tcp_v4_init_sock,
	.destroy		= tcp_v4_destroy_sock,
	.shutdown		= tcp_shutdown,
	.setsockopt		= tcp_setsockopt,
	.getsockopt		= tcp_getsockopt,
	.bpf_bypass_getsockopt	= tcp_bpf_bypass_getsockopt,
	.keepalive		= tcp_set_keepalive,
	.recvmsg		= tcp_recvmsg,
	.sendmsg		= tcp_sendmsg,
	.sendpage		= tcp_sendpage,
	.backlog_rcv		= tcp_v4_do_rcv,
    ...
}
```
所以这里实际调用的`connect`就是`tcp_v4_connect`，相关实现在`net/ipv4/tcp_ipv4.c`
```c
/* This will initiate an outgoing connection. */
int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
    // 将用户态的sockaddr_in强制转化为sockaddr_in
	struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
    // 
	struct inet_sock *inet = inet_sk(sk);
	struct tcp_sock *tp = tcp_sk(sk);
    ...
}
```
这里的三个强制转换，第一个就是将用户态的sockaddr_in强制转化为sockaddr_in
```c
struct sockaddr_in {
  __kernel_sa_family_t	sin_family;	/* Address family		*/
  __be16		sin_port;	/* Port number			*/
  struct in_addr	sin_addr;	/* Internet address		*/

  /* Pad to size of `struct sockaddr'. */
  unsigned char		__pad[__SOCK_SIZE__ - sizeof(short int) -
			sizeof(unsigned short int) - sizeof(struct in_addr)];
};
```
后两个需要理解下不同的`sock`意义：
* struct socket：这是基本的BSD socket，应用程序通过系统调用创建的socket都是这个结构体，是基于VFS创建出来的，类型主要有三种：流式SOCK_STREAM，数据报SOCK_DGRAM，原始套接字SOCK_RAW
* struct sock：这是网络层socket，对应有TCP，UDP，RAW三种
* struct inet_sock：INET域的socket，是对struct sock的扩展，提供了INET域的属性，比如TTL，组播列表，IP地址，端口等
* struct raw_sock：RAW协议的socket，针对struct inet_sock的扩展，处理ICMP相关的内容
* struct udp_sock：UDP协议的socket，针对struct inet_sock的扩展
* struct tcp_sock：TCP协议针对inet_connextion_sock的扩展，增加了滑动窗口，拥塞控制等专用属性
* struct inet_connection_sock：是所有面向连接的socket表示，基于struct inet_sock的扩展
* struct inet_timewait_sock：网络层用于超时控制的socket
* struct tcp_timewait_sock：TCP协议用于超时控制的socket

接着做了一些简单的校验（地址长度/协议族）
```c
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (usin->sin_family != AF_INET)
		return -EAFNOSUPPORT;
```
设置下一跳和目的地址，都是用户态`connect`设置的地址
```c
	nexthop = daddr = usin->sin_addr.s_addr;
```
获取IP路由选项，如果有路由选项的话设置下一跳为`ip路由选项的第一跳地址`
```c
	inet_opt = rcu_dereference_protected(inet->inet_opt,
					     lockdep_sock_is_held(sk));
	if (inet_opt && inet_opt->opt.srr) {
		if (!daddr)
			return -EINVAL;
		nexthop = inet_opt->opt.faddr;
	}
```
设置源、目的端口
```c
	orig_sport = inet->inet_sport;
	orig_dport = usin->sin_port;
```


整个`connect`的流程
```
sys_connect->sock-ops->connect->inet_stream_connect->sk_sk_prot->connect->tcp_v4_connect->inet_sk
```


### Refer
* [TCP/IP inet_csk/inet_sk](https://blog.csdn.net/hxchuan000/article/details/51720270)
* [Linux网络——1](https://github.com/g0dA/linuxStack/blob/master/linux%E7%BD%91%E7%BB%9C(%E4%B8%80).md)
