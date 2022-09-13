
### 前言
这一系列主要剖析Linux内核网络协议栈的实现细节，作为开篇，先搞清楚在Linux内核网络中的几个关键重要的基础结构体。


### Linux Networking
Linux内核提供了3个基础结构体用于处理网络数据包: `struct socket`、`struct sock`、`struct sk_buff`
其中`socket`和`sock`都是一个`socket`套接字的一种抽象：
* `struct socket`是接近用户态套接字的一种抽象，即`BSD socket`
* `struct sock`是在网络侧对套接字的一种表示，即`INET socket`

这两个结构是相互关联的，`struct socket`包含一个`INET socket`字段，`struct sock`也有一个`BSD socket`字段。

`struct sk_buff`结构是真正的表示一个网络数据包，记录了数据包的状态。只有在接受数据包时才会创建。


#### struct socket
`BSD socket`就是Linux内核为用户态定义的一种网络套接字接口，`struct socket`作为一个通信端点，所有的网络系统调用本质上就是在操作`struct socket`，数据从一个`socket`端流向另一个`socket`端。
该结构体定义在`linux/net.h`中
```c
struct socket {
	socket_state		state;

	short			type;

	unsigned long		flags;

	struct file		*file;
	struct sock		*sk;
	const struct proto_ops	*ops;

	struct socket_wq	wq;
};
```
* state: 网络套接字连接状态，包括 未分配/未连接/连接中/已经连接到某socket/断开连接中
```c
typedef enum {
	SS_FREE = 0,			/* not allocated		*/
	SS_UNCONNECTED,			/* unconnected to any socket	*/
	SS_CONNECTING,			/* in process of connecting	*/
	SS_CONNECTED,			/* connected to socket		*/
	SS_DISCONNECTING		/* in process of disconnecting	*/
} socket_state;
```
* type: socket创建type，包括
```c
enum sock_type {
	SOCK_STREAM	= 1,        // 流式
	SOCK_DGRAM	= 2,        // 无连接
	SOCK_RAW	= 3,        
	SOCK_RDM	= 4,
	SOCK_SEQPACKET	= 5,
	SOCK_DCCP	= 6,
	SOCK_PACKET	= 10,
};
```
* file: `struct socket`对应文件结构指针（用于回收机制）
* sk: `struct sock`结构指针
* proto_ops： 和`struct socket`协议有关的操作

`struct socket`提供的操作和系统调用相对应：creation/release/bind/listen/accept/connet...

##### creation
creation操作对应用户态的`socket`函数
内核为不同的使用场景提供了3种`socket creation`方式，创建的`struct socket`结构体将被存储在`res`参数中
```c
int sock_create(int family, int type, int protocol, struct socket **res) creates a socket after the socket() system call;

int sock_create_kern(struct net *net, int family, int type, int protocol, struct socket **res) creates a kernel socket;

int sock_create_lite(int family, int type, int protocol, struct socket **res) creates a kernel socket without parameter sanity checks.
```
各个参数理解
* net，使用的network namespace的引用，通常使用`init_net`的引用
* family，表示协议族，通常是`PF_`，可选项定义在`linux/socket.h`中，常使用的是`PF_INET`表示TCP/IP协议
* type，表socket类型，可选项定义在`linux/net.h`中，通常使用的是基于`源-目的通信`的`SOCK_STREAM`和无连接通信的`SOCK_DGRAM`
* protocol，表和`type`对应的协议，可选项定义在`linux/in.h`中。常使用的是`IPPROTO_TCP`和`IPPROTO_UDP`
例如在Linux内核创建一个TCP socket
```c
struct socket *sock;
int err;

err = sock_create_kern(&init_net, PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
if (err < 0) {
        /* handle error */
}
```
创建一个UDP socket
```c
struct socket *sock;
int err;

err = sock_create_kern(&init_net, PF_INET, SOCK_DGRAM, IPPROTO_UDP, &sock);
if (err < 0) {
        /* handle error */
}
```
真实的case就是`sys_socket`的实现
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
可以看到`sys_socket`实际是内核通过`sock_create`创建一个`struct socket`结构体，再为该结构体分配一个文件描述符`fd`并返回。

##### closing
用户态socket的close对应内核释放`struct socket`资源
```c
void sock_release(struct socket *sock)
```
实现上最终由`struct socket.ops`字段根据协议类型找到对应的释放方法
```c
static void __sock_release(struct socket *sock, struct inode *inode)
{
	if (sock->ops) {
		struct module *owner = sock->ops->owner;

		if (inode)
			inode_lock(inode);
		sock->ops->release(sock);
		sock->sk = NULL;
		if (inode)
			inode_unlock(inode);
		sock->ops = NULL;
		module_put(owner);
	}

	if (sock->wq.fasync_list)
		pr_err("%s: fasync list not empty!\n", __func__);

	if (!sock->file) {
		iput(SOCK_INODE(sock));
		return;
	}
	sock->file = NULL;
}
```


#### struct sock
`struct sock`结构表示`INET socket`网络层套接字，可以理解为用户空间的`socket`和内核网络包`sk_buff`的一个桥梁结构，存储了一个socket connection的状态。
结构定义在`net/sock.h`
```c
struct sock {
    ...
	int			sk_rcvbuf;

	struct sk_filter __rcu	*sk_filter;
	union {
		struct socket_wq __rcu	*sk_wq;
		/* private: */
		struct socket_wq	*sk_wq_raw;
		/* public: */
	};

	struct dst_entry __rcu	*sk_dst_cache;
	atomic_t		sk_omem_alloc;
	int			sk_sndbuf;
    ...

	/*
	 * Because of non atomicity rules, all
	 * changes are protected by socket lock.
	 */
	u8			sk_gso_disabled : 1,
				sk_kern_sock : 1,
				sk_no_check_tx : 1,
				sk_no_check_rx : 1,
				sk_userlocks : 4;
	u8			sk_pacing_shift;
	u16			sk_type;
	u16			sk_protocol;
	u16			sk_gso_max_segs;
    ...
    union {
		struct sk_buff	*sk_send_head;
		struct rb_root	tcp_rtx_queue;
	};
    ...

	struct socket		*sk_socket;
	...
    
	void			(*sk_state_change)(struct sock *sk);
	void			(*sk_data_ready)(struct sock *sk);
	void			(*sk_write_space)(struct sock *sk);
	void			(*sk_error_report)(struct sock *sk);
	int			(*sk_backlog_rcv)(struct sock *sk,
						  struct sk_buff *skb);
    ...
	void                    (*sk_destruct)(struct sock *sk);
    ...
};
```
* sk_protocol socket使用的protocol
* sk_type: socket type (SOCK_STREAM / SOCK_DGRAM ...)
* sk_socket: 表示其对应的BSD socket
* sk_send_head: 表该socket下通信的`struct sk_buff`链表
* 函数指针是不同场景的回调函数


#### struct sk_buff
`struct sk_buff`结构描述了一个network packet，该结构包含了packet的头/内容/协议/设备信息。
该结构定义在`linux/skbuff.h`中
```c

struct sk_buff {
	union {
		struct {
			/* These two members must be first to match sk_buff_head. */
			struct sk_buff		*next;
			struct sk_buff		*prev;

			union {
				struct net_device	*dev;
				/* Some protocols might use this space to store information,
				 * while device pointer would be NULL.
				 * UDP receive path is one user.
				 */
				unsigned long		dev_scratch;
			};
		};
		struct rb_node		rbnode; /* used in netem, ip4 defrag, and tcp stack */
		struct list_head	list;
		struct llist_node	ll_node;
	};

	union {
		struct sock		*sk;
		int			ip_defrag_offset;
	};

	union {
		ktime_t		tstamp;
		u64		skb_mstamp_ns; /* earliest departure time */
	};
    	/*
	 * This is the control buffer. It is free to use for every
	 * layer. Please put your private variables there. If you
	 * want to keep them across layers you have to do a skb_clone()
	 * first. This is owned by whoever has the skb queued ATM.
	 */
	char			cb[48] __aligned(8);

	union {
		struct {
			unsigned long	_skb_refdst;
			void		(*destructor)(struct sk_buff *skb);
		};
		struct list_head	tcp_tsorted_anchor;
     };

	__be16			protocol;
	__u16			transport_header;
	__u16			network_header;
	__u16			mac_header;

	/* These elements must be at the end, see alloc_skb() for details.  */
	sk_buff_data_t		tail;
	sk_buff_data_t		end;
	unsigned char		*head,
				*data;
	unsigned int		truesize;
	refcount_t		users;
}
```
* next/prev 是`sk_buff`链表结构的一部分
* dev 是接受/发送该数据包的设备
* sk是该网络数据包相关的`struct sock`结构
* transport_header/network_header/mac_header都是该packet内各个header的偏移。

### Refer
* [Linux-Kernel-Document-Networking](https://linux-kernel-labs.github.io/refs/heads/master/labs/networking.html)
* [BSD-sockets](https://www.halolinux.us/kernel-reference/bsd-sockets.html)