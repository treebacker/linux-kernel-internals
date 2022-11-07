#### 简介
socket创建的一个socket实例，只是一个命名空间，没有与实际的地址绑定。
bind就是将指定的一个地址分配给一个socket


#### Internal
sys_bind的定义在`net/socket.c`中
```c
int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
{
	struct socket *sock;
	struct sockaddr_storage address;
	int err, fput_needed;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock) {
		err = move_addr_to_kernel(umyaddr, addrlen, &address);
		if (!err) {
			err = security_socket_bind(sock,
						   (struct sockaddr *)&address,
						   addrlen);
			if (!err)
				err = sock->ops->bind(sock,
						      (struct sockaddr *)
						      &address, addrlen);
		}
		fput_light(sock->file, fput_needed);
	}
	return err;
}

```
* 根据指定的fd(`sockfd`)找到对应的`struct socket`实例
  * 根据fd搜索进程文件描述符表找到对应的`struct file`实例、`struct fd`实例
  * `sock_from_file`根据`struct file`的`private_data`字段得到`struct socket`实例（socket创建时，将struct socket实例保存在这里）
* 通过`move_addr_to_kernel`将用户态传入的addr拷贝到内核中
这说明在调用完bind后，用户态的`struct sockaddr *addr`地址可以继续使用（用作别的用途）
* 调用`sock->ops->bind`完成实际的bind工作，对于tcp实际就是`inet_stream_ops->bind`，即`inet_bind`
```c
int inet_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;
	u32 flags = BIND_WITH_LOCK;
	int err;

	/* If the socket has its own bind function then use it. (RAW) */
	if (sk->sk_prot->bind) {
		return sk->sk_prot->bind(sk, uaddr, addr_len);
	}
	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	/* BPF prog is run before any checks are done so that if the prog
	 * changes context in a wrong way it will be caught.
	 */
	err = BPF_CGROUP_RUN_PROG_INET_BIND_LOCK(sk, uaddr,
						 CGROUP_INET4_BIND, &flags);
	if (err)
		return err;

	return __inet_bind(sk, uaddr, addr_len, flags);
}
```
* 首先检查`sk->sk_prot->bind`字段是否指定了特定的bind方法，这里即检查`&tcp_prot->bind`，在tcp_prot中并没有定义该字段，使用默认的`__inet_bind`
```c
int __inet_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len,
		u32 flags)
{
	struct sockaddr_in *addr = (struct sockaddr_in *)uaddr;
	struct inet_sock *inet = inet_sk(sk);
	struct net *net = sock_net(sk);
	unsigned short snum;
    ...


	snum = ntohs(addr->sin_port);
    ...
	if (sk->sk_state != TCP_CLOSE || inet->inet_num)
		goto out_release_sock;

    ...
    if (snum || !(inet->bind_address_no_port ||
            (flags & BIND_FORCE_ADDRESS_NO_PORT))) {
    if (sk->sk_prot->get_port(sk, snum)) {
        inet->inet_saddr = inet->inet_rcv_saddr = 0;
        err = -EADDRINUSE;
        goto out_release_sock;
    }
    ...
    }
    ...
}
```
  * 检查当前socket的状态是否不是`TCP_CLOSE`（创建初始化时sk->sk_state为TCP_CLOSE）
  * 初始化部分字段（源地址、端口（就是用户态指定的sockaddr）；目的地址、端口默认0）
    ```c
    inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
	inet->inet_sport = htons(inet->inet_num);
	inet->inet_daddr = 0;
	inet->inet_dport = 0;
    ```
  * 当用户态指定了绑定的端口时，会调用sk->sk_prot->get_port，实际调用的`inet_csk_get_port`
    ```c
    int inet_csk_get_port(struct sock *sk, unsigned short snum)
    {
    bool reuse = sk->sk_reuse && sk->sk_state != TCP_LISTEN;
    struct inet_hashinfo *hinfo = sk->sk_prot->h.hashinfo;
    int ret = 1, port = snum;
    struct inet_bind_hashbucket *head;
    struct net *net = sock_net(sk);
    struct inet_bind_bucket *tb = NULL;
    int l3mdev;

    l3mdev = inet_sk_bound_l3mdev(sk);

    ...
    head = &hinfo->bhash[inet_bhashfn(net, port,
                        hinfo->bhash_size)];
    ...
    }
    ...
    ```
    * 根net、port找到对应的hash表
    * 遍历表找到对应的bucket
    * 最终调用`inet_bind_hash`
    ```c
    void inet_bind_hash(struct sock *sk, struct inet_bind_bucket *tb,
                const unsigned short snum)
    {
        inet_sk(sk)->inet_num = snum;
        sk_add_bind_node(sk, &tb->owners);
        inet_csk(sk)->icsk_bind_hash = tb;
    }
    ```
    在这里赋值`inet->inet_num = snum`，即用户态指定的端口，所以`inet->inet_sport`就是用户态传入的端口。





