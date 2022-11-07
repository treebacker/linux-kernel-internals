#### 简介
当一个socket同addr绑定之后，要想启用（接收数据）还需要标记为`监听状态`,这是由`listen`完成的

####  Internel
```c
int __sys_listen(int fd, int backlog)
{
	struct socket *sock;
	int err, fput_needed;
	int somaxconn;

	sock = sockfd_lookup_light(fd, &err, &fput_needed);
	if (sock) {
		somaxconn = sock_net(sock->sk)->core.sysctl_somaxconn;
		if ((unsigned int)backlog > somaxconn)
			backlog = somaxconn;

		err = security_socket_listen(sock, backlog);
		if (!err)
			err = sock->ops->listen(sock, backlog);

		fput_light(sock->file, fput_needed);
	}
	return err;
}
```
* 和bind一样，先通过`fd`找到`struct socket`实例
* backlog字段标识该socket允许的最大连接队列（不能超过>core.sysctl_somaxconn，默认128）
* 调用sock->ops->listen，即`inet_listen`
```c
int inet_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int err, tcp_fastopen;

	lock_sock(sk);

	err = -EINVAL;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;

	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	WRITE_ONCE(sk->sk_max_ack_backlog, backlog);
	/* Really, if the socket is already in listen state
	 * we can only allow the backlog to be adjusted.
	 */
	if (old_state != TCP_LISTEN) {
		/* Enable TFO w/o requiring TCP_FASTOPEN socket option.
		 * Note that only TCP sockets (SOCK_STREAM) will reach here.
		 * Also fastopen backlog may already been set via the option
		 * because the socket was in TCP_LISTEN state previously but
		 * was shutdown() rather than close().
		 */
		tcp_fastopen = sock_net(sk)->ipv4.sysctl_tcp_fastopen;
		if ((tcp_fastopen & TFO_SERVER_WO_SOCKOPT1) &&
		    (tcp_fastopen & TFO_SERVER_ENABLE) &&
		    !inet_csk(sk)->icsk_accept_queue.fastopenq.max_qlen) {
			fastopen_queue_tune(sk, backlog);
			tcp_fastopen_init_key_once(sock_net(sk));
		}

		err = inet_csk_listen_start(sk);
		if (err)
			goto out;
		tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_LISTEN_CB, 0, NULL);
	}
	err = 0;

out:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL(inet_listen);
```
* 先做一些check
  * struct socket的状态必须是`SS_UNCONNECTED`未连接状态
  * socket type必须是`SOCK_STREAM`
  * sock->s_state状态不能是`TCP_LISTEN`（对于寂静处于listen状态，只修改了backlog，不做别的处理）

* 最后调用inet_csk_listen_start
    ```c
    int inet_csk_listen_start(struct sock *sk)
    {
        struct inet_connection_sock *icsk = inet_csk(sk);
        struct inet_sock *inet = inet_sk(sk);
        int err = -EADDRINUSE;

        reqsk_queue_alloc(&icsk->icsk_accept_queue);

        sk->sk_ack_backlog = 0;
        inet_csk_delack_init(sk);
        if (sk->sk_txrehash == SOCK_TXREHASH_DEFAULT)
            sk->sk_txrehash = READ_ONCE(sock_net(sk)->core.sysctl_txrehash);

        /* There is race window here: we announce ourselves listening,
        * but this transition is still not validated by get_port().
        * It is OK, because this socket enters to hash table only
        * after validation is complete.
        */
        inet_sk_state_store(sk, TCP_LISTEN);
        if (!sk->sk_prot->get_port(sk, inet->inet_num)) {
            inet->inet_sport = htons(inet->inet_num);

            sk_dst_reset(sk);
            err = sk->sk_prot->hash(sk);

            if (likely(!err))
                return 0;
        }

        inet_sk_set_state(sk, TCP_CLOSE);

    }
    ```
    * 先初始化`icsk_accept_queue`队列，tcp连接建立完成后对应的sock会放在该队列中，accept方法会从该队列取sock
    * 初始化当前sk_ack_backlog为0
    * 初始化sk_txrehash为默认值
    * 修改sk->sk_state为`TCP_LISTEN`
    * 调用sk->sk_prot->get_port即inet_csk_get_port获得sk bind的端口信息
    * 调用sk->sk_prot->hash即inet_hash
        ```c
        int inet_hash(struct sock *sk)
        {
            int err = 0;

            if (sk->sk_state != TCP_CLOSE)
                err = __inet_hash(sk, NULL);

            return err;
        }

        int __inet_hash(struct sock *sk, struct sock *osk)
        {
            struct inet_hashinfo *hashinfo = sk->sk_prot->h.hashinfo;
            struct inet_listen_hashbucket *ilb;
            int err = 0;

            if (sk->sk_state != TCP_LISTEN) {
                local_bh_disable();
                inet_ehash_nolisten(sk, osk, NULL);
                local_bh_enable();
                return 0;
            }
            WARN_ON(!sk_unhashed(sk));
            ilb = &hashinfo->listening_hash[inet_sk_listen_hashfn(sk)];

            spin_lock(&ilb->lock);
            if (sk->sk_reuseport) {
                err = inet_reuseport_add_sock(sk, ilb);
                if (err)
                    goto unlock;
            }
            if (IS_ENABLED(CONFIG_IPV6) && sk->sk_reuseport &&
                sk->sk_family == AF_INET6)
                __sk_nulls_add_node_tail_rcu(sk, &ilb->nulls_head);
            else
                __sk_nulls_add_node_rcu(sk, &ilb->nulls_head);
            inet_hash2(hashinfo, sk);
            ilb->count++;
            sock_set_flag(sk, SOCK_RCU_FREE);
            sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);
        unlock:
            spin_unlock(&ilb->lock);

            return err;
        }
        ```
    * 根据端口和sk哈希找到listen hashbucket`ilb`
    * 调用inet_hash2将sock添加到链表(tcp_hasinfo)中
    * 所在inet_listen_hashbucket 计数加1



