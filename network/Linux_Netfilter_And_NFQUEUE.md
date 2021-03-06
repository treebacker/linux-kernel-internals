## Linux NetFilter And NFQUEUE

### Introduction
Linux的网络栈是属于内核的东西，为了让用户需求，干预网络数据的传输，提供了一些框架，可以使得用户通过一些配置，改变主机的网络数据。
内核中的额Netfilter框架就是为满足这一需求而设计的，其中用户态使用的配置工具就是iptables，通过iptables设置防火墙策略，干预内核数据包的处理策略。

### Iptables
Iptables的组成：四张表 + 五条链；俗称四表五链。

#### Four tables
四表：`filter`、`net`、`mangle`、`raw`，规则没有指定table时默认`filter`。
其中表之间的优先级`raw` > `mangle` > `nat` > `filter`。

|   Table Name |    Comment |
| ------------ | ------------ |
|     filter   |   过滤数据包         |
|     nat      |    网络地址转换（端口映射、地址映射）          |
|     mangle   |    对于特定的数据报文修改          |
|     raw      |     优先级最高，设置raw一般是为了不再让iptables做数据包的跟踪处理、提高性能         |



#### Five chains

|   Chain Name |    Comment |
| ------------ | ------------ |
|     PREROUTING   |   数据包进入路由表之前，对数据包做路由选择之前会先过此链路中的规则，所有数据包进来都会最先由这个链处理         |
|     INPUT      |  通过路由表到达主机后，进来的数据包过该链上的规则        |
|     FORWARD   |    通过路由表，目标地址不为本机，应用该链上的规则          |
|     OUTPUT      |    由本主机向外发送的数据包向外转发时，应用此链中的规则       |
|     POSTROUTING      |   数据包做路由选择之后、发送到网接口之前应用此链中的规则，所有数据包出去的时候，都最先由该链处理  |


#### The relationships between table and chain

|   Table Name |    Chains  |
| ------------ | ------------ |
|    filter    |  INPUT、FORWARD、OUTPUT |
|     nat      |     PREROUTING、OUTPUT、POSTROUTING |
|     mangle   |     PREROUTING、INPUT、FORWARD、 OUTPUT、 POSTROUTING |
|     raw      |     PREROUTING、 OUTPUT     |

#### 数据包在4表5链中的流向

![](images\iptables_packet_flow.png)
其中标识了`三条`网络流路径：
* A是外来数据包由本地进程处理
* B是本地作为中转路由，转发到其他网关
* C是本地进程向其他网关发送的数据包流向


### Netfilter
Linux下Netfilter通过在内核协议栈的各个重要节点埋下钩子，将数据包hook，交由iptables的四表五链处理，并根据iptables的规则，决定对packet执行的动作:
* 数据包的访问控制：`ACCEPT`、`DROP`、`REJECT`
* 数据包的改写：`SNAT`、`DNAT`
* 信息记录: `LOG`

#### 数据包接收过程
Linux的网络包所有IP层的入口函数是`ip_rcv`，在这里会命中第一个HOOK, 即`PREROUTING`
```c
    // net/ipv4/ip_input.c
/*
 * IP receive entry point
 */
int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt,
	   struct net_device *orig_dev)
{
    ...
	return NF_HOOK(NFPROTO_IPV4, NF_INET_PRE_ROUTING,
		       net, NULL, skb, dev, NULL,
		       ip_rcv_finish);
}
```
这里分析一下`NF_HOOK`实现(配置CONFIG_NETFILTER的情况下)
```c
static inline int
NF_HOOK(uint8_t pf, unsigned int hook, struct net *net, struct sock *sk, struct sk_buff *skb,
	struct net_device *in, struct net_device *out,
	int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	int ret = nf_hook(pf, hook, net, sk, skb, in, out, okfn);
	if (ret == 1)
		ret = okfn(net, sk, skb);
	return ret;
}
```
实际是先调用`nf_hook`处理指定chain `hook`上的iptables规则

当`nf_hook`返回`1`表示当前chain上的规则放行了该packet，可以进入下一步`okfn`

`nf_hook`的内核代码
```c
static inline int nf_hook(u_int8_t pf, unsigned int hook, struct net *net,
			  struct sock *sk, struct sk_buff *skb,
			  struct net_device *indev, struct net_device *outdev,
			  int (*okfn)(struct net *, struct sock *, struct sk_buff *))
{
	rcu_read_lock();
	switch (pf) {
	case NFPROTO_IPV4:
		hook_head = rcu_dereference(net->nf.hooks_ipv4[hook]);
		break;
        ...
	}

	if (hook_head) {
		struct nf_hook_state state;

		nf_hook_state_init(&state, hook, pf, indev, outdev,
				   sk, net, okfn);

		ret = nf_hook_slow(skb, &state, hook_head, 0);
	}
	rcu_read_unlock();

	return ret;
}
```
先根据协议取到对应协议（ipv4\ipv6\arp\...）的iptables规则表`nf_hook_entries`
再由`nf_hook_slow`去匹配每一条规则，执行对应的动作
```c
int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
		 const struct nf_hook_entries *e, unsigned int s)
{
	unsigned int verdict;
	int ret;

	for (; s < e->num_hook_entries; s++) {
		verdict = nf_hook_entry_hookfn(&e->hooks[s], skb, state);
		switch (verdict & NF_VERDICT_MASK) {
		case NF_ACCEPT:                                 // 放行
			break;
		case NF_DROP:                                   // 丢包
			kfree_skb_reason(skb,
					 SKB_DROP_REASON_NETFILTER_DROP);
			ret = NF_DROP_GETERR(verdict);
			if (ret == 0)
				ret = -EPERM;
			return ret;
		case NF_QUEUE:                                 // 进入NFQUEUE
			ret = nf_queue(skb, state, s, verdict);
			if (ret == 1)
				continue;
			return ret;
		default:
			/* Implicit handling for NF_STOLEN, as well as any other
			 * non conventional verdicts.
			 */
			return 0;
		}
	}

	return 1;
}
```
当数据包在`PREROUTING`规则里没有被`DROP`, 就会进入`ip_rcv_finish -> ip_rcv_finish_core`，在这里进行路由选择（所以前面是`PREROUNTING`）
```c
static int ip_rcv_finish_core(struct net *net, struct sock *sk,
			      struct sk_buff *skb, struct net_device *dev,
			      const struct sk_buff *hint)
{
    ...
    if (!skb_valid_dst(skb)) {
		err = ip_route_input_noref(skb, iph->daddr, iph->saddr,
					   iph->tos, dev);
		if (unlikely(err))
			goto drop_error;
	}
    ...
}
```
在路由选择时，如果发现是本地设备接收，交由`ip_local_deliver`处理
```c
		rt->dst.output = ip_output;
		if (flags & RTCF_LOCAL)
			rt->dst.input = ip_local_deliver;
	}
```
在`ip_local_deliver`中执行`LOCAL_IN`钩子，也就是`INPUT`链
```c
int ip_local_deliver(struct sk_buff *skb)
{
	/*
	 *	Reassemble IP fragments.
	 */
	struct net *net = dev_net(skb->dev);
    ...
	return NF_HOOK(NFPROTO_IPV4, NF_INET_LOCAL_IN,
		       net, NULL, skb, skb->dev, NULL,
		       ip_local_deliver_finish);
}
```
简单总结上述数据包接收过程路径：`PREROUTING`链->路由选择（本机）->`INPUT`链

#### 数据包发送过程
在Linux内核实现中，网络层发送的入口函数是`ip_queue_xmit`
```c
int __ip_queue_xmit(struct sock *sk, struct sk_buff *skb, struct floi *fl,
		    __u8 tos)
{
    // 判断pkt是否已经路由
    rt = skb_rtable(skb);
	if (rt)
		goto packet_routed;

    // 查找路由缓存
	/* Make sure we can route this packet. */
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	if (!rt) {
		__be32 daddr;

        // 没有缓存信息，查找路由项
		rt = ip_route_output_ports(...);
		if (IS_ERR(rt))
			goto no_route;
		sk_setup_caps(sk, &rt->dst);
	}
	skb_dst_set_noref(skb, &rt->dst);
    ...
    // 发送
    res = ip_local_out(net, sk, skb);
}
```
进入`ip_local_out`发送时函数，在这里执行`NF_INET_LOCAL_OUT`钩子，也就是`OUTPUT`链
```c
int __ip_local_out(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);

	iph->tot_len = htons(skb->len);
	ip_send_check(iph);

    ...
	skb->protocol = htons(ETH_P_IP);

	return nf_hook(NFPROTO_IPV4, NF_INET_LOCAL_OUT,
		       net, sk, skb, NULL, skb_dst(skb)->dev,
		       dst_output);
}
```
执行完`OUTPUT`链上的规则之后，进入`dst_output`，最终调用`ip_output`发送
```c
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	struct net_device *dev = skb_dst(skb)->dev, *indev = skb->dev;

	IP_UPD_PO_STATS(net, IPSTATS_MIB_OUT, skb->len);

	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);

	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			    net, sk, skb, indev, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```
在这里执行了`NF_INET_POST_ROUTING`钩子，就是`POSTROUTING`链

简单总结发送数据包的流程：路由选择->`OUTPUT`链->`POSTROUTING`链



#### 数据包转发过程
数据转发过程和接受过程在`PREROUTING`是一样的，在最终进入`dst_input`后有了区分，转发数据最终由`ip_forward`处理
```c
int ip_forward(struct sk_buff *skb)
{
    ...
    return NF_HOOK(NFPROTO_IPV4, NF_INET_FORWARD,
            net, NULL, skb, skb->dev, rt->dst.dev,
            ip_forward_finish);
}
```
在这里执行了`NF_INET_FORWARD`钩子，就是`FORWARD`链
然后执行`ip_forward_finish`，进而进入`dst_output`->`ip_output`，执行`NF_INET_POST_ROUTING`钩子，就是`POSTROUTING`链
```c
int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
    ...
	return NF_HOOK_COND(NFPROTO_IPV4, NF_INET_POST_ROUTING,
			    net, sk, skb, indev, dev,
			    ip_finish_output,
			    !(IPCB(skb)->flags & IPSKB_REROUTED));
}
```
简单总结转发数据流程：`PREROUTING`链->路由选择（不是本机）->`FORWARD`链->`POSTROUTING`链

### NFQUEUE / iptables-queue
NetfilterQueue是内核基于Netfilter框架，提供给用户程序一个管理所有数据包的接口。
通过iptables规则，将命中规则的数据包加入到`NFQUEUE`队列中由用户态程序处理（并决定是否`ACCEPT`、`DROP`、`REJECT`...）

#### 使用
简单的一条使用`nfquque`的iptables规则
```s
iptables -I PREROUTING -t raw -p tcp -j NFQUEUE --queue-num 1 --queue-bypass
```
* `queue-num`：指定`NFQUEUE`队列序号
* `queue-bypass`：在没有用户程序监听（绑定）当前队列时，默认放行网络包，否则丢包

#### 坑点
`NFQUEUE`既然是一个队列，那就是有容量限制的，默认是`1024`，用户程序可以在监听队列的时候设置容量大小，如果队列满了，`iptables`默认会丢包，在内核`3.6`之后，可以使用`--fail-open`选项设为默认放行。
这里的坑点在于，很多主机上流量安全审计产品/工具，如果在用户态消费`NFQUEUE`队列比较慢，会产生较高的网络延迟，甚至导致`socket buffer`不足，打挂网络。 
另外如果没有设置`--fail-open`参数，在队列满了的情况下，会产生丢包，网络直接被打挂。
最坑的时较上层的应用程序，libnfqueue提供了设置`queue` flags的接口，可以设置`--fail-open`参数，但是部分Linux发行版`iptables`居然没提供该选项（据我所知Centos没有提供、ubuntu提供了）！

