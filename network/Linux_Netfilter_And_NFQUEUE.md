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

在路由选择时，如果发现是本地设备接收，交由
### NFQUEUE / iptables-queue

