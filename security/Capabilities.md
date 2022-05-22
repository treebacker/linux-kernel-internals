## 							Linux Capabilities

### 简述

​		传统的Unix出于权限校验的目的，将进程分为两类（特权、非特权）。特权进程允许做任何事情，而非特权精彩需要校验进程的`cred`。

Kernel2.2后，Linux将特权用户的权限划分为不同的单元，也即`capabilities`，每一个`cap`可以独立的`enable`或`disable`。

**Linux Capabilities**是一种权限最小化原则的体现，它允许非特权用户执行一些特定的特权行为而不用赋予它全部的权限。

Linux内核的`Cap`列表可以参考[man-capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html).



### Capabilities Set

#### Process

进程有以下5种`cap`集合：

* Effective Cap

  * 进程运行时的有效权限集合，用于权限校验

* Permitted Cap

  * 可以通过`capset`启用的权限，可以转为`effective cap`或者`inherited

* Inheritable Cap

  * 可以通过`execve`继承的权限，可继承权限在执行任何程序后仍然是可继承的，如果执行的文件拥有对应的`cap`，这些`cap`将成为`permitted`。

    前提是原进程是特权进程。

* Ambient Cap（Linux 4.3及以后）

  * 非特权进程的可继承权限集合，

* Bounding Set

  * 一种在`execve`时限制进程权限的机制，即限定可以继承的权限范围

#### Executable binarys

* Permitted
  * 文件的`permitted caps`自动加入文件进程的`permitted caps`
* Inheriteable
  * 文件的`inheritable caps`和进程的`Inheritable caps`两个集合的交集决定了`execve`后进程在`permittied`内的`inheritable caps`的启用。
* Effective
  * 不是一个集合而是一个标志位。当该标志位生效时，`execve`时，`permmited caps`将被设置为`effective caps`。

#### Caps在execve中的转化

```
  
P'(ambient)     = (file is privileged) ? 0 : P(ambient)

 P'(permitted)   = (P(inheritable) & F(inheritable)) |
                   (F(permitted) & P(bounding)) | P'(ambient)

P'(effective)   = F(effective) ? P'(permitted) : P'(ambient)

P'(inheritable) = P(inheritable)    [i.e., unchanged]

 P'(bounding)    = P(bounding)       [i.e., unchanged]
 where:

P()： the value of a thread capability set before the execve
P'(): the value of a thread capability set after the execve
 F():  denotes a file capability set
```



### 实际应用

Linux系统提供了管理`caps`的工具：libcap 和 libcap-ng.

libcap提供了`getcap`和`setcap`两个命令分别用于查看和设置文件的`caps`、和shell进程的`caps`

#### Caps in Files

##### 查看caps

```
getcap 
```

##### 增加caps

```
setcap cap_seuid=ep /usr/bin/gdb
```

##### 删除caps

```
setcap -r /usr/bin/gdb
```

#### Caps in Process

进程的`caps`信息在`/proc/pid/status`文件中，对于`root`用户的特权进程，默认包含所有的`caps`，本质是两个`u32`即一个`u64`数字

```
root@tree-ubt:# cat /proc/self/status | grep Cap
CapInh:	0000000000000000
CapPrm:	000000ffffffffff
CapEff:	000000ffffffffff
CapBnd:	000000ffffffffff
CapAmb:	0000000000000000
```

可以用`capsh`将其解释为对应的`caps`

```
root@tree-ubt:# capsh --decode=000000ffffffffff
0x000000ffffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,cap_audit_read,cap_perfmon,cap_bpf
```

或者`gepcaps`命令可以获取指定`pid`进程的`caps`信息

```shell
tree@tree-ubt:$ ping www.baidu.com 1>/dev/null &
[6] 21574
tree@tree-ubt:$ getpcaps 21574
21574: cap_net_raw=p

```

#### Cap In User

Linux允许赋予用户特定的`cap`，意味着由某用户启动的进程，都拥有特定的`caps`

`/etc/security/capability.conf`可配置用户的`caps`，例如

```
# Simple
cap_sys_ptrace               developer
cap_net_raw                  user1

# Multiple capablities
cap_net_admin,cap_net_raw    jrnetadmin
# Identical, but with numeric values
12,13                        jrnetadmin

# Combining names and numerics
cap_sys_admin,22,25          jrsysadmin
```

同时要想上述配置生效，需要将`pam_cap.so`添加到对应的`/etc/pam.d/xx`文件中



### 内核细节

相关代码在`Linux/Kernel/capabilities`中，

内核提供给`userspace`的设置`caps`的系统调用`capset`、`capget`用于修改、获取进程的`caps`

#### 系统调用原型

```c
int capget(cap_user_header_t hdrp, cap_user_data_t datap);
int capset(cap_user_header_t hdrp, const cap_user_data_t datap);

typedef struct __user_cap_header_struct {
	__u32 version;
	int pid;
} __user *cap_user_header_t;

typedef struct __user_cap_data_struct {
        __u32 effective;
        __u32 permitted;
        __u32 inheritable;
} __user *cap_user_data_t;
```

**__user_cap_header_struct** 结构体包含`capabilities version`和目标进程的`pid`信息

**__user_cap_data_struct** 结构体包含进程的`effective\permitted\inheritable`三个`caps set`。

#### capset实现

```c
SYSCALL_DEFINE2(capset, cap_user_header_t, header, const cap_user_data_t, data)
{
	struct __user_cap_data_struct kdata[_KERNEL_CAPABILITY_U32S];
	unsigned i, tocopy, copybytes;
	kernel_cap_t inheritable, permitted, effective;
	struct cred *new;
	int ret;
	pid_t pid;
	....
	ret = cap_validate_magic(header, &tocopy);
	if (ret != 0)
		return ret;
}
```

其中`kernel_cap_t`结构体，本质上是两个`u32`，其中的每一个`bit`标识一种`cap`的`enable`或者`disable`情况。

```c
#define _LINUX_CAPABILITY_U32S_3     2
#define _KERNEL_CAPABILITY_U32S    _LINUX_CAPABILITY_U32S_3

typedef struct kernel_cap_struct {
	__u32 cap[_KERNEL_CAPABILITY_U32S];
} kernel_cap_t;
```



**cap_validate_magic**验证传入的`header`的合法性，校验`header`标识的capability的version，并根据version的不同，确认`userspace`传入的`cap_user_data_t`包含的`__user_cap_data_struct`结构体的数目，存入`tocopy`，用于后续从`userspace`copy到`kernelspace`。

```c
static int cap_validate_magic(cap_user_header_t header, unsigned *tocopy)
{
	__u32 version;

	if (get_user(version, &header->version))
		return -EFAULT;

	switch (version) {
	case _LINUX_CAPABILITY_VERSION_1:
		warn_legacy_capability_use();
		*tocopy = _LINUX_CAPABILITY_U32S_1;
		break;
	case _LINUX_CAPABILITY_VERSION_2:
		warn_deprecated_v2();
		fallthrough;	/* v3 is otherwise equivalent to v2 */
	case _LINUX_CAPABILITY_VERSION_3:
		*tocopy = _LINUX_CAPABILITY_U32S_3;
		break;
	default:
		if (put_user((u32)_KERNEL_CAPABILITY_VERSION, &header->version))
			return -EFAULT;
		return -EINVAL;
	}

	return 0;
}
```

`capset`只允许进程修改自身进程的`caps`，因此校验`header->pid`和当前进程`pid`是否一致

```c
	if (get_user(pid, &header->pid))
		return -EFAULT;

	/* may only affect current now */
	if (pid != 0 && pid != task_pid_vnr(current))
		return -EPERM;
```

根据`version`确定的`__user_cap_data_struct`数目`tocopy`，计算需要的内存大小，并将`userspace`传入的`cap_user_data_t`数据拷贝到内核

```c
	copybytes = tocopy * sizeof(struct __user_cap_data_struct);
	if (copybytes > sizeof(kdata))
		return -EFAULT;

	if (copy_from_user(&kdata, data, copybytes))
		return -EFAULT;
```

之后根据传入的`cap_user_data_t`，分别初始化`effective`、`permitted`、`inheritable`集合（如果是低version的caps，不足部分初始化为0）

```c
	for (i = 0; i < tocopy; i++) {
		effective.cap[i] = kdata[i].effective;
		permitted.cap[i] = kdata[i].permitted;
		inheritable.cap[i] = kdata[i].inheritable;
	}
	while (i < _KERNEL_CAPABILITY_U32S) {
		effective.cap[i] = 0;
		permitted.cap[i] = 0;
		inheritable.cap[i] = 0;
		i++;
	}
```

最后根据`userspace`传入的`caps`信息，为当前进程新生成一个`cred`

```c
	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = security_capset(new, current_cred(),
			      &effective, &inheritable, &permitted);
	if (ret < 0)
		goto error;
```

更新新生成的的`cred`结构体的当前进程的`caps`信息

```c
struct cred {
	...
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	kernel_cap_t	cap_ambient;	/* Ambient capability set */
	...
	}
```

其中**security_capset**是一个调用`LSM wrapper hooks`，最终调用宏`call_int_hook`

```c
int security_capset(struct cred *new, const struct cred *old,
		    const kernel_cap_t *effective,
		    const kernel_cap_t *inheritable,
		    const kernel_cap_t *permitted)
{
	return call_int_hook(capset, 0, new, old,
				effective, inheritable, permitted);
}
```

`call_int_hook`宏简单的遍历执行`security_hook_list`列表函数中的`capset`hook函数，如果任意一个hook函数返回值不为0表示验证失败，是`Linux Security Mode`的一种安全校验方式。

```c

#define call_int_hook(FUNC, IRC, ...) ({			\
	int RC = IRC;						\
	do {							\
		struct security_hook_list *P;			\
								\
		hlist_for_each_entry(P, &security_hook_heads.FUNC, list) { \
			RC = P->hook.FUNC(__VA_ARGS__);		\
			if (RC != 0)				\
				break;				\
		}						\
	} while (0);						\
	RC;							\
})

```

#### capget实现

可以获取指定`pid`进程的`caps`集合信息，主要功能由`cap_get_target_pid`实现

```c
	ret = cap_get_target_pid(pid, &pE, &pI, &pP);
	if (!ret) {
		struct __user_cap_data_struct kdata[_KERNEL_CAPABILITY_U32S];
		unsigned i;

		for (i = 0; i < tocopy; i++) {
			kdata[i].effective = pE.cap[i];
			kdata[i].permitted = pP.cap[i];
			kdata[i].inheritable = pI.cap[i];
		}

		...
		if (copy_to_user(dataptr, kdata, tocopy
				 * sizeof(struct __user_cap_data_struct))) {
			return -EFAULT;
		}
	}
```

这里代码注释到：由于不能通过`capset`修改其他进程的`caps`信息，能够修改`caps`的只有进程自身，所以在读取`caps`信息时，分为两种情况，当读取自身进程`caps`时，需要`RCU`锁，防止自身进程修改了`caps`信息；而读取其他进程`caps`信息时则不需要。但其实还是有些问题，例如进程A不断`capset`修改自身进程`caps`信息，进程B不断`capget`获取进程A的`caps`信息，就会出现竞争情况。

```c
static inline int cap_get_target_pid(pid_t pid, kernel_cap_t *pEp,
				     kernel_cap_t *pIp, kernel_cap_t *pPp)
{
	int ret;

	if (pid && (pid != task_pid_vnr(current))) {
		struct task_struct *target;

		rcu_read_lock();

		target = find_task_by_vpid(pid);
		if (!target)
			ret = -ESRCH;
		else
			ret = security_capget(target, pEp, pIp, pPp);

		rcu_read_unlock();
	} else
		ret = security_capget(current, pEp, pIp, pPp);

	return ret;
}
```



### Capabilities滥用提权

如果系统管理员错误地给部分程序一些`Cap`，可能造成滥用。

例如，如果`gdb`程序拥有`cap_setuid`权限，可以造成提权

```shell
tree@tree-ubt:$ getcap `which gdb`
/usr/bin/gdb cap_setuid=ep

tree@tree-ubt:$ gdb -nx -ex 'python import os;os.setuid(0);' -ex '!sh' -ex quit
GNU gdb (Ubuntu 9.2-0ubuntu2) 9.2
.....
Type "apropos word" to search for commands related to "word".
# id
uid=0(root) gid=1000(tree) groups=1000(tree),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),121(lpadmin),132)

```




### 参考

[man-capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html)

[man-capset](https://linux.die.net/man/2/capset)

[linux-capabilities-in-practice](https://blog.container-solutions.com/linux-capabilities-in-practice)

[Linux-Capabilities](https://book.hacktricks.xyz/linux-unix/privilege-escalation/linux-capabilities)

[linux-privilege-escalation-using-capabilities](https://www.hackingarticles.in/linux-privilege-escalation-using-capabilities/)

[Inside LSM](https://elinux.org/images/0/0a/ELC_Inside_LSM.pdf)

[capability.conf](http://manpages.ubuntu.com/manpages/bionic/man5/capability.conf.5.html)

[privilege_escalation_by_capabilities](https://github.com/carlospolop/hacktricks/blob/master/linux-unix/privilege-escalation/linux-capabilities.md)

[GSSecurity-False Boundaries and Arbitrary Code Execution](https://forums.grsecurity.net/viewtopic.php?f=7&t=2522)

