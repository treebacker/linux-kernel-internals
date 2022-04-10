### Linux Namespace Part 5

#### 前言

​		在前面已经探讨了`user_namespace`、`pid_namespace`、`mnt_namespace`；

本文将剖析

#### 相关数据结构

```c
struct nsproxy {
	atomic_t count;
	struct uts_namespace *uts_ns;
	struct ipc_namespace *ipc_ns;
	struct mnt_namespace *mnt_ns;
	struct pid_namespace *pid_ns_for_children;
	struct net 	     *net_ns;
};
```

