### 	Linux namespaces Part 1

#### 简介

​		Namespace是Linux上一种实现资源隔离的抽象实现机制，可以一定程度实现Linux主机的资源隔离。

Docker的底层技术就是namespace。

Part 1部分主要介绍namespace的不同类型以及在userspace的代码测试，后续Part 主要关注kernel space的namespace的实现原理。

#### Namespace支持隔离的资源类型

* CGroup

  隔离CGroup root目录

* IPC

  隔离IPC、消息队列

* Net

  隔离网络设备、栈、端口等

* Mount

  隔离mnt mountpoint

* PID

  隔离process id

* USER

  隔离user 和 group ID

* UTS

  隔离Hostname和NIS Domain Name

* TIME

  隔离Boot 和 monotonic 时钟

进程所在的各种namespace都在`/proc/$pid/ns`下：

```shell
tree@tree-ubt:~/work$ ls /proc/self/ns/ -al
total 0
dr-x--x--x 2 tree tree 0 12月  5 21:01 .
dr-xr-xr-x 9 tree tree 0 12月  5 21:01 ..
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 cgroup -> 'cgroup:[4026531835]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 ipc -> 'ipc:[4026531839]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 mnt -> 'mnt:[4026531840]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 net -> 'net:[4026531992]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 pid -> 'pid:[4026531836]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 pid_for_children -> 'pid:[4026531836]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 time -> 'time:[4026531834]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 time_for_children -> 'time:[4026531834]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 user -> 'user:[4026531837]'
lrwxrwxrwx 1 tree tree 0 12月  5 21:01 uts -> 'uts:[4026531838]'
```

#### Namespace 实践













#### 参考

[namespace(man-7)](https://man7.org/linux/man-pages/man7/namespaces.7.html)