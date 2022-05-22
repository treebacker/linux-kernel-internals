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
这些namespace文件都是链接文件，内容格式为`xxx:[inode number]`，其中`xxx`标识namespace类型，`inode number`表示一个namespace ID.

#### Namespace Lifetime
一般情况下，当某一个namespace下的最后一个进程结束或者退出namespace后，该namespace自动消失。但是在某些情况下，即使namespace下没有进程了，该namespace也依然存在：
* /proc/[pid]/ns/* 下的文件描述符仍然处于`open`
* 该namespace有一个child namespace
* ...


#### Namespace 实践
以`UTS Namespace`为例
##### 为子进程新建一个namespace
```c
#define _GNU_SOURCE
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <string.h>

#define STACK_SIZE  (1024 * 1024)
static char child_stack[STACK_SIZE];

static int child_main(void* hostname){
    sethostname(hostname, strlen(hostname));
    execlp("/bin/bash", "/bin/bash", NULL);
    return 0;
}

int main(int argc, char** argv) {
    pid_t c_pid = 0;

    c_pid = clone(child_main, child_stack + STACK_SIZE, CLONE_NEWUTS | SIGCHLD, argv[1]);

    waitpid(c_pid, NULL, 0);
    return 0;
}
```
需要root权限（或者有相应的caps）运行，效果：
```
tree@tree-pc:$ sudo ./new_uts container
root@container:# id
uid=0(root) gid=0(root) groups=0(root)
```

##### 将当前进程加入指定的namespace
`setns`函数允许修改当前进程的`namespace`
```
int setns(int fd, int nstype);
```
其中`fd`即是指定`namespace`的文件描述符，来自`open(/proc/[pid]/ns/xxx)`
`nstype`即是需要修改的namespace类型，当为`0`时，由系统检测`fd`属于的namespace类型。

```c
int main(int argc, char** argv) {

    int fd, ret;


    fd = open(argv[1], O_RDONLY);

    ret = setns(fd, CLONE_NEWUTS);
    execlp("bash", "bash", NULL);
    return 0;
}
```
效果
```
tree@tree-pc:~/code/namespace$ sudo ./set_uts /proc/7147/ns/uts
root@container:/home/tree/code/namespace# hostname
container
```
#### 参考

[namespace(man-7)](https://man7.org/linux/man-pages/man7/namespaces.7.html)
[uts_namespace(man-7)](https://man7.org/linux/man-pages/man7/uts_namespaces.7.html)