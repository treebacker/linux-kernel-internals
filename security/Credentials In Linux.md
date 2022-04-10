

### 总览



### Credentials类型

#### Traditional Uinx Credentials

熟知的Linux的UID/GID，通常定义了objective的上下文 ，对于一个task，其又可以细分为不同的场景

- E/S/F UID
- E/S/F GID

通常，EUID/EGID 作为subjective context，RUID/RGID作为objective。



#### Capabilities

这是进程独有的一种Credential，Capabilities分为以下几个集合

- Set of  permitted capabilities

- - 可通过`capset()`将该集合里的caps赋予自己，也就是进入`effecitve caps set`

- Set of inheritable  capabilities

- - 可继承的`caps`可以通过`execve`继承给子进程

- Set of effective  capabilities

- - 进程已经拥有的`caps`

-  Capabilities bounding set

- - 能力集合边界，限制通过`execve`继承的`caps`，尤其是对于以`uid=0`执行的文件。



#### Security management flags(securitybits)

进程独有的，用于管理上述`credentials`通过某些方式的操作和继承，不会直接用做**objective** 或者**subjective**的凭证

#### Keys and keyrings

进程独有的，它们保存了不适合其他标准UNIX凭证的安全令牌。

一个经典的使用场景：进程访问网络文件系统文件，普通程序不需要了解涉及的安全细节。

*Keyring*是一种特殊的*key*，可视为一组*key*的键值，用于搜索期望的*key*。

#### LSM

**Linux Security Mode**允许对进程的行为做更多的限制。

#### AF_KEY

一种基于*socket*的用于网络栈的凭证管理机制。



### File Markings

文件有着自己的客观安全上下文，取决于文件系统类型，通常包含以下一种或多种文件标记

* UNIX UID, GID, mode；
* Unix exec privilege escalation bits (SUID/SGID)（特权标志位）
* File capabilities exec privilege escalation bits（文件能力特权标志位）

当某进程操作一文件时，文件的客观上下文和进程的主观安全上下文相比较，最终判定*允许*或者*不允许*。

当执行`execve`时，特权标志位发挥作用，可能允许进程获取额外的特权。

### Task Credentials

在Linux上，进程的所有credentials都保存在`struct cred`结构中（或者是一个应用），每一个进程结构体`task_struct`中都有一个指向`cred`的指针。

对`cred`结构体的任何改动，遵循*copy-and-replace*原则：首先copy一份`cred`，然后修改复制的`cred`，之后通过*RCU*修改进程的`cred`指针指向复制的新的`cred`。

进程只允许修改它自身的`cred`。`capset`系统调用只允许作用于当前进程，而不能指定其他*PID*进程。



### Open File Credentials

进程打开一个新的文件后， 进程的`cred`结构体中保存一个引用结构体`f_cred`。

### 参考

- Linux Security Document

- - https://www.kernel.org/doc/html/latest/security/credentials.html

- 