#### Description
Linux多个文件系统支持为文件/目录设置扩展属性，基本的格式是`name:value`，类似于进程的环境变量。
所谓的`扩展属性`是相对于`inode`的基础属性而言（`stat`显示的）的。

#### Extended Attribute Name Format And Types
扩展属性名是一个字符串，常见的格式`namespace.attribute`，例如`user.mime_type`、`trusted.md5sum`、`system.posix_acl_access`、`security.selinux`。
其中作为`prefix`的`namespace`是一种区分不同类型的`attribute`的机制，这种区分存在不仅是为了将扩展属性分类，同时也是权限的区分，不同类型的attr所需的权限不同。
目前有的四种`namespace`：
* Security：由内核安全模块使用，例如`Selinux`；文件的`cap`信息也是存在`security.capability`中
* System：system扩展属性由内核使用，用于存储系统对象信息，例如`ACLs`
* Trusted: 在用户态使用，常用于保存只有有`SYS_CAP_ADMIN`权限的进程可访问的信息
* User: 用户可扩展属性常用于描述文件/目录更多的信息，例如：mime type、encoding；对user.xx属性的读写权限由文件的读写权限决定

#### Limitations
不同的文件系统对于`name:value`有不同的长度、大小限制。
VFS文件系统限制`name`长度在`255`bytes以内、`value`大小在`64kb`以内。

#### Manage The Attr From command line
`attr`包提供了管理(set/get)attr的命令
```
$ attr --help
attr: invalid option -- '-'
Unrecognized option: ?
Usage: attr [-LRSq] -s attrname [-V attrvalue] pathname  # set value
       attr [-LRSq] -g attrname pathname                 # get value
       attr [-LRSq] -r attrname pathname                 # remove attr
       attr [-LRq]  -l pathname                          # list attrs 
      -s reads a value from stdin and -g writes a value to stdout
```
设置文件attr `name:value`
```
$ echo "i am a attr demo" >> demo.txt 

$ attr -s user.comment -V "this a comment for demo" demo.txt 
Attribute "user.comment" set to a 23 byte value for demo.txt:
this a comment for demo
```

列举文件所有attr
```
$ attr -l demo.txt 
Attribute "user.comment" has a 23 byte value for demo.txt
```

获取某attr的value
```
$ attr -g user.comment demo.txt 
Attribute "user.comment" had a 23 byte value for demo.txt:
this a comment for demo
```
删除某attr
```
$ attr -r user.comment demo.txt 
$ attr -l demo.txt 
$ 
```

#### Abusing extended attrbitue

文件的扩展属性，由于常见的命令：`cat`、`stat`、`ls`等无法展示其内容，是一个可用于隐藏数据的地方。
以下是一个将payload隐藏在`attribute`中，并取出执行的case：
```
#include <stdio.h>
#include <stdlib.h>
#include <sys/xattr.h>

#define PayloadAttr     "user.payload"
#define PayloadPath     "/tmp/a"

void hide_payload()
{
    int ret = 0;
    ret = setxattr(PayloadPath, PayloadAttr, "ls -al", 5, 0);

    if(ret != 0){
        perror("setxattr");
    }
    return ;
}

void exec_payload()
{   
    int ret = 0;
    char* command[256] = { 0 };

    getxattr(PayloadPath, PayloadAttr, command, 256);
    if(ret != 0){
        perror("setxattr");
    }
    puts(command);
    system(command);
}
int main()
{
    hide_payload();
    exec_payload();
}
```
```
$ ./hide_exec 
ls -a
.  ..  demo.txt  hide_exec  hide_exec.c
```
