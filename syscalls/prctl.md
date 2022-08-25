### Prctl描述
`prctl()`是一个很特殊的系统调用，它能够在多个维度修改当前进程的行为。
`prctl`的部分操作会混淆`user-space`的环境，所以使用时需要小心。


### 分析
```c
 #include <sys/prctl.h>

       int prctl(int option, unsigned long arg2, unsigned long arg3,
                 unsigned long arg4, unsigned long arg5);
```
第一个参数`option`是决定了要用`prctl`做什么，同时也决定了后续的参数是什么。

#### 常用的选项
##### PR_SET_NAME
该选项可以修改当前线程的线程名，就是/proc/self/task/tid/comm，对于单线程进程也是/proc/pid/comm，最长是16bytes（包括null），示例
```c
int main(int argc, char** argv)
{

    int ret=0;

    ret = prctl(PR_SET_NAME, "/usr/bin/ps", 0, 0, 0);
    if(ret != 0){
        perror("prctl");
        exit(-1);
    }
    while(1){
        sleep(1000);
        puts("i a running...");
    }
    close(fd);

    return 0;
}
tree@tree-pc:$ ./prctl_name_hide &
[1] 84028
tree@tree-pc:$ cat /proc/84028/comm 
/usr/bin/ps
```
###### 内核实现
```c
	struct task_struct *me = current;
	unsigned char comm[sizeof(me->comm)];
    ...
    case PR_SET_NAME:
    comm[sizeof(me->comm) - 1] = 0;
    if (strncpy_from_user(comm, (char __user *)arg2,
                    sizeof(me->comm) - 1) < 0)
        return -EFAULT;
    set_task_comm(me, comm);
    proc_comm_connector(me);
    break;
```
先通过`strncpy_from_user`将用户态传进来的`arg2`拷贝到`comm`，再`set_task_comm`设置
`tsk->comm`修改进程`comm`名。
最后的`proc_comm_connector`是向监听了`/proc`的listen比如`perf_event`发送`PROC_EVENT_COMM`事件。

* PR_SET_MM
该选项支持修改当前进程在内核内存里的map描述符，通常这些字段由内核或者动态加载器(ld.so)设定
正常的应用不会这么玩，但是有一种特定类型的程序（自修改程序）会这么做，例如加壳程序在脱壳时需要修改映射的内存。


当选中该选项时，第二个参数指定子选项，举几个例子
  * PR_SET_MM_START_CODE/PR_SET_MM_END_CODE
修改进程可运行代码段的起始/结束地址，指定的内存属性必须是可读可执行但是不可写，并且非共享类型。

  * PR_SET_MM_ARG_START/PR_SET_MM_ARG_END
这两个选项决定了内核在读/proc/pid/cmdline时的结果，换言之可以修改进程cmdline
```c
	prctl_map.arg_start	= mm->arg_start;
	prctl_map.arg_end	= mm->arg_end;
    ....

    case PR_SET_MM_ARG_START:
        prctl_map.arg_start = addr;
        break;
    case PR_SET_MM_ARG_END:
        prctl_map.arg_end = addr;
        break;

	mm->arg_start	= prctl_map.arg_start;
	mm->arg_end	= prctl_map.arg_end;
```
本质是修改`mm_struct->arg_start`和`mm_struct_arg_end`，这也是在读/proc/pid/cmdline内核实际去解析的东西，从`get_task_cmdline`的实现可以看出来
```c
static ssize_t get_task_cmdline(struct task_struct *tsk, char __user *buf,
				size_t count, loff_t *pos)
{
	struct mm_struct *mm;
	ssize_t ret;

	mm = get_task_mm(tsk);
	if (!mm)
		return 0;

	ret = get_mm_cmdline(mm, buf, count, pos);
	mmput(mm);
	return ret;
}
static ssize_t get_mm_cmdline(struct mm_struct *mm, char __user *buf,
			      size_t count, loff_t *ppos)
{
	unsigned long arg_start, arg_end, env_start, env_end;
	unsigned long pos, len;
	char *page, c;

	/* Check if process spawned far enough to have cmdline. */
	if (!mm->env_end)
		return 0;

	spin_lock(&mm->arg_lock);
	arg_start = mm->arg_start;
	arg_end = mm->arg_end;
	env_start = mm->env_start;
	env_end = mm->env_end;
    ...
    if (access_remote_vm(mm, arg_end-1, &c, 1, FOLL_ANON) == 1 && c)
    return get_mm_proctitle(mm, buf, count, pos, arg_start);
}
```
* PR_SET_MM_EXE_FILE
该选项可以修改进程文件路径/proc/pid/exe
```c
    // 验证有没有CAP_SYS_RESOURCE权限
	if (!capable(CAP_SYS_RESOURCE))
		return -EPERM;

	if (opt == PR_SET_MM_EXE_FILE)
		return prctl_set_mm_exe_file(mm, (unsigned int)addr);
```
`prctl`会先验证用于替换的`fd`文件有没有可执行权限
```c
static int prctl_set_mm_exe_file(struct mm_struct *mm, unsigned int fd)
{
	struct fd exe;
	struct inode *inode;
	int err;

	exe = fdget(fd);
	if (!exe.file)
		return -EBADF;

	inode = file_inode(exe.file);

	/*
	 * Because the original mm->exe_file points to executable file, make
	 * sure that this one is executable as well, to avoid breaking an
	 * overall picture.
	 */
	err = -EACCES;
	if (!S_ISREG(inode->i_mode) || path_noexec(&exe.file->f_path))
		goto exit;

	err = file_permission(exe.file, MAY_EXEC);
	if (err)
		goto exit;

	err = replace_mm_exe_file(mm, exe.file);
exit:
	fdput(exe);
	return err;
}
```
最终由`replace_mm_exe_file`替换
```c
int replace_mm_exe_file(struct mm_struct *mm, struct file *new_exe_file)
{
	struct vm_area_struct *vma;
	struct file *old_exe_file;
	int ret = 0;

	/* Forbid mm->exe_file change if old file still mapped. */
	old_exe_file = get_mm_exe_file(mm);
	if (old_exe_file) {
		mmap_read_lock(mm);
		for (vma = mm->mmap; vma && !ret; vma = vma->vm_next) {
			if (!vma->vm_file)
				continue;
			if (path_equal(&vma->vm_file->f_path,
				       &old_exe_file->f_path))
				ret = -EBUSY;
		}
		mmap_read_unlock(mm);
		fput(old_exe_file);
		if (ret)
			return ret;
	}

    ...
	old_exe_file = xchg(&mm->exe_file, new_exe_file);
    ...
	return 0;
}
```
替换之前会检查进程内的`mmap`地址块里是不是还有原`/proc/self/exe`文件的映射，如果有报错`-EBUSY`
否则替换`mm_struct->exe_file`即`/proc/self/exe`。
这个检查`unmap`原/proc/self/exe的条件看似很严格，但是事实上加了壳一类的文件，在脱壳中会去unmap原文件，实际测试upx最新版，unmap的不全，还会保留一个region，导致替换失败。而且觉得壳也比较显眼，所以这里自己实现了一个方案。

#### 完整实例
```c
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mman.h>
#define MAP_UTILS 0x10
#define FAKE_EXE_LENGTH 0x10

size_t orig_start = 0;
size_t map_size = 0;
size_t new_start = 0;

void collect_map_info()
{    
    char self_exe[256] = { 0 };    
    char* line = NULL;    
    size_t start, len, end, last_end = 0;    
    int i = 0 ;
    int flags, file_offset, dev_major, dev_minor, inode;      
    size_t start_array[MAP_UTILS] = { 0 };
    size_t end_array[MAP_UTILS] = { 0 };

    readlink("/proc/self/exe", self_exe, 256);     
    FILE* fp = fopen("/proc/self/maps", "r");   

    while(getline(&line, &len, fp) != -1){        
        sscanf(line,"%lx-%lx %4c %x %x:%x %lu", &start, &end, flags, &file_offset, &dev_major, &dev_minor, &inode);        
        if (strstr(line, self_exe)){                        
            if(orig_start == 0){                
                    orig_start =  start;                
            }
            start_array[i] = start;
            end_array[i] = end;
            last_end = end;
            i++;
        }    
    }    


    // whole map new
    map_size = last_end - orig_start;
    new_start = (size_t)mmap(NULL, map_size, PROT_READ|PROT_EXEC|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);

    // copy
    for(i = 0; i<MAP_UTILS; i++){
        if(start_array[i] == 0){
            break;
        }
        // copy each region
        memcpy((void*)new_start + (start_array[i] - orig_start), (void*)start_array[i], end_array[i] - start_array[i]);
    }
    
    return ;
}
        
void real_main(size_t orig_map_start, size_t orig_map_size)
{   
    int ret = 0;

    // const var store in stack
    const char fake[FAKE_EXE_LENGTH] = {'/', 'u', 's', 'r', '/', 'b', 'i', 'n', '/', 'p', 's', 0};
    int fd = open(fake, O_RDONLY);       
    munmap((void*)orig_start, map_size);    
    ret = prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0);       

    // 需要unmap所有原文件映射的内容    
    while(1){        
       sleep(1000);
    }        
    //close(fd);
    return ;
}


void wait()
{
    while(1){        
       sleep(1000);
    }  
    return ;
}
int main(int argc, char** argv)
{    
    int fd = 0;    
    int ret = 0;    
    size_t offset = 0;    
    const char* fake_argv = "/bin/ps\x00";        
    prctl(PR_SET_NAME, fake_argv, 0, 0, 0);                           //  修改/proc/pid/comm     [影响ps显示进程名，最长16包括null]    
    ret = prctl(PR_SET_MM, PR_SET_MM_ARG_START, fake_argv, 0, 0);       // 修改/proc/pid/cmdline   [影响ps]    
    ret = prctl(PR_SET_MM, PR_SET_MM_ARG_END, fake_argv + sizeof(fake_argv)+1, 0, 0);        
    collect_map_info();    
    offset = ((size_t)real_main - orig_start);    
    void (*real_func)(size_t b, size_t c) = (void(*)(size_t b, size_t c))(new_start + offset);    

    real_func(orig_start, map_size);    
    
    return 0;
}
```
上面的实现过程可以分成两部分：
* `collect_map_info`先收集一波当前进程`maps`信息将/proc/self/exe映射的地址找到；之后再分配一份大的map地址，将原/proc/self/exe映射的内存逐个region的复制一份到新的map中（所有region一起复制可能存在内存间隙导致非法访问）
* 通过偏移计算得到`real_main`在新分配的map中的地址，跳转到该地址执行；在`real_main`函数内完成`unmap`原/proc/self/exe的任务；
这里有一点要注意的是，`real_main`中不能访问原/proc/self/exe中的全局变量（没有修复重定位），所以这里是将变量存在栈上。

效果
```c
root@tree-pc:/home/tree/code/hide# ./prctl_name_hide &
[1] 118750
root@tree-pc:/home/tree/code/hide# ps -ef | grep 118750
root      118750  118677  0 08:04 pts/2    00:00:00 [/bin/ps]
root      118773  118677  0 08:04 pts/2    00:00:00 grep --color=auto 118750
root@tree-pc:/home/tree/code/hide# readlink /proc/118750/exe 
/usr/bin/ps
```
### Refer
* https://man7.org/linux/man-pages/man2/prctl.2.html