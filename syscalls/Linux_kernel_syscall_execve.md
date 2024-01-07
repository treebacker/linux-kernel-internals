

#### execve

`linux_binprm`结构

```c
/*
 * This structure is used to hold the arguments that are used when loading binaries.
 */
struct linux_binprm {
	char buf[BINPRM_BUF_SIZE];
#ifdef CONFIG_MMU
	struct vm_area_struct *vma;
	unsigned long vma_pages;
#else
# define MAX_ARG_PAGES	32
	struct page *page[MAX_ARG_PAGES];
#endif
	struct mm_struct *mm;
	unsigned long p; /* current top of mem */
	unsigned int
		cred_prepared:1,/* true if creds already prepared (multiple
				 * preps happen for interpreters) */
		cap_effective:1;/* true if has elevated effective capabilities,
				 * false if not; except for init which inherits
				 * its parent's caps anyway */
#ifdef __alpha__
	unsigned int taso:1;
#endif
	unsigned int recursion_depth; /* only for search_binary_handler() */
	struct file * file;
	struct cred *cred;	/* new credentials */
	int unsafe;		/* how unsafe this exec is (mask of LSM_UNSAFE_*) */
	unsigned int per_clear;	/* bits to clear in current->personality */
	int argc, envc;
	const char * filename;	/* Name of binary as seen by procps */
	const char * interp;	/* Name of the binary really executed. Most
				   of the time same as filename, but could be
				   different for binfmt_{misc,script} */
	unsigned interp_flags;
	unsigned interp_data;
	unsigned long loader, exec;
};

```



```
	retval = prepare_binprm(bprm);
	if (retval < 0)
		goto out;
```

`prepare_binprm`通过`inode`结构，初始化`binprm`结构，并读取前`128`字节，用于检查被执行文件的文件类型。

```c
/*
 * Fill the binprm structure from the inode.
 * Check permissions, then read the first 128 (BINPRM_BUF_SIZE) bytes
 *
 * This may be called multiple times for binary chains (scripts for example).
 */
int prepare_binprm(struct linux_binprm *bprm)
{
	int retval;

	bprm_fill_uid(bprm);

	/* fill in binprm security blob */
	retval = security_bprm_set_creds(bprm);
	if (retval)
		return retval;
	bprm->cred_prepared = 1;

	memset(bprm->buf, 0, BINPRM_BUF_SIZE);
	return kernel_read(bprm->file, 0, bprm->buf, BINPRM_BUF_SIZE);
}
```











#### Load ELF binfmt

`fs/binfmt_elf.c`

```c
static int __init init_elf_binfmt(void)
{
	register_binfmt(&elf_format);
	return 0;
}

static void __exit exit_elf_binfmt(void)
{
	/* Remove the COFF and ELF loaders. */
	unregister_binfmt(&elf_format);
}

core_initcall(init_elf_binfmt);
module_exit(exit_elf_binfmt);
```

`elf_format`

```c
static struct linux_binfmt elf_format = {
	.module		= THIS_MODULE,
	.load_binary	= load_elf_binary,
	.load_shlib	= load_elf_library,
	.core_dump	= elf_core_dump,
	.min_coredump	= ELF_EXEC_PAGESIZE,
};
```


#### execve/fexecve/execveat区别
```c
       int execve(const char *pathname, char *const _Nullable argv[],
                  char *const _Nullable envp[]);

		int fexecve(int fd, char *const argv[], char *const envp[]);

       int execveat(int dirfd, const char *pathname,
                    char *const _Nullable argv[],
                    char *const _Nullable envp[],
                    int flags);
```
1、execve和execveat是linux内核提供的系统调用，fexecve是glibc提供的库函数
2、execve执行指定的绝对路径的文件，execveat根据目录`dirfd`和文件名`pathname`执行文件
3、fexecve是根据文件`fd`执行文件，目的是允许在执行前校验要执行的文件没有被篡改过。

fexecve底层实现还是依赖execveat的
```c
int
fexecve (int fd, char *const argv[], char *const envp[])
{
  if (fd < 0 || argv == NULL || envp == NULL)
    {
      __set_errno (EINVAL);
      return -1;
    }
#ifdef __NR_execveat
  /* Avoid implicit array coercion in syscall macros.  */
  INLINE_SYSCALL (execveat, 5, fd, "", &argv[0], &envp[0], AT_EMPTY_PATH);
# ifndef __ASSUME_EXECVEAT
  if (errno != ENOSYS)
    return -1;
# endif
#endif
#ifndef __ASSUME_EXECVEAT
  /* We use the /proc filesystem to get the information.  If it is not
     mounted we fail.  We do not need the return value.  */
  struct fd_to_filename filename;
  __execve (__fd_to_filename (fd, &filename), argv, envp);
  int save = errno;
  /* We come here only if the 'execve' call fails.  Determine whether
     /proc is mounted.  If not we return ENOSYS.  */
  struct __stat64_t64 st;
  if (__stat64_time64 ("/proc/self/fd", &st) != 0 && errno == ENOENT)
    save = ENOSYS;
  __set_errno (save);
#endif
  return -1;
}
```
一种是`execveat`支持的`AT_EMPTY_PATH`，另一种是通过`__fd_to_filename`根据`fd`获取进程路径执行`execve`。

##### fexecve利用
fexecve被利用的最多的对抗场景就是无文件执行，由于linux上的匿名fd的存在，fexecve完全可以执行一个非落盘的文件，最佳的组合方式就是`memfd_create+fexecve`，其实通过`memfd_create+execveat`效果也一样




#### Refer

[Play with binfmt](https://www.linux.it/~rubini/docs/binfmt/binfmt.html)

[binfmt_aout](https://elixir.bootlin.com/linux/v5.8.18/source/fs/binfmt_aout.c#L34)

[linux kernel loading a executable program][http://www.dosrc.com/mark/linux-3.18.6/2016/05/15/linux-kernel-loading-of-executable-program.html]

[fexecve-sourcecode](https://codebrowser.dev/glibc/glibc/sysdeps/unix/sysv/linux/fexecve.c.html)
