### 前言
工作中偶然发现引擎部署一段时间之后，机器上的引擎进程会被强制kill一部分，导致引擎丢掉一些处理日志。
通过`dmesg`日志发现每一个被kill的进程都有一条`Out-Of-Memeory ...`记录，最终定位到是由于进程占用过多内存，系统内存负载过高而导致强制kill的，这里详细记录下Linux 内核的OOM机制。

### Memory-WaterMark & Out-Of-Memory
在前面的[Linux内存管理（一）](Linux%E5%86%85%E5%AD%98%E7%AE%A1%E7%90%86%EF%BC%88%E4%B8%80%EF%BC%89.md)中提到的`struct zone`结构中的一个字段`_watermark`，它记录了当前系统`zone`内存区域下的剩余空闲内存，影响到内存回收的决策。
当`_watermark`为`low`时，会触发内存回收处理（内存回收由`kswapd`内核线程处理）。

但是如果不幸的事情出现了，就是当内存回收完之后发现依然没办法满足所需要的内存请求，内核将触发`out-of-memory`路径。
之所以出现这种情况是由于linux的`overcommit`机制，进程在申请内存时，并不是立即去申请真实的物理内存，而是等到需要的时候再去分配（申请并不等于分配），也就意味着一个进程可以申请到大于实际物理内存的内存，即`overcommit`，这就带来一个问题，就是我真的需要我申请的全部的内存。

### OOM-Killer
在系统出现`oom`的情况下，剩下的两种选择就是要么选择一个进程kill掉，要么放任不管，让系统crash，显然前者代价更小。
`oom-killer`机制主要就是在前者情况中，选出一个代价更小、效果更佳的进程去kill。
`oom-killer`机制的实现在`mmm/oom_kill.c`中
主要的策略流程体现在`out_of_memory`函数中，该函数的参数`struct oom_control`结构，记录的是触发`oom killer`的分配请求详情（主要是发生oom的内存zone/cpuset信息），用于辅助决策应该kill哪个进程。
```c
/*
 * Details of the page allocation that triggered the oom killer that are used to
 * determine what should be killed.
 */
struct oom_control {
	/* Used to determine cpuset */
	struct zonelist *zonelist;

	/* Used to determine mempolicy */
	nodemask_t *nodemask;

	/* Memory cgroup in which oom is invoked, or NULL for global oom */
	struct mem_cgroup *memcg;

	/* Used to determine cpuset and node locality requirement */
	const gfp_t gfp_mask;

	/*
	 * order == -1 means the oom kill is required by sysrq, otherwise only
	 * for display purposes.
	 */
	const int order;

	/* Used by oom implementation, do not set */
	unsigned long totalpages;
	struct task_struct *chosen;
	long chosen_points;

	/* Used to print the constraint info. */
	enum oom_constraint constraint;
};
```
```c
/**
 * out_of_memory - kill the "best" process when we run out of memory
 * @oc: pointer to struct oom_control
 *
 * If we run out of memory, we have the choice between either
 * killing a random task (bad), letting the system crash (worse)
 * OR try to be smart about which process to kill. Note that we
 * don't have to be perfect here, we just have to be good.
 */
bool out_of_memory(struct oom_control *oc)
{
    //omm_killer机制开启
	if (oom_killer_disabled)
		return false;

    // 如果是全局memory cgroup发生 oom
	if (!is_memcg_oom(oc)) {
        // 调用block通知链的oom_notify_list函数
		blocking_notifier_call_chain(&oom_notify_list, 0, &freed);
		if (freed > 0 && !is_sysrq_oom(oc))
			/* Got some memory back in the last second. */
			return true;
	}

	/*
	 * If current has a pending SIGKILL or is exiting, then automatically
	 * select it.  The goal is to allow it to allocate so that it may
	 * quickly exit and free its memory.
	 */
    /* 
    * 如果正在申请分配内存的进程（当前进程）有还没处理（pending）的SIGKILL信号，或者正在退出，则选择当前进程/* 来kill，这样退出最快，代价也最低（不用伤害无辜）
    */
	if (task_will_free_mem(current)) {
		mark_oom_victim(current);
		queue_oom_reaper(current);
		return true;
	}

	/*
	 * The OOM killer does not compensate for IO-less reclaim.
	 * pagefault_out_of_memory lost its gfp context so we have to
	 * make sure exclude 0 mask - all other users should have at least
	 * ___GFP_DIRECT_RECLAIM to get here. But mem_cgroup_oom() has to
	 * invoke the OOM killer even if it is a GFP_NOFS allocation.
	 */
	if (oc->gfp_mask && !(oc->gfp_mask & __GFP_FS) && !is_memcg_oom(oc))
		return true;

	/*
	 * Check if there were limitations on the allocation (only relevant for
	 * NUMA and memcg) that may require different handling.
	 */

     /*
     *  检查是否在allocation时有限制，仅用于NUMA场景
     */
	oc->constraint = constrained_alloc(oc);
	if (oc->constraint != CONSTRAINT_MEMORY_POLICY)
		oc->nodemask = NULL;
	check_panic_on_oom(oc);

    /*
    * 检查是否配置了sysctl_oom_kill_allocating_task （触发oom的当前进程被kill）
    * 如果当前进程是killable的，oom_score_adj不是最小值的情况下，选择kill当前进程
    */
	if (!is_memcg_oom(oc) && sysctl_oom_kill_allocating_task &&
	    current->mm && !oom_unkillable_task(current) &&
	    oom_cpuset_eligible(current, oc) &&
	    current->signal->oom_score_adj != OOM_SCORE_ADJ_MIN) {
		get_task_struct(current);
		oc->chosen = current;
		oom_kill_process(oc, "Out of memory (oom_kill_allocating_task)");
		return true;
	}
    // 根据既定策略选择一个最佳的进程kill
	select_bad_process(oc);
	/* Found nothing?!?! */

    /*
    * 如果没有找到一个合适的进程去kill，直接panic
    */
	if (!oc->chosen) {
		dump_header(oc, NULL);
		pr_warn("Out of memory and no killable processes...\n");
		/*
		 * If we got here due to an actual allocation at the
		 * system level, we cannot survive this and will enter
		 * an endless loop in the allocator. Bail out now.
		 */
		if (!is_sysrq_oom(oc) && !is_memcg_oom(oc))
			panic("System is deadlocked on memory\n");
	}
    // 强制kill被选择的进程（释放内存）
	if (oc->chosen && oc->chosen != (void *)-1UL)
		oom_kill_process(oc, !is_memcg_oom(oc) ? "Out of memory" :
				 "Memory cgroup out of memory");
	return !!oc->chosen;
}
```
#### How to select a bad process
选择一个最佳被kill的进程是由select_bad_process完成
```c
/*
 * Simple selection loop. We choose the process with the highest number of
 * 'points'. In case scan was aborted, oc->chosen is set to -1.
 */
static void select_bad_process(struct oom_control *oc)
{
	oc->chosen_points = LONG_MIN;

	if (is_memcg_oom(oc))
		mem_cgroup_scan_tasks(oc->memcg, oom_evaluate_task, oc);
	else {
		struct task_struct *p;

		rcu_read_lock();
		for_each_process(p)
			if (oom_evaluate_task(p, oc))
				break;
		rcu_read_unlock();
	}
}
```
逻辑就是遍历所有进程，计算点数，选择一个最大点数的进程，有一些特殊情况：
* 忽略系统初始化进程`init`和内核线程`KTHREAD`
```c
/* return true if the task is not adequate as candidate victim task. */
static bool oom_unkillable_task(struct task_struct *p)
{
	if (is_global_init(p))
		return true;
	if (p->flags & PF_KTHREAD)
		return true;
	return false;
}
```
* 如果进程被标记为`当它触发OOM时，优先被kill`，则优先选择触发oom的进程
```c
    static inline bool oom_task_origin(const struct task_struct *p)
    {
        return p->signal->oom_flag_origin;
    }

	/*
	 * If task is allocating a lot of memory and has been marked to be
	 * killed first if it triggers an oom, then select it.
	 */
	if (oom_task_origin(task)) {
		points = LONG_MAX;
		goto select;
	}
```
计算每个进程`point`的逻辑在oom_badness中
```c
	points = oom_badness(task, oc->totalpages);
	if (points == LONG_MIN || points < oc->chosen_points)
		goto next;

long oom_badness(struct task_struct *p, unsigned long totalpages)
{
	long points;
	long adj;

    // 忽略init 和 KTHREAD 进程
	if (oom_unkillable_task(p))
		return LONG_MIN;

    // 进程是否还存活
	p = find_lock_task_mm(p);
	if (!p)
		return LONG_MIN;

	/*
	 * Do not even consider tasks which are explicitly marked oom
	 * unkillable or have been already oom reaped or the are in
	 * the middle of vfork
	 */
    // 取进程/proc/PID/oom_score_adj
	adj = (long)p->signal->oom_score_adj;
    // 忽略被标记为OOM_SKIP的进程，忽略处在vfork中的进程
	if (adj == OOM_SCORE_ADJ_MIN ||
			test_bit(MMF_OOM_SKIP, &p->mm->flags) ||
			in_vfork(p)) {
		task_unlock(p);
		return LONG_MIN;
	}

	/*
	 * The baseline for the badness score is the proportion of RAM that each
	 * task's rss, pagetable and swap space use.
	 */
    
    // 计算逻辑
    // points = rss(驻留内存/占用物理内存) + 交换分区用量 + PTE数量
	points = get_mm_rss(p->mm) + get_mm_counter(p->mm, MM_SWAPENTS) +
		mm_pgtables_bytes(p->mm) / PAGE_SIZE;
	task_unlock(p);

	/* Normalize to oom_score_adj units */
    // 归一化
	adj *= totalpages / 1000;
	points += adj;

	return points;
}

```

### 引用
[Out Of Memory Management](https://www.kernel.org/doc/gorman/html/understand/understand016.html)
[Kernel-MM-OOM](https://abcdxyzk.github.io/blog/2015/09/30/kernel-mm-oom/)
[oom_kill.c](https://github.com/torvalds/linux/blob/master/mm/oom_kill.c)