### 简介
内存管理机制是很多上层应用的基础，特别是的性能优化或者异常问题排查过程中，如果深入理解了Linux内核对于内存的管理，就能快速定位并找到解决方案。

### 物理内存体系

目前多处理器系统有两种：（Uniform-Memory-Access，简称UMA）模型和（NonUniform-Memory-Access，简称NUMA）模型。
#### UMA模型
传统的多核使用的是SMP模式：将多个处理器与一个集中的存储器和I/O总线连接。所有的处理器只能访问同一个物理存储器，因此对于SMP模式，对于每一个处理器，内存中的每一个数据都是一致的，处理器访问它们的时间也是一致的。

SMP的缺点在于当存储器和I/O接口达到饱和的时候，因为所有的处理器会相互竞争内存总线的访问，增加处理器并不能获得更高的性能。
#### NUMA模型
NUMA是一种分布式存储器访问方式，处理器可以同时访问不同的存储器地址，大幅度提高并行性。
在NUMA模式下，处理器被划分为多个节点（`node`），每个处理器与一个本地内存直接相连，不同处理器之间通过总线进一步连接，所以每个节点中的处理器都有可以访问所有的存储内存，但是处理器访问它自身节点被分配的存储空间的速度要快于访问其他节点的存储空间。
MUMA的优点在于他的可伸缩性，可以缓解SMP存在的瓶颈问题。


### Linux物理内存结构
Linux适用于不同的体系结构，而不同的体系结构在内存管理方面差别很大，Linux使用一种兼容层的方式使得不同体系的差异被隐藏起来，内核可以同时支持一致/非一致内存访问。

在NUMA下
* 处理器被划分成多个节点`node`，个节点被分配了一定的本地存储空间，每个节点中的处理器都有可以访问所有的存储器，但是处理器访问它自身节点被分配的存储空间的速度要快于访问其他节点的存储空间。
* 内存被分成多个区域（BANK，簇），根据簇和处理器的距离不同，访问不同簇的代码也会不同。比如可能把内存的一个簇指派给每一个处理器，或者某个簇和设备卡很近，就指派给该设备。大多数系统将内存分割成2个区域，一个专门给cpu访问，一块是给外围设备使用（DMA）

UMA模式，就相当于NUMA模式下的一个节点。即内存使用一个NUMA的一个节点管理整个系统的内存，可以认为是一个（伪）NUMA系统。

可以通过`numactl -H`命令查看当前系统的内存架构
```shell
tree@tree-pc:$ numactl -H
available: 1 nodes (0)
node 0 cpus: 0 1 2 3 4 5
node 0 size: 3891 MB
node 0 free: 689 MB
node distances:
node   0 
  0:  10 
```
在我的系统上，有6个cpu核，都是在同一个`node`上，也就是`UMA`模式。

Linux把物理内存划分为三个层次分级管理
#### node
cpu被划分为多个node，每一个node被分配了独立的存储内存，即一个cpu-node对应一个内存簇，每一个内存簇被认为是一个节点.
##### 数据结构
在NUMA机器上，一个节点由一个`pg_data_t`表示，系统中的每一个节点被链接到一个`pgdata_list`链表中，每一个节点利用`pg_data_tnode_next`字段链接到下一个节，对于`UMA`机器，只有一个`pglist_data`管理整个内存。

定义在`include/linux/mmzone.h`: `typedef struct pglist_data pg_data_t`
```c
typedef struct pglist_data {
	/*
	 * node_zones contains just the zones for THIS node. Not all of the
	 * zones may be populated, but it is the full list. It is referenced by
	 * this node's node_zonelists as well as other node's node_zonelists.
	 */
	struct zone node_zones[MAX_NR_ZONES];

	/*
	 * node_zonelists contains references to all zones in all nodes.
	 * Generally the first zones will be references to this node's
	 * node_zones.
	 */
	struct zonelist node_zonelists[MAX_ZONELISTS];

	int nr_zones; /* number of populated zones in this node */
#ifdef CONFIG_FLATMEM	/* means !SPARSEMEM */
	struct page *node_mem_map;
#ifdef CONFIG_PAGE_EXTENSION
	struct page_ext *node_page_ext;
#endif
#endif
#if defined(CONFIG_MEMORY_HOTPLUG) || defined(CONFIG_DEFERRED_STRUCT_PAGE_INIT)
	/*
	 * Must be held any time you expect node_start_pfn,
	 * node_present_pages, node_spanned_pages or nr_zones to stay constant.
	 * Also synchronizes pgdat->first_deferred_pfn during deferred page
	 * init.
	 *
	 * pgdat_resize_lock() and pgdat_resize_unlock() are provided to
	 * manipulate node_size_lock without checking for CONFIG_MEMORY_HOTPLUG
	 * or CONFIG_DEFERRED_STRUCT_PAGE_INIT.
	 *
	 * Nests above zone->lock and zone->span_seqlock
	 */
	spinlock_t node_size_lock;
#endif
	unsigned long node_start_pfn;
	unsigned long node_present_pages; /* total number of physical pages */
	unsigned long node_spanned_pages; /* total size of physical page
					     range, including holes */
	int node_id;
	wait_queue_head_t kswapd_wait;
	wait_queue_head_t pfmemalloc_wait;

	/* workqueues for throttling reclaim for different reasons. */
	wait_queue_head_t reclaim_wait[NR_VMSCAN_THROTTLE];

	atomic_t nr_writeback_throttled;/* nr of writeback-throttled tasks */
	unsigned long nr_reclaim_start;	/* nr pages written while throttled
					 * when throttling started. */
	struct task_struct *kswapd;	/* Protected by
					   mem_hotplug_begin/end() */
	int kswapd_order;
	enum zone_type kswapd_highest_zoneidx;

	int kswapd_failures;		/* Number of 'reclaimed == 0' runs */

#ifdef CONFIG_COMPACTION
	int kcompactd_max_order;
	enum zone_type kcompactd_highest_zoneidx;
	wait_queue_head_t kcompactd_wait;
	struct task_struct *kcompactd;
	bool proactive_compact_trigger;
#endif
	/*
	 * This is a per-node reserve of pages that are not available
	 * to userspace allocations.
	 */
	unsigned long		totalreserve_pages;

#ifdef CONFIG_NUMA
	/*
	 * node reclaim becomes active if more unmapped pages exist.
	 */
	unsigned long		min_unmapped_pages;
	unsigned long		min_slab_pages;
#endif /* CONFIG_NUMA */

	/* Write-intensive fields used by page reclaim */
	ZONE_PADDING(_pad1_)

#ifdef CONFIG_DEFERRED_STRUCT_PAGE_INIT
	/*
	 * If memory initialisation on large machines is deferred then this
	 * is the first PFN that needs to be initialised.
	 */
	unsigned long first_deferred_pfn;
#endif /* CONFIG_DEFERRED_STRUCT_PAGE_INIT */

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
	struct deferred_split deferred_split_queue;
#endif

	/* Fields commonly accessed by the page reclaim scanner */

	/*
	 * NOTE: THIS IS UNUSED IF MEMCG IS ENABLED.
	 *
	 * Use mem_cgroup_lruvec() to look up lruvecs.
	 */
	struct lruvec		__lruvec;

	unsigned long		flags;

	ZONE_PADDING(_pad2_)

	/* Per-node vmstats */
	struct per_cpu_nodestat __percpu *per_cpu_nodestats;
	atomic_long_t		vm_stat[NR_VM_NODE_STAT_ITEMS];
} pg_data_t;
```
* node_zones：包含了该node节点的所有zone，包括ZONE_DMA\ZONE_NORMAL\ZONE_HIGHMEM
* node_zonelists: 包含所有节点的所有zone（备用节点），在当前节点内存不够用时，选取访问代价最低的节点进行分配，分配内存操作时的区域顺序，在调用`free_area_init_core`时，由`build_zonrelists`设置。
* nr_zones：当前node节点包含的不用zone域的数量，并不是所有的节点都要有三个zone，比如一个CPU簇就可能没有ZONE_DMA.
* node_mem_map： node中的第一个page，它可以指向mem_map中的任何一个page
* node_start_pfn：`pfn`即page frame number，表示node开始的page在物理内存中的位置。当前NUMA节点的第一个页的编号，系统中所有页是依次编号的，这个字段表示当前节点页的起始值，对于UMA，只有一个节点，该值一直是0
* node_present_pages：当前节点可用的物理内存页的总数
* node_spanned_pages：当前节点以页为单位的大小（包括内存间隙）
* node_id：当前节点NODE ID编号，从0开始
* kswapd_wait：node的等待队列，交换守护队列进程的等待列表

#### zone（DMA-DMA32-NORMAL-HIGHMEM）
每个内存簇根据不同的用途/特性划分为不同的内存管理区域，在内核中由`struct zone`结构描述
有两种特殊情况：
* 某些设备(ISA总线直接内存存储DMA处理器有一个严格的限制）只能对RAM的前16MB进行寻址，这一部分就是DMA
* 某些体系（X86）因为线性地址空间太小，CPU不能访问到所有的物理地址，内核不可能映射所有的物理内存到线性地址空间，这一部分就是HIGHMEM
除此之外，都是可以映射到虚拟地址空间的普通内存区域，称为ZONE_NORMAL，正常我们代码里用到的内存都来自这个区域。

##### 数据结构
内核中zone的表示结构即`struct `
相关定义在`include/linux/mmzone.h`中
```c
struct zone {
	/* Read-mostly fields */

	/* zone watermarks, access with *_wmark_pages(zone) macros */
	unsigned long _watermark[NR_WMARK];
	unsigned long watermark_boost;

	unsigned long nr_reserved_highatomic;

	/*
	 * We don't know if the memory that we're going to allocate will be
	 * freeable or/and it will be released eventually, so to avoid totally
	 * wasting several GB of ram we must reserve some of the lower zone
	 * memory (otherwise we risk to run OOM on the lower zones despite
	 * there being tons of freeable ram on the higher zones).  This array is
	 * recalculated at runtime if the sysctl_lowmem_reserve_ratio sysctl
	 * changes.
	 */
	long lowmem_reserve[MAX_NR_ZONES];

#ifdef CONFIG_NUMA
	int node;
#endif
	struct pglist_data	*zone_pgdat;
	struct per_cpu_pages	__percpu *per_cpu_pageset;
	struct per_cpu_zonestat	__percpu *per_cpu_zonestats;
	/*
	 * the high and batch values are copied to individual pagesets for
	 * faster access
	 */
	int pageset_high;
	int pageset_batch;

#ifndef CONFIG_SPARSEMEM
	/*
	 * Flags for a pageblock_nr_pages block. See pageblock-flags.h.
	 * In SPARSEMEM, this map is stored in struct mem_section
	 */
	unsigned long		*pageblock_flags;
#endif /* CONFIG_SPARSEMEM */

	/* zone_start_pfn == zone_start_paddr >> PAGE_SHIFT */
	unsigned long		zone_start_pfn;

	/*
	 * spanned_pages is the total pages spanned by the zone, including
	 * holes, which is calculated as:
	 * 	spanned_pages = zone_end_pfn - zone_start_pfn;
	 *
	 * present_pages is physical pages existing within the zone, which
	 * is calculated as:
	 *	present_pages = spanned_pages - absent_pages(pages in holes);
	 *
	 * present_early_pages is present pages existing within the zone
	 * located on memory available since early boot, excluding hotplugged
	 * memory.
	 *
	 * managed_pages is present pages managed by the buddy system, which
	 * is calculated as (reserved_pages includes pages allocated by the
	 * bootmem allocator):
	 *	managed_pages = present_pages - reserved_pages;
	 *
	 * cma pages is present pages that are assigned for CMA use
	 * (MIGRATE_CMA).
	 *
	 * So present_pages may be used by memory hotplug or memory power
	 * management logic to figure out unmanaged pages by checking
	 * (present_pages - managed_pages). And managed_pages should be used
	 * by page allocator and vm scanner to calculate all kinds of watermarks
	 * and thresholds.
	 *
	 * Locking rules:
	 *
	 * zone_start_pfn and spanned_pages are protected by span_seqlock.
	 * It is a seqlock because it has to be read outside of zone->lock,
	 * and it is done in the main allocator path.  But, it is written
	 * quite infrequently.
	 *
	 * The span_seq lock is declared along with zone->lock because it is
	 * frequently read in proximity to zone->lock.  It's good to
	 * give them a chance of being in the same cacheline.
	 *
	 * Write access to present_pages at runtime should be protected by
	 * mem_hotplug_begin/end(). Any reader who can't tolerant drift of
	 * present_pages should get_online_mems() to get a stable value.
	 */
	atomic_long_t		managed_pages;
	unsigned long		spanned_pages;
	unsigned long		present_pages;
#if defined(CONFIG_MEMORY_HOTPLUG)
	unsigned long		present_early_pages;
#endif
#ifdef CONFIG_CMA
	unsigned long		cma_pages;
#endif

	const char		*name;

#ifdef CONFIG_MEMORY_ISOLATION
	/*
	 * Number of isolated pageblock. It is used to solve incorrect
	 * freepage counting problem due to racy retrieving migratetype
	 * of pageblock. Protected by zone->lock.
	 */
	unsigned long		nr_isolate_pageblock;
#endif

#ifdef CONFIG_MEMORY_HOTPLUG
	/* see spanned/present_pages for more description */
	seqlock_t		span_seqlock;
#endif

	int initialized;

	/* Write-intensive fields used from the page allocator */
	ZONE_PADDING(_pad1_)

	/* free areas of different sizes */
	struct free_area	free_area[MAX_ORDER];

	/* zone flags, see below */
	unsigned long		flags;

	/* Primarily protects free_area */
	spinlock_t		lock;

	/* Write-intensive fields used by compaction and vmstats. */
	ZONE_PADDING(_pad2_)

	/*
	 * When free pages are below this point, additional steps are taken
	 * when reading the number of free pages to avoid per-cpu counter
	 * drift allowing watermarks to be breached
	 */
	unsigned long percpu_drift_mark;

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* pfn where compaction free scanner should start */
	unsigned long		compact_cached_free_pfn;
	/* pfn where compaction migration scanner should start */
	unsigned long		compact_cached_migrate_pfn[ASYNC_AND_SYNC];
	unsigned long		compact_init_migrate_pfn;
	unsigned long		compact_init_free_pfn;
#endif

#ifdef CONFIG_COMPACTION
	/*
	 * On compaction failure, 1<<compact_defer_shift compactions
	 * are skipped before trying again. The number attempted since
	 * last failure is tracked with compact_considered.
	 * compact_order_failed is the minimum compaction failed order.
	 */
	unsigned int		compact_considered;
	unsigned int		compact_defer_shift;
	int			compact_order_failed;
#endif

#if defined CONFIG_COMPACTION || defined CONFIG_CMA
	/* Set to true when the PG_migrate_skip bits should be cleared */
	bool			compact_blockskip_flush;
#endif

	bool			contiguous;

	ZONE_PADDING(_pad3_)
	/* Zone statistics */
	atomic_long_t		vm_stat[NR_VM_ZONE_STAT_ITEMS];
	atomic_long_t		vm_numa_event[NR_VM_NUMA_EVENT_ITEMS];
} ____cacheline_internodealigned_in_smp;
```
* _watermark: 内存水位，包括WMARK_MIN、WMARK_LOW、WMARK_HIGH、WMARK_PROMO,表示当前zone剩余的空闲内存，影响到内存回收。
  * HIGH 表示当前剩余内存充足，压力不大
  * LOW 表示内存不足，出发kswapd内核线程进行内存回收处理
  * MIN 当剩余在MIN以下时，内存压力非常大，一般MIN以下的内存不再被分配，默认保留给特殊的用途使用。
* lowmem_reserve：预留的低地址内存，为了防止部分代码必须在低地址区域，事先预留一部分内存
* zone_pgdat: 指向这个zone所在node的pglist_data对象
* per_cpu_pageset： zone里page管理的数据结构对象，成员lists管理page的列表，每一个cpu维护一个page list，可以避免自旋锁冲突
* zone_start_pfn：表示zone的第一个页帧编号
* managed_pages: 实际由该zone管理的页数量，不包括启动时分配的页
* spanned_pages: zone以Page为单位的长度，包括页间隙（zone_end_pfn - zone_start_pfn）
* present_pages: 该zone中实际存在的页数量，包括启动时分配的页
* name：zone的名字，字符串表示："DMA" | "Normal" | "Highmem"

#### page
物理内存的最小管理单位就是页`page`，在32bit机器上，页大小是4KB；在64bit机器上，页大小是8KB.
在内核中每一个物理页，由一个`struct page`结构描述

##### 数据结构
内核由`struct page`结构表示物理页，出于节省内存（该结构的量比较大）的目的，该结构中使用了大量`union`
```c

struct page {
	unsigned long flags;		/* Atomic flags, some possibly
					 * updated asynchronously */
	/*
	 * Five words (20/40 bytes) are available in this union.
	 * WARNING: bit 0 of the first word is used for PageTail(). That
	 * means the other users of this union MUST NOT use the bit to
	 * avoid collision and false-positive PageTail().
	 */
	union {
		struct {	/* Page cache and anonymous pages */
			/**
			 * @lru: Pageout list, eg. active_list protected by
			 * lruvec->lru_lock.  Sometimes used as a generic list
			 * by the page owner.
			 */
			union {
				struct list_head lru;
				/* Or, for the Unevictable "LRU list" slot */
				struct {
					/* Always even, to negate PageTail */
					void *__filler;
					/* Count page's or folio's mlocks */
					unsigned int mlock_count;
				};
			};
			/* See page-flags.h for PAGE_MAPPING_FLAGS */
			struct address_space *mapping;
			pgoff_t index;		/* Our offset within mapping. */
			/**
			 * @private: Mapping-private opaque data.
			 * Usually used for buffer_heads if PagePrivate.
			 * Used for swp_entry_t if PageSwapCache.
			 * Indicates order in the buddy system if PageBuddy.
			 */
			unsigned long private;
		};
		struct {	/* page_pool used by netstack */
			/**
			 * @pp_magic: magic value to avoid recycling non
			 * page_pool allocated pages.
			 */
			unsigned long pp_magic;
			struct page_pool *pp;
			unsigned long _pp_mapping_pad;
			unsigned long dma_addr;
			union {
				/**
				 * dma_addr_upper: might require a 64-bit
				 * value on 32-bit architectures.
				 */
				unsigned long dma_addr_upper;
				/**
				 * For frag page support, not supported in
				 * 32-bit architectures with 64-bit DMA.
				 */
				atomic_long_t pp_frag_count;
			};
		};
		struct {	/* Tail pages of compound page */
			unsigned long compound_head;	/* Bit zero is set */

			/* First tail page only */
			unsigned char compound_dtor;
			unsigned char compound_order;
			atomic_t compound_mapcount;
			atomic_t compound_pincount;
#ifdef CONFIG_64BIT
			unsigned int compound_nr; /* 1 << compound_order */
#endif
		};
		struct {	/* Second tail page of compound page */
			unsigned long _compound_pad_1;	/* compound_head */
			unsigned long _compound_pad_2;
			/* For both global and memcg */
			struct list_head deferred_list;
		};
		struct {	/* Page table pages */
			unsigned long _pt_pad_1;	/* compound_head */
			pgtable_t pmd_huge_pte; /* protected by page->ptl */
			unsigned long _pt_pad_2;	/* mapping */
			union {
				struct mm_struct *pt_mm; /* x86 pgds only */
				atomic_t pt_frag_refcount; /* powerpc */
			};
#if ALLOC_SPLIT_PTLOCKS
			spinlock_t *ptl;
#else
			spinlock_t ptl;
#endif
		};
		struct {	/* ZONE_DEVICE pages */
			/** @pgmap: Points to the hosting device page map. */
			struct dev_pagemap *pgmap;
			void *zone_device_data;
			/*
			 * ZONE_DEVICE private pages are counted as being
			 * mapped so the next 3 words hold the mapping, index,
			 * and private fields from the source anonymous or
			 * page cache page while the page is migrated to device
			 * private memory.
			 * ZONE_DEVICE MEMORY_DEVICE_FS_DAX pages also
			 * use the mapping, index, and private fields when
			 * pmem backed DAX files are mapped.
			 */
		};

		/** @rcu_head: You can use this to free a page by RCU. */
		struct rcu_head rcu_head;
	};

	union {		/* This union is 4 bytes in size. */
		/*
		 * If the page can be mapped to userspace, encodes the number
		 * of times this page is referenced by a page table.
		 */
		atomic_t _mapcount;

		/*
		 * If the page is neither PageSlab nor mappable to userspace,
		 * the value stored here may help determine what this page
		 * is used for.  See page-flags.h for a list of page types
		 * which are currently stored here.
		 */
		unsigned int page_type;
	};

	/* Usage count. *DO NOT USE DIRECTLY*. See page_ref.h */
	atomic_t _refcount;

#ifdef CONFIG_MEMCG
	unsigned long memcg_data;
#endif

	/*
	 * On machines where all RAM is mapped into kernel address space,
	 * we can simply calculate the virtual address. On machines with
	 * highmem some memory is mapped into kernel virtual memory
	 * dynamically, so we need a place to store that address.
	 * Note that this field could be 16 bits on x86 ... ;)
	 *
	 * Architectures with slow multiplication can define
	 * WANT_PAGE_VIRTUAL in asm/page.h
	 */
#if defined(WANT_PAGE_VIRTUAL)
	void *virtual;			/* Kernel virtual address (NULL if
					   not kmapped, ie. highmem) */
#endif /* WANT_PAGE_VIRTUAL */

#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
	int _last_cpupid;
#endif
} _struct_page_alignment;
```
* flags: 标识页的状态，例如当前页是否是`脏页`或者被锁，每一个bit标识一种状态，所以至少可以同时标识32种状态，定义在`include/linux/page-flags.h`
* _refcount：引用计数，标识内核中引用该page的次数，当该值为0时，标识没有引用该page的位置，可以解除映射，在内存回收中使用
* virtual：对于可以将物理内存映射到内核的地址，我们可以计算出虚拟地址；但是像HIGHMEM这种动态映射到内核虚拟地址的，需要一个字段保存其虚拟地址
* _mapcount: 如果该page可以被映射到用户态，标识该Page被page table引用的次数

#### summary
上述node、zone、page三种层级的关系可以如下理解
![](images\memory.png)

### Refer
[Linux内存管理一](https://www.cnblogs.com/linhaostudy/p/9986692.html#_label0_0)
