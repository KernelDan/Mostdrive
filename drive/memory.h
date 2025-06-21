//
// Created by fuqiuluo on 25-1-22.
//

#ifndef zoe_MEMORY_H
#define zoe_MEMORY_H

#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 11, 0)
#include <linux/sched/mm.h>
#include <linux/sched/task.h>
#endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0))
#include <linux/mmap_lock.h>
#define MM_READ_LOCK(mm) mmap_read_lock(mm);
#define MM_READ_UNLOCK(mm) mmap_read_unlock(mm);
#else
#include <linux/rwsem.h>
#define MM_READ_LOCK(mm) down_read(&(mm)->mmap_sem);
#define MM_READ_UNLOCK(mm) up_read(&(mm)->mmap_sem);
#endif

#include "mmuhack.h"
#include "kkit.h"

#ifdef CONFIG_CMA
//#warning CMA is enabled!
#endif

#if !defined(ARCH_HAS_VALID_PHYS_ADDR_RANGE) || defined(MODULE)
static inline int memk_valid_phys_addr_range(phys_addr_t addr, size_t size)
{
	return addr + size <= __pa(high_memory);
}
#define IS_VALID_PHYS_ADDR_RANGE(x,y) memk_valid_phys_addr_range(x,y)
#else
#define IS_VALID_PHYS_ADDR_RANGE(x,y) valid_phys_addr_range(x,y)
#endif

#if !defined(min)
#define min(x, y) ({        \
typeof(x) _min1 = (x);  \
typeof(y) _min2 = (y);  \
(void) (&_min1 == &_min2); /* 类型检查 */ \
_min1 < _min2 ? _min1 : _min2; })
#endif

uintptr_t get_module_base(pid_t pid, char *name, int vm_flag);
uintptr_t get_module_base_bss(pid_t pid, char *name, int vm_flag);

phys_addr_t vaddr_to_phy_addr(struct mm_struct *mm, uintptr_t va);

int read_process_memory_ioremap(pid_t pid, void __user* addr, void __user* dest, size_t size);
int write_process_memory_ioremap(pid_t pid, void __user* addr, void __user* src, size_t size);

int read_process_memory(pid_t pid, void __user* addr, void __user* dest, size_t size);
int write_process_memory(pid_t pid, void __user* addr, void __user* src, size_t size);

int access_process_vm_by_pid(pid_t from, void __user* from_addr, pid_t to, void __user* to_addr, size_t size);

#endif //zoe_MEMORY_H
