//
// Created by fuqiuluo on 25-2-3.
//

#ifndef zoe_SERVER_H
#define zoe_SERVER_H

#include <linux/completion.h>
#include <linux/bpf.h>
#include <linux/workqueue.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <net/sock.h>
#include "vma.h"

#define MAX_CACHE_KERNEL_ADDRESS_COUNT 16

#define REQ_GET_PROCESS_PID 658
#define REQ_IS_PROCESS_PID_ALIVE 659
#define REQ_ATTACH_PROCESS	660
#define REQ_GET_PROCESS_MODULE_BASE	661
#define REQ_READ_PROCESS_MEMORY_IOREMAP	662
#define REQ_WRITE_PROCESS_MEMORY_IOREMAP 663
#define REQ_ACCESS_PROCESS_VM	664
#define REQ_READ_PROCESS_MEMORY	665
#define REQ_WRITE_PROCESS_MEMORY 666
#define REMAP_MEMORY 667

#define CMD_TOUCH_CLICK_DOWN 1000
#define CMD_TOUCH_CLICK_UP 1001
#define CMD_TOUCH_MOVE 1006
#define CMD_COPY_PROCESS 1007
#define CMD_PROCESS_MALLOC 1008
#define CMD_HIDE_VMA 1009

struct req_access_process_vm {
	pid_t from;
	void __user* from_addr;
	pid_t to;
	void __user* to_addr;
	size_t size;
};

struct touch_event_base {
	int slot;
	int x;
	int y;
	int pressure;
};

struct copy_process_args {
	void* fn;
	void* arg;
};

struct hide_vma_args {
	unsigned long ptr;
	enum hide_mode: int {
		HIDE_X =	0,
		HIDE_NAME = 1, // TODO
		HIDE_ADDR = 2, // TODO
	} mode;
};

// Note:an zoe_sock can only be mmap once
struct zoe_sock {
	pid_t pid;

	atomic_t remap_in_progress;
	unsigned long pfn;

	unsigned long cached_kernel_pages[MAX_CACHE_KERNEL_ADDRESS_COUNT];
	size_t cached_count;
};

int init_server(void);

void exit_server(void);

#endif //zoe_SERVER_H
