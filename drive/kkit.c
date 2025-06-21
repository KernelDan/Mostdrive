#include <linux/kprobes.h>
#include "kkit.h"

int zoe_flip_open(const char *filename, int flags, umode_t mode, struct file **f) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    *f = filp_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#else
    static struct file* (*reserve_flip_open)(const char *filename, int flags, umode_t mode) = NULL;

    if (reserve_flip_open == NULL) {
        reserve_flip_open = (struct file* (*)(const char *filename, int flags, umode_t mode))zoe_kallsyms_lookup_name("filp_open");
        if (reserve_flip_open == NULL) {
            return -1;
        }
    }

    *f = reserve_flip_open(filename, flags, mode);
    return *f == NULL ? -2 : 0;
#endif
}

int zoe_flip_close(struct file **f, fl_owner_t id) {
#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0))
    filp_close(*f, id);
    return 0;
#else
    static struct file* (*reserve_flip_close)(struct file **f, fl_owner_t id) = NULL;

    if (reserve_flip_close == NULL) {
        reserve_flip_close = (struct file* (*)(struct file **f, fl_owner_t id))zoe_kallsyms_lookup_name("filp_close");
        if (reserve_flip_close == NULL) {
            return -1;
        }
    }

    reserve_flip_close(f, id);
    return 0;
#endif
}

bool is_file_exist(const char *filename) {
    struct file* fp;

    if(zoe_flip_open(filename, O_RDONLY, 0, &fp) == 0) {
        if (!IS_ERR(fp)) {
            zoe_flip_close(&fp, NULL);
            return true;
        }
        return false;
    }

    return false;
}

unsigned long zoe_kallsyms_lookup_name(const char *symbol_name) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
    typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);

    static kallsyms_lookup_name_t lookup_name = NULL;
    if (lookup_name == NULL) {
        struct kprobe kp = {
                .symbol_name = "kallsyms_lookup_name"
        };

        if(register_kprobe(&kp) < 0) {
            return 0;
        }

        lookup_name = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
    }
    return lookup_name(symbol_name);
#else
    return kallsyms_lookup_name(symbol_name);
#endif
}

unsigned long *zoe_find_syscall_table(void) {
    unsigned long *syscall_table;
    syscall_table = (unsigned long*)zoe_kallsyms_lookup_name("sys_call_table");
    return syscall_table;
}

int mark_pid_root(pid_t pid) {
    static struct cred* (*my_prepare_creds)(void) = NULL;

    struct pid * pid_struct;
    struct task_struct *task;
    kuid_t kuid;
    kgid_t kgid;
    struct cred *new_cred;

    kuid = KUIDT_INIT(0);
    kgid = KGIDT_INIT(0);

    pid_struct = find_get_pid(pid);

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (task == NULL){
        printk(KERN_ERR "[zoe] Failed to get current task info.\n");
        return -1;
    }

    if (my_prepare_creds == NULL) {
        my_prepare_creds = (void *) zoe_kallsyms_lookup_name("prepare_creds");
        if (my_prepare_creds == NULL) {
            printk(KERN_ERR "[zoe] Failed to find prepare_creds\n");
            return -1;
        }
    }

    new_cred = my_prepare_creds();
    if (new_cred == NULL) {
        printk(KERN_ERR "[zoe] Failed to prepare new credentials\n");
        return -ENOMEM;
    }
    new_cred->uid = kuid;
    new_cred->gid = kgid;
    new_cred->euid = kuid;
    new_cred->egid = kgid;
    
    rcu_assign_pointer(task->cred, new_cred);
    return 0;
}

int is_pid_alive(pid_t pid) {
    struct pid * pid_struct;
    struct task_struct *task;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return false;

    task = pid_task(pid_struct, PIDTYPE_PID);
    if (!task)
        return false;

    return pid_alive(task);
}

static int (*my_get_cmdline)(struct task_struct *task, char *buffer, int buflen) = NULL;

static void foreach_process(void (*callback)(struct zoe_task_struct *)) {
    struct task_struct *task;
    struct zoe_task_struct zoe_task;
    int ret = 0;

    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void *) zoe_kallsyms_lookup_name("get_cmdline");
    }

    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        zoe_task = (struct zoe_task_struct) {
                .task = task,
                .cmdline_len = 0
        };

        memset(zoe_task.cmdline, 0, 256);
        if (my_get_cmdline != NULL) {
            ret = my_get_cmdline(task, zoe_task.cmdline, 256);
            if (ret < 0) {
                continue;
            }
            zoe_task.cmdline_len = ret;
        }

        callback(&zoe_task);
    }
    rcu_read_unlock();
}

pid_t find_process_by_name(const char *name) {
    struct task_struct *task;
    char cmdline[256];
	size_t name_len;
    int ret;

	name_len = strlen(name);
	if (name_len == 0) {
		pr_err("[zoe] process name is empty\n");
		return -2;
	}

    if (my_get_cmdline == NULL) {
        my_get_cmdline = (void *) zoe_kallsyms_lookup_name("get_cmdline");
		// It can be NULL, because there is a fix below if get_cmdline is NULL
    }

	// code from https://github.com/torvalds/linux/blob/master/kernel/sched/debug.c#L797
    rcu_read_lock();
    for_each_process(task) {
        if (task->mm == NULL) {
            continue;
        }

        cmdline[0] = '\0';
        if (my_get_cmdline != NULL) {
            ret = my_get_cmdline(task, cmdline, sizeof(cmdline));
        } else {
            ret = -1;
        }

        if (ret < 0) {
            pr_warn("[zoe] Failed to get cmdline for pid %d\n", task->pid);
            if (strncmp(task->comm, name, min(strlen(task->comm), name_len)) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        } else {
            if (strncmp(cmdline, name, min(name_len, strlen(cmdline))) == 0) {
                rcu_read_unlock();
                return task->pid;
            }
        }
    }

    rcu_read_unlock();
    return 0;
}

#if INJECT_SYSCALLS == 1
int hide_process(pid_t pid) {
    return 0;
}
#endif
