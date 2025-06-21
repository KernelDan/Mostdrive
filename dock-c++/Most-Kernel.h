#ifndef HAKUTAKU_H
#define HAKUTAKU_H

#include <sys/uio.h>
#include <filesystem>
#include <dirent.h>
#include <string>
#include <vector>
#include <list>
#include <assert.h>

#define VM_READ		0x00000001
#define VM_WRITE	0x00000002
#define VM_EXEC		0x00000004
#define VM_SHARED	0x00000008

namespace hak {
    struct proc_stat {
        pid_t pid;
        std::string comm;
        char state;
        pid_t ppid;
    };

    auto get_process_list() -> std::vector<proc_stat>;
    auto get_pid_list() -> std::vector<pid_t>;
    auto find_process(std::string_view package) -> pid_t;
    auto get_module_base(pid_t pid, std::string_view module) -> uintptr_t;

    enum DRIVER_FUNCTION_REQUEST: int {
        GET_PROCESS_PID = 658
        IS_PROCESS_ALIVE_PID = 659,
        ATTACH_PROCESS = 660,
        GET_PROCESS_MODULE_BASE = 661,
        READ_PROCESS_MEMORY_IOREMAP = 662,
        WRITE_PROCESS_MEMORY_IOREMAP = 663,
        ACCESS_PROCESS_VM = 664,
        READ_PROCESS_MEMORY = 665,
        WRITE_PROCESS_MEMORY = 666,
        REMAP_MEMORY = 667,
    };

    class driver {
    public:
        bool verbose;

        driver();

        ~driver();

        bool active() const;

        bool is_verbose() const;

        pid_t get_process_pid(std::string_view package);

        bool is_process_alive_pid(pid_t pid) const;

        int access_process_vm(pid_t from, uintptr_t from_addr, pid_t to, uintptr_t to_addr, size_t len);

        int attach_process_pid(pid_t pid) const;

        uintptr_t get_process_module_base(const std::string &module, int vm_flag) const;

        size_t read_process_memory_ioremap(uintptr_t addr, void* buffer, size_t size) const;
        size_t write_process_memory_ioremap(uintptr_t addr, void* buffer, size_t size) const;

        size_t read_process_memory(uintptr_t addr, void* buffer, size_t size) const;
        size_t write_process_memory(uintptr_t addr, void* buffer, size_t size) const;

        int remap_memory(uintptr_t addr, size_t size, void** buffer) const;
    public:

    private:
        int sock;

        static auto find_driver_id() -> int;
    };
}

#endif