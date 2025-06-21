#include "Most-Kernel.h"
#include <iostream>
#include <sys/mman.h>

static hak::driver driver;

int main() {
	auto pid = driver.get_process_pid("com.tencent.mobileqq");
	if (pid == 0) {
		std::cerr << "请先启动QQ: errno = " << errno << std::endl;
		return -1;
	} else {
		std::cout << "QQ进程PID: " << pid << std::endl;
	}
	auto alive = driver.is_process_alive_pid(pid);
	if (alive) {
		std::cout << "QQ进程存活\n";
	} else {
		std::cerr << "QQ进程已退出: errno = " << errno << std::endl;
		return -1;
	}

	if (driver.attach_process_pid(pid) < 0) {
		std::cerr << "附加进程失败: errno = " << errno << std::endl;
		return -1;
	} else {
		std::cout << "附加进程成功\n";
	}

	auto base = driver.get_process_module_base("libzplan_service.so", VM_EXEC);
	if (base == 0) {
		std::cerr << "获取模块基址失败: errno = " << errno << std::endl;
		return -1;
	} else {
		std::cout << "libzplan_service.so基址: " << std::hex << base << std::endl;
	}

	driver.attach_process_pid(getpid()); // detach from process

	{
		auto *a = new int(1008611);
		auto *b = new int(1001011);

		driver.read_process_memory_ioremap((uintptr_t) a, b, sizeof(int));
		assert(*b == 1008611);
		*b = 114514;
		driver.write_process_memory_ioremap((uintptr_t) a, b, sizeof(int));
		assert(*a == 114514);

		delete a;
		delete b;
	}

	{
		auto *a = new int(1008611);
		auto *b = new int(1001011);

		driver.access_process_vm(getpid(), (uintptr_t) a, getpid(), (uintptr_t) b, sizeof(int));
		assert(*b == 1008611);
		*b = 114514;
		driver.access_process_vm(getpid(), (uintptr_t) b, getpid(), (uintptr_t) a, sizeof(int));
		assert(*a == 114514);

		delete a;
		delete b;
	}

	{
		auto *a = new int(1008611);
		auto *b = new int(1001011);
		auto start = std::chrono::high_resolution_clock::now();
		for (int i = 0; i < 100000; ++i) {
			*a = 1008611;
			driver.read_process_memory_ioremap((uintptr_t) a, b, sizeof(int));
			assert(*b == 1008611);
			*b = 114514;
			driver.write_process_memory_ioremap((uintptr_t) a, b, sizeof(int));
			assert(*a == 114514);
		}
		auto end = std::chrono::high_resolution_clock::now();
		std::cout << std::dec << "read_process_memory_ioremap Time: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
				  << "ms\n";
		delete a;
		delete b;
	}

	{
		int *a = (int*) new int(1008611);
		auto start = std::chrono::high_resolution_clock::now();
		int* b = nullptr;
		if(driver.remap_memory((uintptr_t) a, 4, (void**) &b)) {
			std::cerr << "remap_memory failed: " << strerror(errno) << std::endl;
			return -1;
		}
		for (int i = 0; i < 100000000; ++i) {
			*a = i;
			assert(*b == i);
			*b = i+999;
			assert(*a == i + 999);
		}
		std::cout << "a = " << *a << ", b = " << *b << std::endl;
		auto end = std::chrono::high_resolution_clock::now();
		std::cout << "remap_memory Time: " << std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count() << "ms\n";
		munmap(a, 0x1000);
	}
	return 0;
}