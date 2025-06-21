MODULE = 阿念Most

obj-m :=$(MODULE).o
$(MODULE)-objs += core.o
$(MODULE)-objs += mmuhack.o
$(MODULE)-objs += kkit.o
$(MODULE)-objs += peekaboo.o
$(MODULE)-objs += memory.o
$(MODULE)-objs += server.o
$(MODULE)-objs += touch.o
$(MODULE)-objs += vma.o
$(MODULE)-objs += addr_pfn_map.o

EXTRA_CFLAGS += -DHIDE_SELF_MODULE=0	# 是否在模块表中移除自己
EXTRA_CFLAGS += -DBUILD_REMAP=1	# 是否编译内存重映射API（不稳定）
EXTRA_CFLAGS += -DENABLE_REMAP2=0 # 是否使用新的REMAP接口（vmf_insert_pfn）
EXTRA_CFLAGS += -DINJECT_SYSCALLS=0	# 是否注入SYSCALL开启更多功能
EXTRA_CFLAGS += -DBIG_PAGE

EXTRA_CFLAGS += -O2                # 优化等级2
EXTRA_CFLAGS += -fvisibility=hidden  # 隐藏符号
EXTRA_CFLAGS += -fomit-frame-pointer # 省略帧指针
# EXTRA_CFLAGS += -g0 去除调试信息
EXTRA_CFLAGS += -fno-pic -fvisibility=hidden
EXTRA_CFLAGS += -fno-stack-protector

# ARM架构优化
EXTRA_CFLAGS += -march=armv8-a     # 适用于ARMv8架构
EXTRA_CFLAGS += -mtune=cortex-a53  # 针对Cortex-A53优化
#EXTRA_CFLAGS += -mfpu=neon-fp-armv8  # 使用NEON和VFP单元
#EXTRA_CFLAGS += -mfloat-abi=hard   # 硬件浮点

all:
	make -C $(KDIR) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean