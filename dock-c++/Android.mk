LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := Test-Most读取测试

LOCAL_CFLAGS := -fvisibility=hidden -w
LOCAL_CPPFLAGS := -std=c++17
LOCAL_CPPFLAGS += -fvisibility=hidden

LOCAL_SRC_FILES := main.cpp
LOCAL_SRC_FILES += Most-Kernel.cpp

LOCAL_LDLIBS := -llog -landroid
include $(BUILD_EXECUTABLE)
