LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := seccomp_example
LOCAL_SRC_FILES := test.cpp

include $(BUILD_EXECUTABLE)
