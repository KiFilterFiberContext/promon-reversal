LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := shieldpatcher
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include/ 

LOCAL_SRC_FILES := $(LOCAL_PATH)/src/aarch64hook.cpp $(LOCAL_PATH)/src/main.cpp 
LOCAL_LDLIBS := -llog 

include $(BUILD_SHARED_LIBRARY)