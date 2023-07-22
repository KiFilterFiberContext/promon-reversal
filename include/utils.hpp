#pragma once

#include <dlfcn.h>
#include <link.h>
#include <string.h>
#include <android/log.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <jni.h>
#include <string>

#define GETRET(n) uint64_t retaddr##n = (uint64_t) (__builtin_extract_return_addr(__builtin_return_address (n)))
#define LOGV(...) __android_log_print(ANDROID_LOG_INFO, "brawlpatcher", __VA_ARGS__)

#define __intval(p)                reinterpret_cast<intptr_t>(p)
#define __uintval(p)               reinterpret_cast<uintptr_t>(p)
#define __ptr(p)                   reinterpret_cast<void *>(p)
#define __page_size                4096
#define __page_align(n)            __align_up(static_cast<uintptr_t>(n), __page_size)
#define __ptr_align(x)             __ptr(__align_down(reinterpret_cast<uintptr_t>(x), __page_size))
#define __align_up(x, n)           (((x) + ((n) - 1)) & ~((n) - 1))
#define __align_down(x, n)         ((x) & -(n))
#define __countof(x)               static_cast<intptr_t>(sizeof(x) / sizeof((x)[0])) // must be signed
#define __atomic_increase(p)       __sync_add_and_fetch(p, 1)
#define __sync_cmpswap(p, v, n)    __sync_bool_compare_and_swap(p, v, n)
#define __predict_true(exp)        __builtin_expect((exp) != 0, 1)
#define __flush_cache(c, n)        __builtin___clear_cache(reinterpret_cast<char *>(c), reinterpret_cast<char *>(c) + n)
#define __make_rwx(p, n)           ::mprotect(__ptr_align(p), \
                                              __page_align(__uintval(p) + n) != __page_align(__uintval(p)) ? __page_align(n) + __page_size : __page_align(n), \
                                              PROT_READ | PROT_WRITE | PROT_EXEC)
#define __remove_rwx(p, n)           ::mprotect(__ptr_align(p), \
                                              __page_align(__uintval(p) + n) != __page_align(__uintval(p)) ? __page_align(n) + __page_size : __page_align(n), \
                                              PROT_READ | PROT_EXEC)
										

static volatile uint64_t libshield_base = 0x0;

static volatile bool is_decrypted = false;
static volatile bool has_loaded = false;										
											  
#if defined(VERSION_50_201)
// libshield offsets
constexpr const char* SHIELD_NAME = "hpbjopkogddk";
constexpr uint64_t OPENAT_SYSCALL_OFFSET = 0x4522f4;

#elif defined(VERSION_50_221)
constexpr const char* SHIELD_NAME = "niiblkgocjbb";
constexpr uint64_t OPENAT_SYSCALL_OFFSET = 0x43c708;

#endif

inline __attribute__((always_inline)) 
void print_ret(bool print_extra = false) 
{
	GETRET(0);
	__android_log_print(ANDROID_LOG_INFO, "patcher", "\nReturn PC at level 0: %lx\n", retaddr0);
	
	GETRET(1);
	__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 1: %lx\n", retaddr1);
	
	if (print_extra) 
	{
		GETRET(2);
		__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 2: %lx\n", retaddr2);

#if EXTEND_CALL_STACK
		GETRET(3);
		__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 3: %lx\n", retaddr3);
		
		GETRET(4);
		__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 4: %lx\n", retaddr4);
		
		GETRET(5);
		__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 5: %lx\n", retaddr5);
		
		GETRET(6);
		__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 6: %lx\n", retaddr6);
		
		GETRET(7);
		__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 7: %lx\n", retaddr7);
		
		GETRET(8);
		__android_log_print(ANDROID_LOG_INFO, "patcher", "Return PC at level 7: %lx\n", retaddr8);
#endif
	}
}

void* unpatcher(void* arg)
{
	usleep(100000);
	
	// to bypass signature check for libshield we revert the syscall stub hook 
	__make_rwx((void*)((uint64_t) libshield_base + OPENAT_SYSCALL_OFFSET), 64);
	memcpy((void*)((uint64_t) libshield_base + OPENAT_SYSCALL_OFFSET), "\x08\x07\x80\xd2\x01\x00\x00\xd4", 8);
	__remove_rwx((void*)((uint64_t) libshield_base + OPENAT_SYSCALL_OFFSET), 64);
	__flush_cache((void*)((uint64_t) libshield_base + OPENAT_SYSCALL_OFFSET), 64);

	LOGV("** Unpatched bin **");
	
	return NULL;
}

int get_shield_base(struct dl_phdr_info *info, size_t size, void *data) 
{
	if (strstr(info->dlpi_name, SHIELD_NAME) != NULL)
		libshield_base = (uint64_t) info->dlpi_addr;
	
	return 0;
}
