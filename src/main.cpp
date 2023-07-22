#include <stdio.h>
#include <inttypes.h>

#include "aarch64hook.hpp"
#include "utils.hpp"
#include "hooks.hpp"
#include "libc-hooks.hpp"
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

FILE* (*fopen_o)(char*, char*) = NULL;
FILE* fopen_hk(char* fname, char* mode) 
{
	print_ret();
	
	auto ret = fopen_o(fname, mode);
	LOGV("fopen(%s, %s) -> %p", fname, mode, ret);
	
	return ret;
}

int (*prctl_o)(int, unsigned long, unsigned long, unsigned long, unsigned long) = NULL;
int prctl_hk(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) 
{
	print_ret();
	
	if (!is_decrypted) 
	{
		if (libshield_base == 0) 
		{
			dl_iterate_phdr(get_shield_base, NULL);
			LOGV("** Image Base ** : %lx", libshield_base);
		}
		
		if (libshield_base != 0) 
		{
			if(!memcmp((void*)((uint64_t) libshield_base + OPENAT_SYSCALL_OFFSET), "\x08\x07\x80\xd2", 4))
			{
				LOGV("** libshield is decrypted **");
				
				A64HookFunction((void*)((uint64_t) libshield_base + OPENAT_SYSCALL_OFFSET), (void*) openat_hk, (void**) &openat_o);
				is_decrypted = true;
			}
		}
	}
	
	auto ret = prctl_o(option, arg2, arg3, arg4, arg5);
	LOGV("prctl(%d, %ld, %ld, %ld, %ld) -> %d", option, arg2, arg3, arg4, arg5, ret);
	
	return ret;
}

__attribute__((constructor)) 
static void lib_init(void) 
{	
	A64HookFunction((void*)dlsym(RTLD_NEXT, "prctl"), (void*) prctl_hk, (void**) &prctl_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "fopen"), (void*) fopen_hk, (void**) &fopen_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "dlopen"), (void*) dlopen_hk, (void**) &dlopen_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "pthread_create"), (void*) pthread_create_hk, (void**) &pthread_create_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "access"), (void*) access_hk, (void**) &access_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "fork"), (void*) fork_hk, (void**) &fork_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "getxattr"), (void*) getxattr_hk, (void**) &getxattr_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "getauxval"), (void*) getauxval_hk, (void**) &getauxval_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "strpbrk"), (void*) strpbrk_hk, (void**) &strpbrk_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "tgkill"), (void*) tgkill_hk, (void**) &tgkill_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "killpg"), (void*) killpg_hk, (void**) &killpg_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "exit"), (void*) exit_hk, (void**) &exit_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "dladdr"), (void*) dladdr_hk, (void**) &dladdr_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "fread"), (void*) fread_hk, (void**) &fread_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "fwrite"), (void*) fwrite_hk, (void**) &fwrite_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "__system_property_get"), (void*) propget_hk, (void**) &propget_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "inotify_add_watch"), (void*) notify_hk, (void**) &notify_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "raise"), (void*) raise_hk, (void**) &raise_o);
	A64HookFunction((void*)dlsym(RTLD_NEXT, "dl_iterate_phdr"), (void*) iter_hk, (void**) &iter_o);

	A64HookFunction((void*)dlsym(RTLD_NEXT, "dlsym"), (void*) dlsym_hk, (void**) &dlsym_o);
}
