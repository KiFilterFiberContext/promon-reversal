#pragma once
#include "utils.hpp"

int (*dladdr_o)(const void*, Dl_info*) = NULL;
int dladdr_hk(const void* addr, Dl_info* info) 
{	
	auto ret = dladdr_o(addr, info);
	LOGV("dladdr(%p, %s) -> %d", addr, info->dli_fname, ret);
	
	return ret;
}

size_t (*fread_o)(void*, size_t, size_t, FILE*) = NULL;
size_t fread_hk(void* ptr, size_t size, size_t n, FILE* f)
{
	print_ret();
	
	auto ret = fread_o(ptr, size, n, f);
	LOGV("fread(%p, %d, %d, %p) -> %d", ptr, size, n, f, ret);
	
	return ret;
}
	   
size_t (*fwrite_o)(void*, size_t, size_t, FILE*) = NULL;
size_t fwrite_hk(void* ptr, size_t size, size_t n, FILE* s) 
{
	print_ret();
	
	auto ret = fwrite_o(ptr, size, n, s);
	LOGV("fwrite(%p, %d, %d, %p) -> %d", ptr, size, n, s, ret);
	
	return ret;
}

ssize_t (*sendto_o)(int, void*, size_t, int, const struct sockaddr*, uint32_t) = NULL;
ssize_t sendto_hk(int fd, void* buf, size_t n, int flags, const struct sockaddr* addr, uint32_t addr_len)
{
	print_ret(true);
	
	auto ret = sendto_o(fd, buf, n, flags, addr, addr_len);
	LOGV("sendto(%d, %p, %d, %d, %p, %d) -> %d", fd, buf, n, flags, addr, addr_len, ret);
	hexdump("send", buf, n);
	
	return ret;
}

int (*socket_o)(int, int, int) = NULL;
int socket_hk(int domain, int type, int proto)
{
	print_ret(true);
	auto ret = socket_o(domain, type, proto);
	
	LOGV("socket(%d, %d, %d) -> %d", domain, type, proto, ret);
	return ret;
}

ssize_t (*recvfrom_o)(int, void*, size_t, int, const struct sockaddr*, uint32_t) = NULL;
ssize_t recvfrom_hk(int fd, void* buf, size_t n, int flags, const struct sockaddr* addr, uint32_t addr_len)
{
	print_ret(true);
	
	auto ret = recvfrom_o(fd, buf, n, flags, addr, addr_len);
	LOGV("recvfrom(%d, %p, %d, %d, %p, %d) -> %d", fd, buf, n, flags, addr, addr_len, ret);
	hexdump("recv", buf, n);
	
	return ret;
}

int (*propget_o)(const char*, char*) = NULL;
int propget_hk(const char* name, char* val) 
{
	print_ret();
	
	if (has_loaded && strstr(name, "ro.kernel.qemu") != NULL)
	{
		LOGV("Stopping propget checks");
		while (true)
			;;
	}
	
	auto ret = propget_o(name, val);
	LOGV("propget(%s, ...) -> %d", name, ret);
	
	return ret;
}


pid_t (*fork_o)(void) = NULL;
pid_t fork_hk(void) 
{
	print_ret();
	
	auto ret = fork_o();
	LOGV("fork() -> %d", ret);
	
	return ret;
}

ssize_t (*getxattr_o)(char*, char*, void*, size_t) = NULL;
ssize_t getxattr_hk(char* path, char* name, void* val, size_t size) 
{
	print_ret();
	
	auto ret = getxattr_o(path, name, val, size);
	LOGV("getxattr(%s, %s, %p, %d) -> %d", path, name, val, size, ret);
	
	return ret;
}

unsigned long (*getauxval_o)(unsigned long) = NULL;
unsigned long getauxval_hk(unsigned long type) 
{
	print_ret();
	
	auto ret = getauxval_o(type);
	LOGV("getauxval(%ld) -> %d", type, ret);
	
	return ret;
}

char* (*strpbrk_o)(const char*, const char*) = NULL;
char* strpbrk_hk(const char* s, const char* accept) 
{
	print_ret();
	
	auto ret = strpbrk_o(s, accept);
	LOGV("strpbrk(%s, %s) -> %s", s, accept, ret);
	
	return ret;
}

int (*tgkill_o)(int, int, int) = NULL;
int tgkill_hk(int tgid, int tid, int sig) 
{
	print_ret(true);
	
	auto ret = tgkill_o(tgid, tid, sig);
	LOGV("tgkill(%d, %d, %d) -> %d", tgid, tid, sig, ret);
	
	return ret;
}

int (*killpg_o)(int, int) = NULL;
int killpg_hk(int pgrp, int sig) 
{
	print_ret();
	
	auto ret = killpg_o(pgrp, sig);
	LOGV("killpg(%d, %d) -> %d", pgrp, sig, ret);
	
	return ret;
}

void (*exit_o)(int) = NULL;
void exit_hk(int status)
{
	print_ret();
	LOGV("exit(%d)", status);

	return exit_o(status);
}

int (*access_o)(char*, int) = NULL;
int access_hk(char* fname, int mode) 
{
	print_ret();
	
	if (has_loaded && (strstr(fname, "/su") != NULL || strstr(fname, "supersu") != NULL))
	{
		LOGV("Stopping access checks");
		while(true) 
			;;
	}
	
	auto ret = access_o(fname, mode);
	LOGV("access(%s, %d) -> %d", fname, mode, ret);

	return ret;
}


int (*pthread_create_o)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*) = NULL;
int pthread_create_hk(pthread_t* th, const pthread_attr_t* attr, void* (*start_rt)(void*), void* arg) 
{
	print_ret();
	
	// suspend all threads from promon shield anticheat to prevent checks
	if (has_loaded)
	{
		GETRET(0);
		
		Dl_info dl_info;
		dladdr((void*) retaddr0, &dl_info);
		
		if (strstr(dl_info.dli_fname, SHIELD_NAME)) 
		{
			LOGV("Stopping pthread_create checks");
			while (true) 
				;;
		}
	}
	
	auto ret = pthread_create_o(th, attr, start_rt, arg);
	LOGV("pthread_create(%p, %p, %p, %p) -> %d", th, attr, start_rt, arg, ret);
		
	return ret;
}

void* (*dlopen_o)(char*, int) = NULL;
void* dlopen_hk(char* fname, int flags) 
{
	print_ret();
	
	if (has_loaded && strstr(fname, "libFridaGadget") != NULL)
	{
		LOGV("Stopping hooking checks");
		while(true) 
			;;
	}
	
	auto ret = dlopen_o(fname, flags);
	LOGV("dlopen(%s, %d) -> %p", fname, flags, ret);
	
	return ret;
}

void* (*dlsym_o)(void*, const char*) = NULL;
void* dlsym_hk(void* handle, const char* sym) 
{
	print_ret();
	
	if (has_loaded && strstr(sym, "_ZN3art6mirror9ArtMethod16EnableXposedHookEP7_JNIEnvP8_jobject") != NULL)
	{
		LOGV("Stopping hooking 2 checks");
		while(true) 
			;;
	}
	
	auto ret = dlsym_o(handle, sym);
	LOGV("dlsym(%lx, %s) -> %lx", (uint64_t) handle, sym, (uint64_t) ret);
	
	return ret;
}

int (*notify_o)(int, const char*, uint32_t) = NULL;
int notify_hk(int fd, const char* pathname, uint32_t mask)
{
	print_ret();
	
	auto ret = notify_o(fd, pathname, mask);
	LOGV("inotify_add_watch(%d, %s, %d) -> %d", fd, pathname, mask, ret);
	
	return ret;
}

int (*raise_o)(int) = NULL;
int raise_hk(int sig) 
{
	print_ret(true);
	
	LOGV("raise(%d)", sig);
	return raise_o(sig);
}

int (*iter_o)(void*, void*) = NULL;
int iter_hk(void* cb, void* data) 
{
	print_ret();
	
	LOGV("dl_iterate_phdr(%p, %p)", cb, data);
	return iter_o(cb, data);
}