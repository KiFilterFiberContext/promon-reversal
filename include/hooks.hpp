#pragma once
#include "utils.hpp"

int (*sigaction_o)(int, struct sigaction*, struct sigaction*) = NULL;
int sigaction_hk(int sig, struct sigaction* act, struct sigaction* oldact) 
{
	print_ret();
	
	auto ret = sigaction(sig, act, oldact);
	LOGV("sigaction(%d, %p | %p, %p) -> %d", sig, act->sa_handler, act->sa_sigaction, oldact, ret);
	
	return ret;
}

ssize_t (*read_o)(int, void*, size_t) = NULL;
ssize_t read_hk(int fd, void* buf, size_t count)
{
	print_ret();
	
	ssize_t ret = read_o(fd, buf, count);
	LOGV("read(%d, %lx, %d) -> %d", fd, (uint64_t) buf, count, ret);

	return ret;
}

int (*close_o)(int) = NULL;
int close_hk(int fd)
{
	print_ret();

	int ret = close_o(fd);
	LOGV("close(%d) -> %d", fd, ret);

	return ret;
}

long (*ptrace_o)(int, pid_t, void*, void*) = NULL;
long ptrace_hk(int request, pid_t pid, void* addr, void* data)
{
	print_ret();
	
	auto ret = ptrace_o(request, pid, addr, data);
	LOGV("ptrace(%d, %d, %p, %p) -> %d", request, pid, addr, data, ret);

	return ret;
}

ssize_t (*write_o)(int, void*, size_t) = NULL;
ssize_t write_hk(int fd, void* buf, size_t count)
{
	print_ret();
	
	auto ret = write_o(fd, buf, count);
	LOGV("write(%d, %p, %d) -> %d", fd, buf, count, ret);
	
	return ret;
}

pid_t (*getpid_o)() = NULL;
pid_t getpid_hk()
{
	print_ret();
	
	auto ret = getpid_o();
	LOGV("getpid() -> %d", ret);
	
	return ret;
}

int (*execve_o)(char*, char**, char**) = NULL;
int execve_hk(char* pathname, char** argv, char** envp) 
{
	print_ret();
	
	auto ret = execve_o(pathname, argv, envp);
	LOGV("execve(%s, %s, %s) -> %d", pathname, argv[0], envp[0], ret);
	
	return ret;
}

int (*kill_o)(pid_t, int) = NULL;
int kill_hk(pid_t pid, int sig) 
{
	print_ret();
	LOGV("kill(%d, %d)", pid, sig);
	
	return kill(pid, sig);
}

void (*exit_group_o)(int) = NULL;
void exit_group_hk(int status) 
{
	print_ret();
	LOGV("exit_group(%d)", status);
	
	return exit_group_o(status);
}

int (*openat_o)(int, char*, int, mode_t) = NULL;
int openat_hk(int dirfd, char *pathname, int flags, mode_t mode) 
{
	print_ret();
	int ret = -1;
	
	if (strstr(pathname, "base.apk")) 
	{
		char temppath[100];
		char newpath[100];
	
		// replace modified APK with original APK 
		strncpy(temppath, pathname, strlen(pathname) - 9);
		sprintf(newpath, "%s/backup.apk", temppath);
		
		LOGV("Replaced %s with %s", pathname, newpath);
		ret = openat_o(dirfd, newpath, flags, mode);	
		
		LOGV("openat(%d, %s (%d), %d, %d) -> %d", dirfd, newpath, strlen(pathname), flags, mode, ret);
		
		pthread_t thid;
		pthread_create(&thid, NULL, unpatcher, NULL);
	}
	else 
	{
		ret = openat_o(dirfd, pathname, flags, mode);	
		LOGV("openat(%d, %s (%d), %d, %d) -> %d", dirfd, pathname, strlen(pathname), flags, mode, ret);
	}
	
	return ret;
}