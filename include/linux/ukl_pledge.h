/* SPDX-License-Identifier: GPL-2.0 */
/*
 * UKL Pledge - Security sandboxing for Unikernel Linux
 *
 * Inspired by OpenBSD pledge(2) and the Nanos unikernel implementation.
 * Allows UKL applications to restrict their own capabilities after
 * initialization, providing defense-in-depth for Ring 0 applications.
 *
 * The pledge bits are designed to be compatible with OpenBSD/Nanos for
 * portability, with reserved space for Linux-specific extensions.
 */
#ifndef _LINUX_UKL_PLEDGE_H
#define _LINUX_UKL_PLEDGE_H

#include <linux/types.h>

/*
 * Core pledge promises (compatible with OpenBSD/Nanos)
 * Each bit grants access to a category of system calls.
 */

/* Basic I/O: read, write, close, dup, pipe, poll, select, etc. */
#define UKL_PLEDGE_STDIO        (1ULL << 0)

/* Filesystem access */
#define UKL_PLEDGE_RPATH        (1ULL << 1)   /* Read-only path operations */
#define UKL_PLEDGE_WPATH        (1ULL << 2)   /* Write path operations */
#define UKL_PLEDGE_CPATH        (1ULL << 3)   /* Create/delete paths */
#define UKL_PLEDGE_DPATH        (1ULL << 4)   /* Create device nodes */
#define UKL_PLEDGE_TMPPATH      (1ULL << 5)   /* Temporary file access */

/* Networking */
#define UKL_PLEDGE_INET         (1ULL << 6)   /* IPv4/IPv6 sockets */
#define UKL_PLEDGE_MCAST        (1ULL << 7)   /* Multicast operations */
#define UKL_PLEDGE_UNIX         (1ULL << 11)  /* Unix domain sockets */
#define UKL_PLEDGE_DNS          (1ULL << 12)  /* DNS resolution */

/* File operations */
#define UKL_PLEDGE_FATTR        (1ULL << 8)   /* File attributes (chmod, etc.) */
#define UKL_PLEDGE_CHOWN        (1ULL << 9)   /* Change ownership */
#define UKL_PLEDGE_FLOCK        (1ULL << 10)  /* File locking */

/* IPC */
#define UKL_PLEDGE_SENDFD       (1ULL << 14)  /* Send file descriptors */
#define UKL_PLEDGE_RECVFD       (1ULL << 15)  /* Receive file descriptors */

/* Devices */
#define UKL_PLEDGE_TAPE         (1ULL << 16)  /* Tape device operations */
#define UKL_PLEDGE_TTY          (1ULL << 17)  /* Terminal operations */
#define UKL_PLEDGE_AUDIO        (1ULL << 28)  /* Audio devices */
#define UKL_PLEDGE_VIDEO        (1ULL << 29)  /* Video devices */

/* Process control */
#define UKL_PLEDGE_PROC         (1ULL << 18)  /* fork, kill, wait, etc. */
#define UKL_PLEDGE_EXEC         (1ULL << 19)  /* execve */
#define UKL_PLEDGE_PROT_EXEC    (1ULL << 20)  /* mmap with PROT_EXEC */

/* System */
#define UKL_PLEDGE_SETTIME      (1ULL << 21)  /* Set system time */
#define UKL_PLEDGE_PS           (1ULL << 22)  /* Process listing */
#define UKL_PLEDGE_VMINFO       (1ULL << 23)  /* VM information */
#define UKL_PLEDGE_ID           (1ULL << 24)  /* Change UID/GID */
#define UKL_PLEDGE_GETPW        (1ULL << 13)  /* Password/group lookups */

/* Network administration */
#define UKL_PLEDGE_PF           (1ULL << 25)  /* Packet filter */
#define UKL_PLEDGE_ROUTE        (1ULL << 26)  /* Read routing tables */
#define UKL_PLEDGE_WROUTE       (1ULL << 27)  /* Write routing tables */

/* Advanced */
#define UKL_PLEDGE_BPF          (1ULL << 30)  /* BPF operations */
#define UKL_PLEDGE_UNVEIL       (1ULL << 31)  /* unveil() syscall */

/* Behavior modifiers */
#define UKL_PLEDGE_ERROR        (1ULL << 32)  /* Return -ENOSYS instead of SIGABRT */

/*
 * Linux-specific extensions (bits 33-62 reserved for future use)
 * Uncomment and use as needed:
 *
 * #define UKL_PLEDGE_IOURING     (1ULL << 33)
 * #define UKL_PLEDGE_SECCOMP     (1ULL << 34)
 * #define UKL_PLEDGE_NETLINK     (1ULL << 35)
 * #define UKL_PLEDGE_PERF        (1ULL << 36)
 * #define UKL_PLEDGE_USERFAULTFD (1ULL << 37)
 */

/* Special values */
#define UKL_PLEDGE_NEVER        (1ULL << 63)  /* Syscalls that can NEVER be enabled */
#define UKL_PLEDGE_ALL          (~0ULL)       /* All abilities (no restrictions) */

/*
 * Common pledge sets for convenience
 * Applications can use these or combine individual pledges.
 */
#define UKL_PLEDGE_NETWORK      (UKL_PLEDGE_INET | UKL_PLEDGE_DNS)
#define UKL_PLEDGE_FILESYSTEM   (UKL_PLEDGE_RPATH | UKL_PLEDGE_WPATH | UKL_PLEDGE_CPATH)
#define UKL_PLEDGE_MINIMAL      (UKL_PLEDGE_STDIO)

/*
 * Syscall number for ukl_pledge (to be registered in syscall table)
 */
#define __NR_ukl_pledge         451

/*
 * Function prototypes (implemented in kernel/ukl_pledge.c)
 */
#ifdef CONFIG_UNIKERNEL_LINUX
long sys_ukl_pledge(u64 promises, u64 execpromises);
bool ukl_pledge_check(unsigned int syscall_nr);
#else
static inline long sys_ukl_pledge(u64 promises, u64 execpromises) { return -ENOSYS; }
static inline bool ukl_pledge_check(unsigned int syscall_nr) { return true; }
#endif

#endif /* _LINUX_UKL_PLEDGE_H */
