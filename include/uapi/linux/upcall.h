/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 */

#ifndef _UAPI_LINUX_UPCALL_H
#define _UAPI_LINUX_UPCALL_H

#include <linux/types.h>
#include <uapi/linux/eventpoll.h>

/* Upcall event masks, lifted from eventpoll.h */

#ifdef __x86_64__
#define UPCALL_PACKED __attribute__((packed))
#else
#define UPCALL_PACKED
#endif

#define UPCALL_MASK		(O_CLOEXEC)

typedef enum {
	UP_READ,        // Requesting a read of the fd
	UP_WRITE,       // Requesting a write of the fd
	UP_ACCEPT,      // Requesting an accept4 on the fd (will imply SOCK_NONBLOCK)
	UP_VEC,         // Give the struct iovec array at buf with len items to the kernel
	NR_ACTIONS      // Error checking
} up_action_t;

struct up_event {
	int32_t		fd;
	int32_t		result;
	void		__user *buf;
	uint64_t	len;
	void		(*work_fn)(struct up_event *arg);
	union {
		up_action_t	type;
		uint64_t	pad;
	};
} UPCALL_PACKED;

#endif
