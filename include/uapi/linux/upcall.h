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
#define UPCALLIN	EPOLLIN
#define UPCALLPRI	EPOLLPRI
#define UPCALLOUT	EPOLLOUT
#define UPCALLERR	EPOLLERR
#define UPCALLHUP	EPOLLHUP
#define UPCALLNVAL	EPOLLNVAL
#define UPCALLRDNORM	EPOLLRDNORM
#define UPCALLRDBAND	EPOLLRDBAND
#define UPCALLWRNORM	EPOLLWRNORM
#define UPCALLWRBAND	EPOLLWRBAND
#define UPCALLMSG	EPOLLMSG
#define UPCALLRDHUP	EPOLLRDHUP

#define UPCALL_ADD 1
#define UPCALL_DEL 2

#ifdef __x86_64__
#define UPCALL_PACKED __attribute__((packed))
#else
#define UPCALL_PACKED
#endif

#define UPIOGQCNT	0x00000001
#define UPIOSTSK	0x00000002

#define UPCALL_PCPU		0x00010000
#define UPCALL_PCACHE		0x00020000
#define UPCALL_SINGLE		0x00040000
#define UPCALL_MODEL_MASK	0x00070000
#define UPCALL_MASK		(O_CLOEXEC | UPCALL_MODEL_MASK)

struct work_item {
	void *arg;
	void (*work_fn)(void *arg);
} UPCALL_PACKED;


#endif
