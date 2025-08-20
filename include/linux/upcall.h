/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UPCALL_H
#define _LINUX_UPCALL_H

#include <uapi/linux/upcall.h>
#include <linux/file.h>

void upcall_release_file(struct file *file);

static inline void upcall_release(struct file *file)
{
	if (likely(!file->f_upcall))
		return;

	upcall_release_file(file);
};

#endif
