/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_UPCALL_H
#define _LINUX_UPCALL_H

#include <linux/poll.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/wait.h>

struct work_item {
        void *arg;
        void (*work_fn)(void *arg);
};

struct ukl_event{
        struct work_item work;
        wait_queue_entry_t wait;
        __poll_t events;
        wait_queue_head_t *whead;
	struct list_head anchor;
};

#endif
