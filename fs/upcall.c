// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Upcall event handler implementaion for UKL
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/signal.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/mount.h>
#include <linux/bitops.h>
#include <linux/mutex.h>
#include <linux/anon_inodes.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <asm/mman.h>
#include <linux/atomic.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/compat.h>
#include <linux/rculist.h>
#include <net/busy_poll.h>
#include <asm/mmu_context.h>
#include <linux/percpu-defs.h>
#include <linux/cpumask.h>

#include <linux/tsc_logger.h>

#include <linux/sched.h>
#include <uapi/linux/sched/types.h>

struct event_work_item{
	void *data;
	struct list_head work_item_head;
};

struct event_handler
{
	struct task_struct		*handler_task; 	// This should probably become a collection.
	struct list_head		work_item_head;
};

static DEFINE_PER_CPU(struct event_handler, pcpu_upcall);

extern void ukl_state_u2k(void);
extern void ukl_state_k2u(void);

void ukl_worker_sleep(void)
{
	// This function is intended to be called from a user space thread that
	// was created to handle events. AFAICT this is the most efficient way
	// for a task to "sleep".

	//ukl_state_u2k();
	enter_ukl_kernel();

	// The block here is for the stack allocation of flags and to ensure
	// that it is popped before we call ukl_state_k2u
	{
		// There are no events to handle at the moment, mark ourselves
		// idle and go to sleep
		unsigned long flags;
		local_irq_save(flags);
		set_current_state(TASK_IDLE);
		local_irq_restore(flags);
	}

	// Schedule is outside the block with flags because we don't know where
	// we will be running when we return
	schedule();

	enter_ukl_user();

	//ukl_state_k2u();
}

/*
 * Take the calling task (which should be a thread for the application using
 * upcalls) and make it the event handler for the specified CPU. We will pin
 * it to the specified CPU in user space (the API for pinning is simpler there)
 */
void register_ukl_handler_task(void)
{
	struct sched_param params;
	struct event_handler *handler;
	unsigned long flags;

	enter_ukl_kernel();
	local_irq_save(flags);
	handler = this_cpu_ptr(&pcpu_upcall);

	// Setup the work queue and lock
	INIT_LIST_HEAD(&handler->work_item_head);

	// Set scheduler and cpu for handler task
	params.sched_priority = 99;
	if (sched_setscheduler_nocheck(current, SCHED_RR, &params)) {
		pr_warn("Failed to change scheduler policy to SCHED_RR.\n");
	}


	handler->handler_task = current;
	local_irq_restore(flags);

	enter_ukl_user();
}

// Return the opaque pointer supplied when this event was registered
void* workitem_queue_consume_event(void)
{
	void *value = NULL;
	unsigned long flags;
	struct event_work_item *evi;
	struct event_handler *handler;

	enter_ukl_kernel();

	local_irq_save(flags);
	handler = this_cpu_ptr(&pcpu_upcall);
	evi = list_first_entry_or_null(&handler->work_item_head, struct event_work_item,
			work_item_head);
	if (!evi) {
		local_irq_restore(flags);
		goto out;
	}

	__list_del_entry(&handler->work_item_head);
	local_irq_restore(flags);
	value = evi->data;
	kfree(evi);

out:
	enter_ukl_user();
	return value;
}

static void workitem_queue_add_event(struct event_handler *handler, void *private)
{
	unsigned long flags;
	struct event_work_item *evi = kmalloc(sizeof(struct event_work_item), GFP_ATOMIC);
	if (!evi) {
		pr_err("Out of memory, dropping event!\n");
		return;
	}

	evi->data = private;
	local_irq_save(flags);
	list_add_tail(&evi->work_item_head, &handler->work_item_head);
	local_irq_restore(flags);
}

void upcall_handler(void *private)
{
	struct event_handler *handler;

	handler = this_cpu_ptr(&pcpu_upcall);

	if (!handler) {
		pr_err("Can't read pcpu handler pointer\n");
		return;
	}

	workitem_queue_add_event(handler, private);
	wake_up_process(handler->handler_task);
}

