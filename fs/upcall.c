// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Upcall event handler implementaion for UKL
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched/signal.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/errno.h>
#include <linux/poll.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/rbtree.h>
#include <linux/wait.h>
#include <linux/eventpoll.h>
#include <linux/bitops.h>
#include <linux/uaccess.h>
#include <asm/io.h>
#include <linux/atomic.h>
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
	struct list_head		idle_tasks;
	spinlock_t			tasks_lock;
	struct list_head		work_item_head;
	spinlock_t			work_lock;
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
		struct event_handler *handler;

		local_irq_save(flags);
		handler = this_cpu_ptr(&pcpu_upcall);
		set_current_state(TASK_IDLE);
		spin_lock(&handler->tasks_lock);
		list_add_tail(&current->event_handlers, &handlers->idle_tasks);
		spin_unlock(&handler->tasks_lock);
		local_irq_restore(flags);
	}

	// Schedule is outside the block with flags because we want it cleared from
	// the stack when we return.
	schedule();

	enter_ukl_user();

	//ukl_state_k2u();
}

/*
 * Initialize the percpu event handler structures and prepare for execution
 * contexts to be registered.
 */
void init_upcall_handler(void)
{
	int i;
	struct event_handler *handler;
	for_each_online_cpu(i) {
		handler = per_cpu_ptr(&pcpu_upcall, i);
		INIT_LIST_HEAD(&handler->idle_tasks)
		INIT_LIST_HEAD(&handler->work_item_head);
		spin_lock_init(&handler->tasks_lock);
		spin_lock_init(&handler->work_lock);
	}
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

	// Set scheduler and cpu for handler task
	params.sched_priority = 99;
	if (sched_setscheduler_nocheck(current, SCHED_RR, &params)) {
		pr_warn("Failed to change scheduler policy to SCHED_RR.\n");
	}


	INIT_LIST_HEAD(&current->event_handlers);
	spin_lock(&handler->tasks_lock);
	list_add_tail(&current->event_handlers, &handler->idle_tasks);
	spin_unlock(&handler->tasks_lock);
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
	spin_lock(&handler->work_lock);
	evi = list_first_entry_or_null(&handler->work_item_head, struct event_work_item,
			work_item_head);
	if (!evi) {
		spin_unlockirq_restore(&handler->work_lock, flags);
		goto out;
	}

	__list_del_entry(&handler->work_item_head);
	spin_unlock_irqrestore(&handler->work_lock, flags);
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
	spin_lock_irqsave(&handler->work_lock, flags);
	list_add_tail(&evi->work_item_head, &handler->work_item_head);
	spin_unlock_irqrestore(&handler->work_lock, flags);
}

void upcall_handler(void *private)
{
	unsigned long flags;
	struct event_handler *handler;
	struct task_struct *thread;

	local_irq_save(flags);
	handler = this_cpu_ptr(&pcpu_upcall);

	if (!handler) {
		pr_err("Can't read pcpu handler pointer\n");
		return;
	}

	spin_lock(&handler->work_lock);
	workitem_queue_add_event(handler, private);
	spin_unlock(&handler->work_lock);

	spin_lock(&handler->tasks_lock);
	// Check if there is an idle handler and wake it. If there are no handlers idle,
	// the next one to finish its work will take up this new task.
	if (!list_empty(&handler->idle_tasks)) {
		thread = container_of(handler->idle_tasks->next, struct task_struct, event_handlers);
		list_del(&thread->event_handlers);
		wake_up_process(thread);
	}
	spin_lock_irqrestore(&handler->tasks_lock, flags);
}

