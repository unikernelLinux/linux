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
#include <linux/upcall.h>
#include <net/busy_poll.h>
#include <asm/mmu_context.h>
#include <linux/percpu-defs.h>
#include <linux/cpumask.h>

#include <linux/tsc_logger.h>

#include <linux/sched.h>
#include <uapi/linux/sched/types.h>

struct event_handler
{
	struct list_head		tasks;
	spinlock_t			tasks_lock;
	struct list_head		work_item_head;
	spinlock_t			work_lock;
};

struct pcpu_handler
{
	struct event_handler *handler;
};

static DEFINE_PER_CPU(struct pcpu_handler, pcpu_upcall);

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
		unsigned long flags;
		struct event_handler *handler;
		struct pcpu_handler *container;

		local_irq_save(flags);
		container = this_cpu_ptr(&pcpu_upcall);
		handler = container->handler;

		// There are no events to handle at the moment, mark ourselves
		// idle and go to sleep

		spin_lock(&handler->tasks_lock);
		list_add_tail(&current->event_handlers, &handler->tasks);
		set_current_state(TASK_IDLE);
		spin_unlock(&handler->tasks_lock);
		local_irq_restore(flags);
		// This barrier is paired with the one in upcall_hanlder() which will execute in
		// softIRQ context and attempt to wake a worker.
		smp_mb();
	}

	// Schedule is outside the block with flags because we want it cleared from
	// the stack when we return.
	schedule();
	enter_ukl_user();

	//ukl_state_k2u();
}

static struct event_handler *create_handler(void)
{
	struct event_handler *handler = kmalloc(sizeof(struct event_handler), GFP_ATOMIC);
	INIT_LIST_HEAD(&handler->tasks);
	INIT_LIST_HEAD(&handler->work_item_head);
	spin_lock_init(&handler->tasks_lock);
	spin_lock_init(&handler->work_lock);
	return handler;
}

#define UPCALL_PCPU	0
#define UPCALL_PCACHE	1
#define UPCALL_SINGLE	2
/*
 * Initialize the percpu event handler structures and prepare for execution
 * contexts to be registered.
 */
int init_upcall_handler(int concurrency_model)
{
	int i;
	int j;
	struct pcpu_handler *container;
	struct event_handler *mine;
	unsigned long flags;
	int queue_cnt = 0;

	switch(concurrency_model) {
	case UPCALL_PCPU:
		local_irq_save(flags);
		for_each_online_cpu(i) {
			container = per_cpu_ptr(&pcpu_upcall, i);
			container->handler = create_handler();
			queue_cnt++;
		}
		local_irq_restore(flags);
		break;
	case UPCALL_PCACHE:
		local_irq_save(flags);
		for_each_online_cpu(i) {
			container = per_cpu_ptr(&pcpu_upcall, i);
			if (container->handler) // We already have one set
				continue;
			mine = create_handler();
			queue_cnt++;
			container->handler = mine;
			for_each_cpu(j, topology_cluster_cpumask(i)) {
				if (i == j)
					continue;
				container = per_cpu_ptr(&pcpu_upcall, j);
				container->handler = mine;
			}
		}
		local_irq_restore(flags);
		break;
	case UPCALL_SINGLE:
		mine = create_handler();
		queue_cnt++;
		local_irq_save(flags);
		for_each_online_cpu(i) {
			container = per_cpu_ptr(&pcpu_upcall, i);
			container->handler = mine;
		}
		local_irq_restore(flags);
		break;
	}
	return queue_cnt;
}

/*
 * Take the calling task (which should be a thread for the application using
 * upcalls) and make it the event handler for the specified CPU. We will pin
 * it to the specified CPU in user space (the API for pinning is simpler there)
 */
void register_ukl_handler_task(void)
{
	struct sched_param params;
	struct pcpu_handler *container;
	struct event_handler *handler;
	unsigned long flags;

	enter_ukl_kernel();

	local_irq_save(flags);
	container = this_cpu_ptr(&pcpu_upcall);
	handler = container->handler;

	// Set scheduler and cpu for handler task
	params.sched_priority = 99;
	if (sched_setscheduler_nocheck(current, SCHED_RR, &params)) {
		pr_warn("Failed to change scheduler policy to SCHED_RR.\n");
	}


	INIT_LIST_HEAD(&current->event_handlers);
	spin_lock(&handler->tasks_lock);
	list_add_tail(&current->event_handlers, &handler->tasks);
	spin_unlock_irqrestore(&handler->tasks_lock, flags);

	enter_ukl_user();
}

struct event_work_item {
	struct list_head	work_item_head;
	struct ukl_event *	event;
};

// Return the opaque pointer supplied when this event was registered and re-enable
// the event waiter
struct work_item* workitem_queue_consume_event(void)
{
	struct ukl_event *value = NULL;
	unsigned long flags;
	struct event_work_item *evi;
	struct pcpu_handler *container;
	struct event_handler *handler;

	enter_ukl_kernel();

	local_irq_save(flags);
	container = this_cpu_ptr(&pcpu_upcall);
	handler = container->handler;
	spin_lock(&handler->work_lock);
	// This barrier is paired with one in workitem_queue_add_event(), this barrier ensures
	// the worker thread sees the new work items.
	smp_mb();
	evi = list_first_entry_or_null(&handler->work_item_head, struct event_work_item,
			work_item_head);
	if (evi) {
		list_del_init(&evi->work_item_head);
		value = evi->event;
	}

	spin_unlock_irqrestore(&handler->work_lock, flags);

	if (!value)
		return NULL;

	kfree(evi);

	add_wait_queue(value->whead, &value->wait);

	enter_ukl_user();
	return &value->work;
}

/* Caller is expected to have disabled interrupts */
static void workitem_queue_add_event(struct event_handler *handler, struct ukl_event *event)
{
	struct event_work_item *evi = kmalloc(sizeof(struct event_work_item), GFP_ATOMIC);
	if (!evi) {
		pr_err("Out of memory, dropping event!\n");
		return;
	}

	INIT_LIST_HEAD(&evi->work_item_head);

	evi->event = event;
	spin_lock(&handler->work_lock);
	list_add_tail(&evi->work_item_head, &handler->work_item_head);
	spin_unlock(&handler->work_lock);
	// This barrier is paired with the one in workitem_queue_consume_event()
	smp_mb();
}

void enqueue_event(struct ukl_event *event)
{
	unsigned long flags;
	struct event_handler *handler;
	struct pcpu_handler *container;
	struct task_struct *thread = NULL;

	local_irq_save(flags);
	container = this_cpu_ptr(&pcpu_upcall);
	handler = container->handler;

	if (!handler) {
		pr_err("Can't read pcpu handler pointer\n");
		return;
	}

	workitem_queue_add_event(handler, event);

	spin_lock(&handler->tasks_lock);
	// This barrier is paired with the one in the worker_sleep() function
	smp_mb();

	thread = list_first_entry_or_null(&handler->tasks, struct task_struct,
			event_handlers);
	if (thread) {
		list_del_init(&thread->event_handlers);
		wake_up_process(thread);
	}

	spin_unlock_irqrestore(&handler->tasks_lock, flags);
}

