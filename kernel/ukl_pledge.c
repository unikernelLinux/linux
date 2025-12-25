// SPDX-License-Identifier: GPL-2.0
/*
 * UKL Pledge - Security sandboxing for Unikernel Linux
 *
 * This module implements OpenBSD-style pledge(2) for UKL applications,
 * allowing processes to voluntarily restrict their own capabilities.
 *
 * Inspired by:
 *   - OpenBSD pledge(2): https://man.openbsd.org/pledge
 *   - Nanos unikernel: https://github.com/nanovms/nanos
 *
 * Copyright (c) 2024 UKL Contributors
 */

#include <linux/syscalls.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/ukl_pledge.h>

/*
 * String names for pledge promises.
 * Must be kept in sync with UKL_PLEDGE_* bit definitions.
 * Used for future string-based API (like OpenBSD's pledge("stdio rpath", NULL))
 */
static const char * const ukl_pledge_names[] = {
	[0]  = "stdio",
	[1]  = "rpath",
	[2]  = "wpath",
	[3]  = "cpath",
	[4]  = "dpath",
	[5]  = "tmppath",
	[6]  = "inet",
	[7]  = "mcast",
	[8]  = "fattr",
	[9]  = "chown",
	[10] = "flock",
	[11] = "unix",
	[12] = "dns",
	[13] = "getpw",
	[14] = "sendfd",
	[15] = "recvfd",
	[16] = "tape",
	[17] = "tty",
	[18] = "proc",
	[19] = "exec",
	[20] = "prot_exec",
	[21] = "settime",
	[22] = "ps",
	[23] = "vminfo",
	[24] = "id",
	[25] = "pf",
	[26] = "route",
	[27] = "wroute",
	[28] = "audio",
	[29] = "video",
	[30] = "bpf",
	[31] = "unveil",
	[32] = "error",
	/* Bits 33-62 reserved for Linux-specific extensions */
	/* Bit 63 is UKL_PLEDGE_NEVER */
};

#define UKL_PLEDGE_NAMES_COUNT ARRAY_SIZE(ukl_pledge_names)

/*
 * ukl_pledge_fail - Handle a pledge violation
 * @t: The task that violated the pledge
 *
 * By default, sends SIGABRT to the violating task (like OpenBSD).
 * If UKL_PLEDGE_ERROR is set, returns -ENOSYS instead (graceful mode).
 *
 * Returns: 0 if signal sent, -ENOSYS if ERROR mode
 */
static long __maybe_unused ukl_pledge_fail(struct task_struct *t)
{
	/*
	 * Check if the task requested error mode instead of signal.
	 * This allows applications to handle pledge violations gracefully.
	 */
	if (t->ukl_pledge & UKL_PLEDGE_ERROR)
		return -ENOSYS;

	/*
	 * Default behavior: Send SIGABRT to terminate the process.
	 * This matches OpenBSD pledge(2) semantics.
	 */
	send_sig(SIGABRT, t, 0);
	return 0;
}

/*
 * sys_ukl_pledge - Restrict process capabilities
 * @promises: Bitmask of capabilities to allow
 * @execpromises: Bitmask for capabilities after execve (reserved, unused)
 *
 * Once pledge is called, the process can only:
 *   1. Use system calls allowed by the promises bitmask
 *   2. Call pledge again to further REDUCE capabilities (never increase)
 *
 * Security guarantees:
 *   - Pledge can only be made more restrictive, never less
 *   - A zero value for promises (after first pledge) blocks almost everything
 *   - UKL_PLEDGE_NEVER bit is never allowed to be set
 *
 * Returns:
 *   0      - Success
 *   -EPERM - Attempted to add new abilities not previously held
 *   -EINVAL - Invalid promises (e.g., PLEDGE_NEVER bit set)
 */
SYSCALL_DEFINE2(ukl_pledge, u64, promises, u64, execpromises)
{
	struct task_struct *task = current;
	u64 current_pledge;

	/*
	 * Validate input: PLEDGE_NEVER must never be set by userspace.
	 * This bit is reserved for internal use to mark syscalls that
	 * should never be allowed under any pledge.
	 */
	if (promises & UKL_PLEDGE_NEVER)
		return -EINVAL;

	/*
	 * Read current pledge state.
	 * A value of 0 means "no pledge set yet" (all abilities allowed).
	 */
	current_pledge = task->ukl_pledge;

	/*
	 * First pledge call: Any valid promises mask is accepted.
	 * This establishes the initial capability restriction.
	 */
	if (current_pledge == 0) {
		task->ukl_pledge = promises;
		return 0;
	}

	/*
	 * Subsequent pledge calls: Can only REDUCE capabilities.
	 * Check if new promises request abilities not currently held.
	 * 
	 * Logic: (promises & ~current_pledge) gives bits that are:
	 *   - Set in 'promises' (requested)
	 *   - NOT set in 'current_pledge' (not allowed)
	 * If any such bits exist, this is an attempt to escalate.
	 */
	if (promises & ~current_pledge)
		return -EPERM;

	/*
	 * Update pledge with the new (more restrictive) mask.
	 * Since promises is a subset of current_pledge, this is safe.
	 */
	task->ukl_pledge = promises;

	return 0;
}

/*
 * ukl_pledge_check - Check if a syscall is allowed by current pledge
 * @syscall_nr: The system call number being attempted
 *
 * This function is called from the syscall entry path (Phase 2).
 * For now (Phase 1), it's a stub that always allows.
 *
 * Returns:
 *   true  - Syscall is allowed
 *   false - Syscall is blocked by pledge
 */
bool ukl_pledge_check(unsigned int syscall_nr)
{
	struct task_struct *task = current;

	/*
	 * No pledge set: All syscalls allowed.
	 * This preserves backward compatibility.
	 */
	if (task->ukl_pledge == 0)
		return true;

	/*
	 * TODO (Phase 2): Implement actual check against syscall mapping.
	 * For now, always allow to enable incremental testing.
	 *
	 * Future logic:
	 *   u64 required = ukl_syscall_abilities[syscall_nr];
	 *   if ((task->ukl_pledge & required) != required) {
	 *       ukl_pledge_fail(task);
	 *       return false;
	 *   }
	 */
	return true;
}
EXPORT_SYMBOL_GPL(ukl_pledge_check);

/*
 * ukl_pledge_get_name - Get the name of a pledge bit (for debugging/logging)
 * @bit: Bit position (0-63)
 *
 * Returns: String name or NULL if bit is reserved/unknown
 */
const char *ukl_pledge_get_name(unsigned int bit)
{
	if (bit >= UKL_PLEDGE_NAMES_COUNT)
		return NULL;
	return ukl_pledge_names[bit];
}
EXPORT_SYMBOL_GPL(ukl_pledge_get_name);
