/* SPDX-License-Identifier: GPL-2.0-only */

	.global _start
_start:
	jmp main

	.global syscall

/* Usage: long syscall (syscall_number, arg1, arg2, arg3, arg4, arg5, arg6)
   We need to do some arg shifting, the syscall_number will be in
   rax.  */

	.text
syscall:
	movq %rdi, %rax		/* Syscall number -> rax.  */
	movq %rsi, %rdi		/* shift arg1 - arg5.  */
	movq %rdx, %rsi
	movq %rcx, %rdx
	movq %r8, %r10
	movq %r9, %r8
	movq 8(%rsp),%r9	/* arg6 is on the stack.  */
	call entry_SYSCALL_64	/* Do the system call.  */
	cmpq $-4095, %rax	/* Check %rax for error.  */
	jae loop	/* Jump to error handler if error.  */
	ret			/* Return to caller.  */

loop:
	jmp loop
