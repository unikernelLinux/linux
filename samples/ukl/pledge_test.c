// SPDX-License-Identifier: GPL-2.0-only
/*
 * UKL Pledge Test - Minimal version using only syscalls
 *
 * This test uses direct syscall() calls instead of libc functions
 * because UKL apps are linked into the kernel without libc.
 */

/* Syscall numbers (x86_64) */
#define SYS_write   1
#define SYS_exit    60
#define SYS_pledge  451

/* Pledge bits */
#define UKL_PLEDGE_STDIO  (1ULL << 0)
#define UKL_PLEDGE_INET   (1ULL << 6)

/* External syscall function (provided by syscall.S) */
extern long syscall(long number, ...);

/* Simple string output (no printf needed) */
static void print(const char *s)
{
	int len = 0;
	while (s[len]) len++;
	syscall(SYS_write, 1, s, len);
}

/* Print test result */
static void pass(const char *name)
{
	print("[PASS] ");
	print(name);
	print("\n");
}

static void fail(const char *name)
{
	print("[FAIL] ");
	print(name);
	print("\n");
}

/* Test counters */
static int tests_passed = 0;
static int tests_failed = 0;

int main(void)
{
	long ret;

	print("\n");
	print("========================================\n");
	print("     UKL Pledge Syscall Test Suite\n");
	print("========================================\n");
	print("Testing Phase 1 (skeleton) functionality\n");
	print("\n");

	/* Test 1: Initial pledge should succeed */
	print("=== Test 1: Initial pledge ===\n");
	ret = syscall(SYS_pledge, UKL_PLEDGE_STDIO | UKL_PLEDGE_INET, 0);
	if (ret == 0) {
		pass("Initial pledge (STDIO|INET) returns 0");
		tests_passed++;
	} else {
		fail("Initial pledge failed");
		tests_failed++;
	}

	/* Test 2: Reduce pledge should succeed */
	print("\n=== Test 2: Reduce pledge ===\n");
	ret = syscall(SYS_pledge, UKL_PLEDGE_STDIO, 0);
	if (ret == 0) {
		pass("Reduce to STDIO only returns 0");
		tests_passed++;
	} else {
		fail("Reduce pledge failed");
		tests_failed++;
	}

	/* Test 3: Escalation should fail */
	print("\n=== Test 3: Escalation (should fail) ===\n");
	ret = syscall(SYS_pledge, UKL_PLEDGE_STDIO | UKL_PLEDGE_INET, 0);
	if (ret == -1) {
		pass("Escalation blocked (returned -1)");
		tests_passed++;
	} else {
		fail("Escalation was NOT blocked!");
		tests_failed++;
	}

	/* Test 4: Reduce to zero should work */
	print("\n=== Test 4: Reduce to zero ===\n");
	ret = syscall(SYS_pledge, 0, 0);
	if (ret == 0) {
		pass("Reduce to zero returns 0");
		tests_passed++;
	} else {
		fail("Reduce to zero failed");
		tests_failed++;
	}

	/* Print summary */
	print("\n");
	print("========================================\n");
	print("           TEST SUMMARY\n");
	print("========================================\n");

	if (tests_failed == 0) {
		print("  *** ALL TESTS PASSED ***\n");
	} else {
		print("  !!! SOME TESTS FAILED !!!\n");
	}

	print("========================================\n");
	print("\nTest complete. Halting.\n");

	/* Exit with success/failure code */
	syscall(SYS_exit, tests_failed > 0 ? 1 : 0);

	/* Should never reach here */
	while (1) {}

	return 0;
}
