/*
 * Copyright (c) 2026 SUSE LLC
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <stdbool.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdlib.h>
#include <cmocka.h>
#include <time.h>
#include "time-util.h"
#include "util.h"
#include "debug.h"

#include "globals.c"

static const long billion = 1000L * 1000 * 1000;

struct normalize_test {
	long sec_in, nsec_in;
};

static const struct normalize_test normalize_tests[] = {
	/* already normalized */
	{ 0, 0 },
	{ 5, 0 },
	{ 5, 999999999 },
	{ -5, 0 },
	/* single positive overflow */
	{ 5, 1000000000 },
	{ 5, 1000000001 },
	{ 0, 1000000000 },
	/* multiple positive overflow */
	{ 5, 2000000000 },
	{ 5, 2500000000 },
	{ 0, 3000000001 },
	/* single negative overflow */
	{ 5, -1 },
	{ 0, -1 },
	/* multiple negative overflow */
	{ 5, -2000000000 },
	{ 5, -2000000001 },
	{ 0, -3000000001 },
};

static void test_normalize_timespec(void **state)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(normalize_tests); i++) {
		const struct normalize_test *t = &normalize_tests[i];
		struct timespec ts = { .tv_sec = t->sec_in, .tv_nsec = t->nsec_in };
		long long total_in = (long long)t->sec_in * billion + t->nsec_in;
		long long total_out;

		normalize_timespec(&ts);
		total_out = (long long)ts.tv_sec * billion + ts.tv_nsec;
		condlog(3, "%ld.%09ld -> %ld.%09ld",
			t->sec_in, t->nsec_in, ts.tv_sec, ts.tv_nsec);
		assert_in_range(ts.tv_nsec, 0, billion - 1);
		assert_int_equal(total_out, total_in);
	}
}

static void test_timespecsub(void **state)
{
	struct timespec a = { .tv_sec = 10, .tv_nsec = 500000000 };
	struct timespec b = { .tv_sec = 3, .tv_nsec = 700000000 };
	struct timespec res;

	/* a - b: nsec borrow required */
	timespecsub(&a, &b, &res);
	assert_int_equal(res.tv_sec, 6);
	assert_int_equal(res.tv_nsec, 800000000);

	/* b - a: negative result */
	timespecsub(&b, &a, &res);
	assert_int_equal(res.tv_sec, -7);
	assert_int_equal(res.tv_nsec, 200000000);

	/* a - a: zero result */
	timespecsub(&a, &a, &res);
	assert_int_equal(res.tv_sec, 0);
	assert_int_equal(res.tv_nsec, 0);

	/* no borrow needed */
	a.tv_sec = 10; a.tv_nsec = 700000000;
	b.tv_sec = 3; b.tv_nsec = 500000000;
	timespecsub(&a, &b, &res);
	assert_int_equal(res.tv_sec, 7);
	assert_int_equal(res.tv_nsec, 200000000);
}

static void test_timespeccmp(void **state)
{
	struct timespec a = { .tv_sec = 10, .tv_nsec = 500000000 };
	struct timespec b = { .tv_sec = 10, .tv_nsec = 500000000 };

	assert_int_equal(timespeccmp(&a, &b), 0);

	b.tv_nsec = 500000001;
	assert_int_equal(timespeccmp(&a, &b), -1);
	assert_int_equal(timespeccmp(&b, &a), 1);

	b.tv_sec = 9;
	b.tv_nsec = 999999999;
	assert_int_equal(timespeccmp(&a, &b), 1);
	assert_int_equal(timespeccmp(&b, &a), -1);

	b.tv_sec = 11;
	b.tv_nsec = 0;
	assert_int_equal(timespeccmp(&a, &b), -1);
	assert_int_equal(timespeccmp(&b, &a), 1);
}

static int test_timespec(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_normalize_timespec),
		cmocka_unit_test(test_timespecsub),
		cmocka_unit_test(test_timespeccmp),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}

int main(void)
{
	int ret = 0;

	init_test_verbosity(-1);
	ret += test_timespec();
	return ret;
}
