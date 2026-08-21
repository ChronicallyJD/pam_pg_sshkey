/*
 * test_framework.h, minimal C test framework (C99-compatible)
 *
 * Usage in each test file:
 *   Define a test function:   static void test_foo(void) { ASSERT_EQ(a, b); }
 *   Register it in main():    RUN(test_foo);
 *   Call at end of main():    return SUMMARY();
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef TEST_FRAMEWORK_H
#define TEST_FRAMEWORK_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int _tf_run    = 0;
static int _tf_passed = 0;
static int _tf_failed = 0;
static int _tf_cur_fail = 0;

/* ── assertion macros ─────────────────────────────────────────────────── */
#define _TF_FAIL(fmt, ...) \
    do { \
        fprintf(stderr, "    FAIL %s:%d: " fmt "\n", \
                __FILE__, __LINE__, ##__VA_ARGS__); \
        _tf_cur_fail = 1; \
    } while (0)

#define ASSERT_TRUE(expr) \
    do { if (!(expr)) _TF_FAIL("expected true: %s", #expr); } while (0)

#define ASSERT_FALSE(expr) \
    do { if (expr) _TF_FAIL("expected false: %s", #expr); } while (0)

#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) \
        _TF_FAIL("%s==%s (%lld != %lld)", #a, #b, \
                 (long long)(a), (long long)(b)); } while (0)

#define ASSERT_NE(a, b) \
    do { if ((a) == (b)) \
        _TF_FAIL("%s!=%s (both==%lld)", #a, #b, (long long)(a)); } while (0)

#define ASSERT_STR_EQ(a, b) \
    do { const char *_a=(a), *_b=(b); \
         if (!_a||!_b||strcmp(_a,_b)!=0) \
             _TF_FAIL("strcmp: \"%s\" != \"%s\"", \
                      _a?_a:"(null)", _b?_b:"(null)"); } while (0)

#define ASSERT_NOT_NULL(p) \
    do { if ((p)==NULL) _TF_FAIL("%s is NULL", #p); } while (0)

#define ASSERT_NULL(p) \
    do { if ((p)!=NULL) _TF_FAIL("%s is not NULL", #p); } while (0)

#define ASSERT_MEM_EQ(a, b, n) \
    do { if (memcmp((a),(b),(n))!=0) \
             _TF_FAIL("memcmp(%s, %s, %zu) != 0", #a, #b, (size_t)(n)); \
    } while (0)

/* ── runner macros ────────────────────────────────────────────────────── */
#define RUN(fn) \
    do { \
        _tf_run++; _tf_cur_fail = 0; \
        printf("  %-50s", #fn); \
        fn(); \
        if (_tf_cur_fail) { _tf_failed++; printf("FAIL\n"); } \
        else              { _tf_passed++; printf("pass\n"); } \
    } while (0)

#define SUMMARY() \
    ( printf("\n%d passed, %d failed, %d total\n", \
             _tf_passed, _tf_failed, _tf_run), \
      (_tf_failed > 0) ? 1 : 0 )

#endif /* TEST_FRAMEWORK_H */
