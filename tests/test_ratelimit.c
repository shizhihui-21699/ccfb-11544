/* Unit tests for the two rate-limit algorithms, driven by a fake clock
 * so timing behavior is exact and reproducible. Builds against the same
 * ratelimit.c / hashmap.c used by the proxy. */
#include "ratelimit.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond, msg) do { \
    g_checks++; \
    if (!(cond)) { g_failures++; printf("  FAIL: %s (%s:%d)\n", msg, __FILE__, __LINE__); } \
} while (0)

static void test_token_bucket(void) {
    printf("token bucket: burst then sustained refill\n");
    rl_params_t p = { ALG_TOKEN_BUCKET, .rate = 10, .burst = 20, .window_ms = 1000 };
    rl_zone_t *z = rl_zone_create("tb", &p);
    int64_t t = 100000;

    /* Full bucket: burst of 20 allowed immediately. */
    int allowed = 0;
    for (int i = 0; i < 20; i++) {
        rl_decision_t d = rl_zone_check(z, "k", t);
        if (d.allowed) allowed++;
    }
    CHECK(allowed == 20, "burst capacity of 20");

    /* 21st at the same instant must be denied with Retry-After. */
    rl_decision_t denied = rl_zone_check(z, "k", t);
    CHECK(!denied.allowed, "21st request denied");
    CHECK(denied.retry_after_s >= 1, "Retry-After present on deny");

    /* After 100ms, 1 token refilled (10/s => 1 per 100ms). */
    t += 100;
    rl_decision_t one = rl_zone_check(z, "k", t);
    CHECK(one.allowed, "one token refilled after 100ms");

    /* After a full second of idle, bucket refills but caps at burst. */
    t += 5000;
    allowed = 0;
    for (int i = 0; i < 25; i++) {
        rl_decision_t d = rl_zone_check(z, "k", t);
        if (d.allowed) allowed++;
    }
    CHECK(allowed == 20, "bucket never exceeds burst cap after long idle");

    /* Independent keys do not share tokens. */
    rl_decision_t other = rl_zone_check(z, "different-key", t);
    CHECK(other.allowed, "separate key has its own bucket");

    size_t keys; uint64_t a, dn;
    rl_zone_stats(z, &keys, &a, &dn);
    CHECK(keys == 2, "two tracked keys");
    CHECK(dn >= 1, "deny counter incremented");
    rl_zone_destroy(z);
}

static void test_sliding_log(void) {
    printf("sliding window log: exact ceiling and smooth slide\n");
    rl_params_t p = { ALG_SLIDING_LOG, .rate = 5, .burst = 5, .window_ms = 1000 };
    rl_zone_t *z = rl_zone_create("sl", &p);
    int64_t t = 200000;

    int allowed = 0;
    for (int i = 0; i < 5; i++) {
        if (rl_zone_check(z, "k", t).allowed) allowed++;
    }
    CHECK(allowed == 5, "exactly rate requests allowed");
    CHECK(!rl_zone_check(z, "k", t).allowed, "6th denied within window");

    /* Just inside the window (oldest entry age 999ms), still denied. */
    t += 999;
    CHECK(!rl_zone_check(z, "k", t).allowed, "denied at 999ms");

    /* At exactly window ms the oldest entry still counts (half-open
     * interval), so the request is denied once more. */
    t += 1;
    CHECK(!rl_zone_check(z, "k", t).allowed, "denied at exactly window ms");

    /* One ms later all five old entries have aged out together, so the
     * full budget of 5 is available again in the new window. */
    t += 1;
    int refill = 0;
    for (int i = 0; i < 5; i++)
        if (rl_zone_check(z, "k", t).allowed) refill++;
    CHECK(refill == 5, "full budget returns once the old window clears");
    CHECK(!rl_zone_check(z, "k", t).allowed, "6th request in new window denied");

    /* After a full window with no traffic, the full budget returns. */
    t += 2000;
    allowed = 0;
    for (int i = 0; i < 5; i++)
        if (rl_zone_check(z, "k", t).allowed) allowed++;
    CHECK(allowed == 5, "full budget restored after quiet window");
    rl_zone_destroy(z);
}

static void test_reconfigure(void) {
    printf("reconfigure: counters preserved across parameter change\n");
    rl_params_t p = { ALG_TOKEN_BUCKET, .rate = 100, .burst = 100, .window_ms = 1000 };
    rl_zone_t *z = rl_zone_create("rc", &p);
    int64_t t = 0;
    for (int i = 0; i < 50; i++) CHECK(rl_zone_check(z, "k", t).allowed, "pre-reload traffic");

    rl_params_t tight = { ALG_TOKEN_BUCKET, .rate = 1, .burst = 1, .window_ms = 1000 };
    CHECK(rl_zone_reconfigure(z, &tight) == 0, "reconfigure succeeds");
    /* Existing bucket had ~50 tokens but new cap is 1; refill clamps. */
    rl_params_t got;
    rl_zone_get_params(z, &got);
    CHECK(got.burst == 1 && got.rate == 1, "new params live");

    rl_params_t switched = { ALG_SLIDING_LOG, .rate = 3, .burst = 3, .window_ms = 1000 };
    CHECK(rl_zone_reconfigure(z, &switched) == 0, "algorithm swap succeeds");
    int allowed = 0;
    for (int i = 0; i < 5; i++)
        if (rl_zone_check(z, "k", t).allowed) allowed++;
    CHECK(allowed == 3, "fresh sliding-log state after algorithm swap");
    rl_zone_destroy(z);
}

static void test_sweep(void) {
    printf("idle sweep reclaims stale keys\n");
    rl_params_t p = { ALG_TOKEN_BUCKET, .rate = 10, .burst = 10, .window_ms = 1000 };
    rl_zone_t *z = rl_zone_create("sw", &p);
    int64_t t = 0;
    rl_zone_check(z, "a", t);
    rl_zone_check(z, "b", t);
    rl_zone_check(z, "c", t);
    size_t keys; uint64_t x, y;
    rl_zone_stats(z, &keys, &x, &y);
    CHECK(keys == 3, "three keys before sweep");

    t += 1000;
    rl_zone_check(z, "a", t); /* a stays active */
    rl_zone_sweep(z, t, 500);  /* idle threshold 500ms */
    rl_zone_stats(z, &keys, &x, &y);
    CHECK(keys == 1, "idle keys swept, active key retained");
    rl_zone_destroy(z);
}

static void test_retry_after_bounds(void) {
    printf("Retry-After is always a positive whole second on deny\n");
    rl_params_t p = { ALG_TOKEN_BUCKET, .rate = 1, .burst = 1, .window_ms = 1000 };
    rl_zone_t *z = rl_zone_create("ra", &p);
    int64_t t = 0;
    rl_zone_check(z, "k", t); /* consume the single token */
    for (int ms = 1; ms <= 1000; ms += 137) {
        rl_decision_t d = rl_zone_check(z, "k", t + ms);
        if (!d.allowed) CHECK(d.retry_after_s >= 1, "Retry-After >= 1");
    }
    rl_zone_destroy(z);
}

int main(void) {
    test_token_bucket();
    test_sliding_log();
    test_reconfigure();
    test_sweep();
    test_retry_after_bounds();
    printf("\n%d checks, %d failures\n", g_checks, g_failures);
    return g_failures ? 1 : 0;
}
