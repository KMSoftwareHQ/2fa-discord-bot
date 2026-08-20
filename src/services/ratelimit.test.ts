import test from "node:test";
import assert from "node:assert/strict";
import {
  LIMITS,
  checkRateLimit,
  formatRateLimitWindow,
  getRateLimitRuleDescription,
  rateLimitEntryCount,
  resetRateLimits,
  sweep,
} from "./ratelimit";

const ALICE = "123456789012345678";
const BOB = "234567890123456789";
const T0 = 1_700_000_000_000;

test("allows up to the limit, then denies", () => {
  resetRateLimits();
  const max = LIMITS["2fa:get"]!.maxRequests;
  for (let i = 0; i < max; i++) {
    assert.equal(checkRateLimit("2fa:get", ALICE, T0 + i).allowed, true, `request ${i + 1}`);
  }
  const denied = checkRateLimit("2fa:get", ALICE, T0 + max);
  assert.equal(denied.allowed, false);
  assert.ok(!denied.allowed && denied.retryAfterSeconds >= 1);
  assert.ok(!denied.allowed && /10 per 5 minutes/.test(denied.rule));
});

test("the window slides — access returns once the oldest entry ages out", () => {
  resetRateLimits();
  const { maxRequests, windowMs } = LIMITS["2fa:get"]!;
  for (let i = 0; i < maxRequests; i++) checkRateLimit("2fa:get", ALICE, T0);
  assert.equal(checkRateLimit("2fa:get", ALICE, T0 + windowMs - 1).allowed, false);
  assert.equal(
    checkRateLimit("2fa:get", ALICE, T0 + windowMs + 1).allowed,
    true,
    "the whole window has passed",
  );
});

test("retryAfterSeconds derives from the oldest in-window request", () => {
  resetRateLimits();
  const { maxRequests, windowMs } = LIMITS["2fa:get"]!;
  for (let i = 0; i < maxRequests; i++) checkRateLimit("2fa:get", ALICE, T0);
  const denied = checkRateLimit("2fa:get", ALICE, T0 + 60_000);
  assert.equal(denied.allowed, false);
  if (!denied.allowed) {
    assert.equal(denied.retryAfterSeconds, (windowMs - 60_000) / 1000);
  }
});

test("buckets and keys are independent of one another", () => {
  resetRateLimits();
  const max = LIMITS["2fa:get"]!.maxRequests;
  for (let i = 0; i < max; i++) checkRateLimit("2fa:get", ALICE, T0);

  assert.equal(checkRateLimit("2fa:get", ALICE, T0).allowed, false, "alice exhausted");
  assert.equal(checkRateLimit("2fa:get", BOB, T0).allowed, true, "bob unaffected");
  assert.equal(
    checkRateLimit("2fa:list", ALICE, T0).allowed,
    true,
    "a different bucket for the same user is unaffected",
  );
});

test("per-secret keys do not bleed into each other", () => {
  resetRateLimits();
  const max = LIMITS["2fa:get:secret"]!.maxRequests;
  for (let i = 0; i < max; i++) {
    checkRateLimit("2fa:get:secret", `${ALICE}:aws-root`, T0);
  }
  assert.equal(checkRateLimit("2fa:get:secret", `${ALICE}:aws-root`, T0).allowed, false);
  assert.equal(
    checkRateLimit("2fa:get:secret", `${ALICE}:github-org`, T0).allowed,
    true,
    "a different secret is a different bucket entry",
  );
  assert.equal(
    checkRateLimit("2fa:get:secret", `${BOB}:aws-root`, T0).allowed,
    true,
    "a different user is a different bucket entry",
  );
});

test("an unknown bucket is not a limit", () => {
  resetRateLimits();
  for (let i = 0; i < 1000; i++) {
    assert.equal(checkRateLimit("nope", ALICE, T0).allowed, true);
  }
  assert.equal(getRateLimitRuleDescription("nope"), null);
});

test("sweep evicts entries whose window has fully passed", () => {
  resetRateLimits();
  checkRateLimit("2fa:get", ALICE, T0);
  checkRateLimit("2fa:get:secret", `${BOB}:aws-root`, T0);
  assert.equal(rateLimitEntryCount(), 2);

  assert.equal(sweep(T0 + 1000), 0, "nothing expired yet");
  assert.equal(rateLimitEntryCount(), 2);

  // Both buckets use a 5-minute window; step past it.
  assert.equal(sweep(T0 + 300_001), 2);
  assert.equal(rateLimitEntryCount(), 0, "the Map must not grow without bound");
});

test("sweep uses each entry's own window, not one guessed from the key", () => {
  resetRateLimits();
  checkRateLimit("2fa:list", ALICE, T0); // 1-minute window
  checkRateLimit("2fa:get", ALICE, T0); // 5-minute window

  sweep(T0 + 61_000);
  assert.equal(rateLimitEntryCount(), 1, "the 1-minute entry went, the 5-minute one stayed");
  assert.equal(
    checkRateLimit("2fa:get", ALICE, T0 + 61_000).allowed,
    true,
    "and the survivor still has its history",
  );
});

test("formatRateLimitWindow reads naturally", () => {
  assert.equal(formatRateLimitWindow(60_000), "minute");
  assert.equal(formatRateLimitWindow(300_000), "5 minutes");
  assert.equal(formatRateLimitWindow(3_600_000), "hour");
  assert.equal(formatRateLimitWindow(7_200_000), "2 hours");
  assert.equal(formatRateLimitWindow(30_000), "30 seconds");
});
