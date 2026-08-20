import test from "node:test";
import assert from "node:assert/strict";
import {
  DEFAULT_TOTP_PARAMS,
  formatCode,
  generateCode,
  msUntilNextStep,
  normalizeBase32Secret,
  parseOtpauthUri,
  secondsRemaining,
  validateTotpParams,
  type TotpAlgorithm,
} from "./totp";

/**
 * Derived rather than pasted: if this encoder were wrong the RFC codes below
 * would not match, so the vectors check the encoder and the encoder feeds the
 * vectors. Transcribing 103 base32 characters by hand is how you get a test
 * that fails for reasons unrelated to the code under test.
 */
function base32Encode(buf: Buffer): string {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of buf) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

// RFC 6238 Appendix B: the 20-byte ASCII seed, extended to the hash's block
// size for SHA256 and SHA512 (the interpretation every implementation uses).
const SEED_20 = "12345678901234567890";
const SEEDS: Record<TotpAlgorithm, string> = {
  SHA1: base32Encode(Buffer.from(SEED_20, "ascii")),
  SHA256: base32Encode(Buffer.from(SEED_20.repeat(2).slice(0, 32), "ascii")),
  SHA512: base32Encode(Buffer.from(SEED_20.repeat(4).slice(0, 64), "ascii")),
};

/** [unix seconds, SHA1, SHA256, SHA512] — all 8 digits, 30-second step. */
const RFC6238_VECTORS: ReadonlyArray<[number, string, string, string]> = [
  [59, "94287082", "46119246", "90693936"],
  [1111111109, "07081804", "68084774", "25091201"],
  [1111111111, "14050471", "67062674", "99943326"],
  [1234567890, "89005924", "91819424", "93441116"],
  [2000000000, "69279037", "90698825", "38618901"],
  [20000000000, "65353130", "77737706", "47863826"],
];

test("generateCode matches the RFC 6238 test vectors for all three algorithms", () => {
  for (const [seconds, sha1, sha256, sha512] of RFC6238_VECTORS) {
    const expected: Record<TotpAlgorithm, string> = {
      SHA1: sha1,
      SHA256: sha256,
      SHA512: sha512,
    };
    for (const algorithm of ["SHA1", "SHA256", "SHA512"] as const) {
      const { code } = generateCode(
        SEEDS[algorithm],
        { algorithm, digits: 8, period: 30 },
        seconds * 1000,
      );
      assert.equal(
        code,
        expected[algorithm],
        `${algorithm} at t=${seconds} should be ${expected[algorithm]}, got ${code}`,
      );
    }
  }
});

test("digits and period are honoured, not assumed", () => {
  const at = 1111111109 * 1000;
  // Same instant, same seed — a 6-digit request is the 8-digit code's tail.
  const six = generateCode(SEEDS.SHA1, { ...DEFAULT_TOTP_PARAMS }, at);
  assert.equal(six.code.length, 6);
  assert.equal(six.code, "081804");

  // A 60-second period lands in a different step, so a different code.
  const sixty = generateCode(
    SEEDS.SHA1,
    { algorithm: "SHA1", digits: 6, period: 60 },
    at,
  );
  assert.notEqual(sixty.code, six.code);
});

test("secondsRemaining counts down within the step and never returns 0", () => {
  const stepStart = 1111111080 * 1000; // a multiple of 30 seconds
  assert.equal(secondsRemaining(30, stepStart), 30);
  assert.equal(secondsRemaining(30, stepStart + 1_000), 29);
  assert.equal(secondsRemaining(30, stepStart + 29_000), 1);
  assert.equal(secondsRemaining(30, stepStart + 30_000), 30, "rolls over");
  for (let offset = 0; offset < 30_000; offset += 137) {
    const left = secondsRemaining(30, stepStart + offset);
    assert.ok(left >= 1 && left <= 30, `out of range at +${offset}ms: ${left}`);
  }
});

test("msUntilNextStep lands exactly on the boundary", () => {
  const stepStart = 1111111080 * 1000;
  assert.equal(msUntilNextStep(30, stepStart), 30_000);
  assert.equal(msUntilNextStep(30, stepStart + 29_500), 500);
  for (const offset of [0, 1, 999, 15_000, 29_999]) {
    const wait = msUntilNextStep(30, stepStart + offset);
    assert.ok(wait > 0 && wait <= 30_000, `bad wait at +${offset}ms`);
    assert.equal(
      (stepStart + offset + wait) % 30_000,
      0,
      "waiting must put us on a step boundary",
    );
  }
});

test("normalizeBase32Secret accepts real-world copy-paste", () => {
  assert.equal(normalizeBase32Secret("jbswy3dpehpk3pxp"), "JBSWY3DPEHPK3PXP");
  assert.equal(
    normalizeBase32Secret("JBSW Y3DP EHPK 3PXP"),
    "JBSWY3DPEHPK3PXP",
  );
  assert.equal(
    normalizeBase32Secret("JBSW-Y3DP-EHPK-3PXP"),
    "JBSWY3DPEHPK3PXP",
  );
  assert.equal(normalizeBase32Secret("JBSWY3DPEHPK3PXP===="), "JBSWY3DPEHPK3PXP");
});

test("normalizeBase32Secret rejects things that are not base32", () => {
  assert.throws(() => normalizeBase32Secret(""), /empty/i);
  assert.throws(() => normalizeBase32Secret("   "), /empty|not valid base32/i);
  assert.throws(() => normalizeBase32Secret("JBSWY3DP1EHPK"), /base32/i, "1 is not in the alphabet");
  assert.throws(() => normalizeBase32Secret("JBSWY3DP!"), /base32/i);
  assert.throws(() => normalizeBase32Secret("JBSWY3D"), /too short/i);
});

test("validateTotpParams rejects unsupported combinations", () => {
  assert.throws(
    () => validateTotpParams({ algorithm: "MD5" as TotpAlgorithm, digits: 6, period: 30 }),
    /Unsupported algorithm/,
  );
  assert.throws(
    () => validateTotpParams({ algorithm: "SHA1", digits: 9, period: 30 }),
    /Unsupported digit count/,
  );
  assert.throws(
    () => validateTotpParams({ algorithm: "SHA1", digits: 6, period: 0 }),
    /Period must be/,
  );
  assert.throws(
    () => validateTotpParams({ algorithm: "SHA1", digits: 6, period: 30.5 }),
    /Period must be/,
  );
});

test("parseOtpauthUri reads the parameters the QR already carries", () => {
  const parsed = parseOtpauthUri(
    "otpauth://totp/ACME%20Co:alice%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
  );
  assert.equal(parsed.secret, "JBSWY3DPEHPK3PXP");
  assert.equal(parsed.issuer, "ACME Co");
  assert.equal(parsed.account, "alice@example.com");
  assert.equal(parsed.algorithm, "SHA256");
  assert.equal(parsed.digits, 8);
  assert.equal(parsed.period, 60);
});

test("parseOtpauthUri applies the spec defaults when parameters are absent", () => {
  const parsed = parseOtpauthUri(
    "otpauth://totp/alice@example.com?secret=jbswy3dpehpk3pxp",
  );
  assert.equal(parsed.secret, "JBSWY3DPEHPK3PXP", "normalised on the way in");
  assert.equal(parsed.issuer, "");
  assert.equal(parsed.account, "alice@example.com");
  assert.equal(parsed.algorithm, "SHA1");
  assert.equal(parsed.digits, 6);
  assert.equal(parsed.period, 30);
});

test("parseOtpauthUri prefers the issuer parameter over the label prefix", () => {
  const parsed = parseOtpauthUri(
    "otpauth://totp/Stale:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Authoritative",
  );
  assert.equal(parsed.issuer, "Authoritative");
  assert.equal(parsed.account, "alice@example.com");
});

test("parseOtpauthUri rejects what it cannot serve", () => {
  assert.throws(() => parseOtpauthUri("not a uri at all"), /valid URI/i);
  assert.throws(
    () => parseOtpauthUri("https://example.com/?secret=JBSWY3DPEHPK3PXP"),
    /Expected an otpauth/,
  );
  assert.throws(
    () => parseOtpauthUri("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=1"),
    /time-based/i,
    "HOTP is stateful and cannot be handed out this way",
  );
  assert.throws(
    () => parseOtpauthUri("otpauth://totp/alice"),
    /no secret/i,
  );
  assert.throws(
    () => parseOtpauthUri("otpauth://totp/alice?secret=not-base32!"),
    /base32/i,
  );
  assert.throws(
    () => parseOtpauthUri("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&digits=9"),
    /Unsupported digit count/,
  );
});

test("formatCode groups for readability without altering the digits", () => {
  assert.equal(formatCode("482913"), "482 913");
  assert.equal(formatCode("12345678"), "1234 5678");
  assert.equal(formatCode("1234567"), "1234567", "odd lengths pass through");
  assert.equal(formatCode("482913").replace(/\s/g, ""), "482913");
});
