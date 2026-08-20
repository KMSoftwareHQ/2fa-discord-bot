import test from "node:test";
import assert from "node:assert/strict";
import winston from "winston";
import { Writable } from "node:stream";
import { logger } from "./logger";

const SEED = "JBSWY3DPEHPK3PXP";

/** Capture exactly what the configured format chain emits. */
async function capture(fn: () => void): Promise<string> {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, done) {
      chunks.push(String(chunk));
      done();
    },
  });
  const sink = new winston.transports.Stream({ stream });
  logger.add(sink);
  try {
    fn();
    // Winston pipes through the format chain asynchronously; let it drain.
    await new Promise((resolve) => setImmediate(resolve));
  } finally {
    logger.remove(sink);
  }
  return chunks.join("");
}

test("a base32 seed is redacted wherever it appears", async () => {
  const out = await capture(() => {
    logger.info("storing", { secret: SEED, other: SEED, nested: { deep: SEED } });
  });
  assert.ok(!out.includes(SEED), `seed leaked into: ${out}`);
});

test("a Buffer is never serialised as recoverable bytes", async () => {
  // Winston's default JSON would render this as {"type":"Buffer","data":[...]},
  // which is the seed in a form no log review would spot.
  const out = await capture(() => {
    logger.info("plaintext handling", { plaintext: Buffer.from(SEED, "utf8") });
  });
  assert.ok(!out.includes('"data"'), "raw byte array must not be emitted");
  assert.ok(!out.includes("74,66,83"), "the seed's bytes must not appear");
  assert.ok(out.includes("[redacted]") || out.includes("[buffer:"), out);
});

test("an otpauth URI is redacted even in a free-text message", async () => {
  const out = await capture(() => {
    logger.error(`import failed for otpauth://totp/a?secret=${SEED}`);
  });
  assert.ok(!out.includes(SEED));
  assert.ok(!out.includes("otpauth://"));
});

test("sensitive key names are redacted regardless of value shape", async () => {
  const out = await capture(() => {
    logger.info("boot", {
      masterKey: "deadbeef".repeat(8),
      code: "482913",
      token: "abc.def.ghi",
      apiKey: "x",
    });
  });
  assert.ok(!out.includes("deadbeef"), out);
  assert.ok(!out.includes("482913"), "an issued code must never be logged");
  assert.ok(!out.includes("abc.def.ghi"), out);
});

test("ordinary diagnostic fields still come through", async () => {
  const out = await capture(() => {
    logger.info("request handled", { name: "aws-root", outcome: "allowed", count: 3 });
  });
  assert.ok(out.includes("aws-root"), "the operator still needs readable logs");
  assert.ok(out.includes("allowed"));
  assert.ok(out.includes("request handled"));
});
