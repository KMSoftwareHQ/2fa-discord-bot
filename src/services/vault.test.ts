import test from "node:test";
import assert from "node:assert/strict";
import { openDatabase } from "../db";
import { parseAcl } from "../core/acl";
import { generateCode } from "../core/totp";
import { resetRateLimits } from "./ratelimit";
import { queryAudit } from "./audit";
import {
  DENIED_MESSAGE,
  listAccessible,
  listSecretMetadata,
  resolveCodeRequest,
  storeSecret,
  type VaultDeps,
} from "./vault";

const KEY = Buffer.alloc(32, 0x42);
const OTHER_KEY = Buffer.alloc(32, 0x43);
const ALICE = "123456789012345678";
const BOB = "234567890123456789";
const SEED = "JBSWY3DPEHPK3PXP";
// 1700000000s sits 20s into a 30-second step, so +20s lands 10s into the next
// one: comfortably mid-window, no boundary wait.
const T0 = 1_700_000_000_000 + 20_000;

const ACL = parseAcl({
  version: 1,
  secrets: {
    "aws-root": { allowed: [ALICE] },
    "github-org": { allowed: [ALICE, BOB] },
  },
});

function fixture() {
  const db = openDatabase(":memory:");
  storeSecret(db, KEY, {
    name: "aws-root",
    secret: SEED,
    issuer: "AWS",
    account: "root@example.com",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
  }, T0);
  storeSecret(db, KEY, {
    name: "github-org",
    secret: SEED,
    issuer: "GitHub",
    account: "org-owner",
    algorithm: "SHA256",
    digits: 8,
    period: 30,
  }, T0);
  return db;
}

function deps(db: ReturnType<typeof fixture>, over: Partial<VaultDeps> = {}): VaultDeps {
  return { db, acl: ACL, key: KEY, nowMs: T0, sleep: async () => {}, ...over };
}

test("an authorized request returns the correct code", async () => {
  resetRateLimits();
  const db = fixture();
  const res = await resolveCodeRequest(deps(db), { userId: ALICE, name: "aws-root" });
  assert.equal(res.kind, "code");
  if (res.kind !== "code") return;

  const expected = generateCode(SEED, { algorithm: "SHA1", digits: 6, period: 30 }, T0);
  assert.equal(res.code, expected.code);
  assert.equal(res.formattedCode, `${res.code.slice(0, 3)} ${res.code.slice(3)}`);
  assert.equal(res.issuer, "AWS");
  assert.equal(res.expiresInSeconds, 20, "10s into a 30s step");
  assert.equal(res.waitedMs, 0);
  db.close();
});

test("per-secret TOTP parameters are honoured, not defaulted", async () => {
  resetRateLimits();
  const db = fixture();
  const res = await resolveCodeRequest(deps(db), { userId: ALICE, name: "github-org" });
  assert.equal(res.kind, "code");
  if (res.kind !== "code") return;
  assert.equal(res.code.length, 8, "stored as 8 digits");
  const expected = generateCode(SEED, { algorithm: "SHA256", digits: 8, period: 30 }, T0);
  assert.equal(res.code, expected.code, "and SHA256, not the SHA1 default");
  db.close();
});

test("every failure mode is byte-identical to the user", async () => {
  resetRateLimits();
  const db = fixture();

  // Bob is not granted aws-root; nobody is granted a name that does not exist.
  const notGranted = await resolveCodeRequest(deps(db), { userId: BOB, name: "aws-root" });
  const notFound = await resolveCodeRequest(deps(db), { userId: BOB, name: "no-such-thing" });
  const grantedButMissing = await resolveCodeRequest(
    deps(db, { acl: parseAcl({ version: 1, secrets: { ghost: { allowed: [BOB] } } }) }),
    { userId: BOB, name: "ghost" },
  );

  assert.equal(notGranted.kind, "denied");
  assert.equal(notFound.kind, "denied");
  assert.equal(grantedButMissing.kind, "denied");
  assert.deepEqual(notGranted, notFound, "the shapes must be indistinguishable");
  assert.deepEqual(notGranted, grantedButMissing);
  assert.deepEqual(
    Object.keys(notGranted),
    ["kind"],
    "a denial must carry no reason field at all",
  );
  db.close();
});

test("the audit trail records the truth the user was not told", async () => {
  resetRateLimits();
  const db = fixture();
  await resolveCodeRequest(deps(db), { userId: BOB, name: "aws-root" });
  await resolveCodeRequest(deps(db), { userId: BOB, name: "no-such-thing" });

  const rows = queryAudit(db, {});
  assert.equal(rows.length, 2);
  const outcomes = rows.map((r) => r.outcome).sort();
  assert.deepEqual(outcomes, ["denied", "not_found"], "distinguished server-side");
  assert.ok(
    rows.some((r) => r.secretName === "no-such-thing"),
    "the real requested name is recorded even though the reply named nothing",
  );
  db.close();
});

test("no seed and no issued code ever reaches the audit table", async () => {
  resetRateLimits();
  const db = fixture();
  const res = await resolveCodeRequest(deps(db), { userId: ALICE, name: "aws-root" });
  assert.equal(res.kind, "code");
  if (res.kind !== "code") return;

  const dump = JSON.stringify(queryAudit(db, { limit: 1000 }));
  assert.ok(!dump.includes(SEED), "seed must not appear anywhere in the audit log");
  assert.ok(!dump.includes(res.code), "the issued code must not be recorded");
  assert.ok(dump.includes("step="), "but the step index is, for correlation");
  db.close();
});

test("the per-user limit applies before authorization, so denials are bounded", async () => {
  resetRateLimits();
  const db = fixture();
  // Bob has no grant on aws-root. He must still exhaust the limiter by probing.
  for (let i = 0; i < 10; i++) {
    const r = await resolveCodeRequest(deps(db), { userId: BOB, name: `probe-${i}` });
    assert.equal(r.kind, "denied", `probe ${i} denied`);
  }
  const limited = await resolveCodeRequest(deps(db), { userId: BOB, name: "probe-10" });
  assert.equal(
    limited.kind,
    "rate_limited",
    "an unauthorized user cannot enumerate names indefinitely",
  );
  db.close();
});

test("the per-secret limit does not become an existence oracle", async () => {
  resetRateLimits();
  const db = fixture();
  // Alice legitimately pulls aws-root until the per-secret bucket is empty.
  for (let i = 0; i < 5; i++) {
    const r = await resolveCodeRequest(deps(db), { userId: ALICE, name: "aws-root" });
    assert.equal(r.kind, "code", `pull ${i}`);
  }
  const sixth = await resolveCodeRequest(deps(db), { userId: ALICE, name: "aws-root" });
  assert.equal(sixth.kind, "rate_limited");

  // Bob, unauthorized, must not be able to exhaust a per-secret bucket at all:
  // if he could, the bucket state would tell him which names are real.
  resetRateLimits();
  for (let i = 0; i < 6; i++) {
    const r = await resolveCodeRequest(deps(db), { userId: BOB, name: "aws-root" });
    assert.equal(r.kind, "denied", "always the same answer, never a limit signal");
  }
  db.close();
});

test("a code about to expire waits for the next window instead of being handed over", async () => {
  resetRateLimits();
  const db = fixture();
  // +8s puts us 28 seconds into a 30-second step: 2 seconds left.
  const nearBoundary = 1_700_000_000_000 + 8_000;
  let slept = 0;
  const res = await resolveCodeRequest(
    deps(db, { nowMs: nearBoundary, sleep: async (ms) => { slept = ms; } }),
    { userId: ALICE, name: "aws-root" },
  );
  assert.equal(res.kind, "code");
  if (res.kind !== "code") return;

  assert.ok(slept > 0, "it waited");
  assert.equal(res.waitedMs, 2_250, "2s to the boundary plus a 250ms cushion");
  assert.ok(res.expiresInSeconds >= 25, "the user gets a full window, not 2 seconds");

  const expected = generateCode(
    SEED,
    { algorithm: "SHA1", digits: 6, period: 30 },
    nearBoundary + 2_250,
  );
  assert.equal(res.code, expected.code, "and it is the NEXT step's code");
  db.close();
});

test("a wrong master key yields an error, not a wrong code", async () => {
  resetRateLimits();
  const db = fixture();
  const res = await resolveCodeRequest(deps(db, { key: OTHER_KEY }), {
    userId: ALICE,
    name: "aws-root",
  });
  assert.equal(res.kind, "error");
  assert.equal(queryAudit(db, {})[0]?.outcome, "error");
  db.close();
});

test("listAccessible shows only what the caller may reach and that exists", () => {
  const db = fixture();
  assert.deepEqual(
    listAccessible(db, ACL, ALICE).map((s) => s.name),
    ["aws-root", "github-org"],
  );
  assert.deepEqual(
    listAccessible(db, ACL, BOB).map((s) => s.name),
    ["github-org"],
    "bob does not learn that aws-root exists",
  );
  assert.deepEqual(listAccessible(db, ACL, "999999999999999999"), []);

  // A grant for a secret with no row must not be advertised.
  const ghostAcl = parseAcl({ version: 1, secrets: { ghost: { allowed: [ALICE] } } });
  assert.deepEqual(listAccessible(db, ghostAcl, ALICE), []);
  db.close();
});

test("storeSecret updates in place and preserves created_at", () => {
  const db = fixture();
  storeSecret(db, KEY, {
    name: "aws-root", secret: SEED, issuer: "AWS Updated",
    algorithm: "SHA1", digits: 8, period: 60,
  }, T0 + 10_000);

  const all = listSecretMetadata(db);
  assert.equal(all.length, 2, "updated, not duplicated");
  const row = all.find((s) => s.name === "aws-root")!;
  assert.equal(row.issuer, "AWS Updated");
  assert.equal(row.digits, 8);
  assert.equal(row.period, 60);
  assert.equal(row.createdAt, T0, "created_at survives an update");
  assert.equal(row.updatedAt, T0 + 10_000);
  db.close();
});

test("the seed is not recoverable from the stored row", () => {
  const db = fixture();
  const raw = db.prepare("SELECT ciphertext, nonce, tag FROM secrets WHERE name = ?")
    .get("aws-root") as { ciphertext: Buffer; nonce: Buffer; tag: Buffer };
  const blob = Buffer.concat([raw.nonce, raw.ciphertext, raw.tag]).toString("utf8");
  assert.ok(!blob.includes(SEED), "grepping the row must not turn up the seed");
  db.close();
});

test("DENIED_MESSAGE is re-exported so the Discord layer has one source", () => {
  assert.equal(DENIED_MESSAGE, "No secret by that name is available to you.");
});
