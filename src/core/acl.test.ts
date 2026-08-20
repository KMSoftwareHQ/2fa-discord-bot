import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AclStore,
  DENIED_MESSAGE,
  accessibleNames,
  isAllowed,
  parseAcl,
  parseAclJson,
} from "./acl";

const ALICE = "123456789012345678";
const BOB = "234567890123456789";
const CAROL = "345678901234567890";

const VALID = {
  version: 1,
  secrets: {
    "aws-root": { allowed: [ALICE], note: "break-glass" },
    "github-org": { allowed: [ALICE, BOB] },
  },
};

test("parseAcl accepts a well-formed allowlist", () => {
  const acl = parseAcl(VALID);
  assert.equal(acl.version, 1);
  assert.equal(acl.secrets.size, 2);
  assert.deepEqual(acl.secrets.get("aws-root")?.allowed, [ALICE]);
  assert.equal(acl.secrets.get("aws-root")?.note, "break-glass");
  assert.equal(acl.secrets.get("github-org")?.note, "");
  assert.deepEqual(acl.warnings, []);
});

test("an empty allowlist is valid and grants nobody", () => {
  const acl = parseAcl({ version: 1, secrets: {} });
  assert.equal(acl.secrets.size, 0);
  assert.equal(isAllowed(acl, "aws-root", ALICE), false);
  assert.deepEqual(accessibleNames(acl, ALICE), []);
});

test("a Discord ID written as a JSON number is rejected, not silently mangled", () => {
  // 123456789012345678 > 2^53, so JSON.parse yields 123456789012345680 —
  // a different, real, valid-looking snowflake. Silently granting the wrong
  // account is worse than any error.
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "aws-root": { allowed: [123456789012345678] } } }),
    /written as a JSON number.*cannot be recovered.*wrap it in quotes/s,
  );

  // The advice must not echo the rounded value back: telling someone to quote
  // "123456789012345680" would grant a different account than they intended.
  try {
    parseAcl({ version: 1, secrets: { "aws-root": { allowed: [123456789012345678] } } });
    assert.fail("should have thrown");
  } catch (err) {
    const msg = (err as Error).message;
    assert.ok(
      !/quote it: "123456789012345680"/i.test(msg),
      "must not tell the operator to quote the already-corrupted number",
    );
  }
});

test("parseAcl rejects structurally wrong input with distinct messages", () => {
  assert.throws(() => parseAcl(null), /must be a JSON object/);
  assert.throws(() => parseAcl([]), /must be a JSON object/);
  assert.throws(() => parseAcl({}), /"version" must be 1/);
  assert.throws(() => parseAcl({ version: 2, secrets: {} }), /"version" must be 1/);
  assert.throws(() => parseAcl({ version: 1 }), /"secrets" must be an object/);
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "aws-root": [] } }),
    /must be an object/,
  );
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "aws-root": {} } }),
    /must have an "allowed" array/,
  );
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "aws-root": { allowed: "nope" } } }),
    /must have an "allowed" array/,
  );
});

test("parseAcl rejects bad names and bad IDs", () => {
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "AWS Root": { allowed: [ALICE] } } }),
    /Invalid secret name/,
  );
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "a|b": { allowed: [ALICE] } } }),
    /Invalid secret name/,
    "a pipe would make the crypto AAD ambiguous",
  );
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "aws-root": { allowed: ["not-an-id"] } } }),
    /not a Discord user ID/,
  );
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "aws-root": { allowed: ["12345"] } } }),
    /not a Discord user ID/,
  );
  assert.throws(
    () => parseAcl({ version: 1, secrets: { "aws-root": { allowed: [null] } } }),
    /non-string entry/,
  );
});

test("parseAcl warns without failing on recoverable oddities", () => {
  const acl = parseAcl({
    version: 1,
    secrets: {
      dup: { allowed: [ALICE, ALICE] },
      nobody: { allowed: [] },
      extra: { allowed: [BOB], colour: "blue" },
    },
  });
  assert.deepEqual(acl.secrets.get("dup")?.allowed, [ALICE], "deduped");
  assert.ok(acl.warnings.some((w) => /more than once/.test(w)));
  assert.ok(acl.warnings.some((w) => /grants nobody/.test(w)));
  assert.ok(acl.warnings.some((w) => /unknown field "colour"/.test(w)));
});

test("isAllowed and accessibleNames reflect exactly the grants", () => {
  const acl = parseAcl(VALID);
  assert.equal(isAllowed(acl, "aws-root", ALICE), true);
  assert.equal(isAllowed(acl, "aws-root", BOB), false);
  assert.equal(isAllowed(acl, "github-org", BOB), true);
  assert.equal(isAllowed(acl, "github-org", CAROL), false);
  assert.equal(isAllowed(acl, "does-not-exist", ALICE), false);

  assert.deepEqual(accessibleNames(acl, ALICE), ["aws-root", "github-org"]);
  assert.deepEqual(accessibleNames(acl, BOB), ["github-org"]);
  assert.deepEqual(accessibleNames(acl, CAROL), []);
});

test("parseAclJson reports malformed JSON as such", () => {
  assert.throws(() => parseAclJson("{ nope"), /not valid JSON/);
  assert.doesNotThrow(() => parseAclJson(JSON.stringify(VALID)));
});

test("AclStore re-reads on change and keeps the last-good copy on breakage", () => {
  const dir = mkdtempSync(join(tmpdir(), "acl-test-"));
  const path = join(dir, "acl.json");
  try {
    writeFileSync(path, JSON.stringify(VALID));
    // minRecheckMs 0 so the test controls timing rather than the clock.
    const store = new AclStore(path, 0);

    let got = store.get(1000);
    assert.equal(got.stale, false);
    assert.equal(isAllowed(got.acl, "github-org", BOB), true);
    assert.equal(isAllowed(got.acl, "github-org", CAROL), false);

    // Add Carol — no restart involved.
    writeFileSync(
      path,
      JSON.stringify({
        version: 1,
        secrets: { "aws-root": { allowed: [ALICE] }, "github-org": { allowed: [ALICE, BOB, CAROL] } },
      }),
    );
    got = store.get(2000);
    assert.equal(got.stale, false);
    assert.equal(isAllowed(got.acl, "github-org", CAROL), true, "hot reload applied");

    // Break the file mid-edit.
    writeFileSync(path, "{ this is not json");
    got = store.get(3000);
    assert.equal(got.stale, true, "flagged as serving a stale copy");
    assert.match(got.error ?? "", /not valid JSON/);
    assert.equal(
      isAllowed(got.acl, "github-org", CAROL),
      true,
      "last-good ACL still serves — a typo must not lock the team out",
    );

    // Fixing it heals without a restart.
    writeFileSync(path, JSON.stringify(VALID));
    got = store.get(4000);
    assert.equal(got.stale, false);
    assert.equal(isAllowed(got.acl, "github-org", CAROL), false, "removal now applied");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AclStore does not re-stat inside the recheck floor", () => {
  const dir = mkdtempSync(join(tmpdir(), "acl-test-"));
  const path = join(dir, "acl.json");
  try {
    writeFileSync(path, JSON.stringify(VALID));
    const store = new AclStore(path, 1000);
    store.get(10_000);

    writeFileSync(path, JSON.stringify({ version: 1, secrets: {} }));
    const within = store.get(10_500);
    assert.equal(within.acl.secrets.size, 2, "still the cached parse");

    const after = store.get(11_100);
    assert.equal(after.acl.secrets.size, 0, "re-read once the floor elapsed");
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("AclStore refuses to start on a broken file", () => {
  const dir = mkdtempSync(join(tmpdir(), "acl-test-"));
  const path = join(dir, "acl.json");
  try {
    writeFileSync(path, "nope");
    assert.throws(() => new AclStore(path, 0).loadOrThrow(), /not valid JSON/);
    assert.throws(() => new AclStore(join(dir, "missing.json"), 0).loadOrThrow(), /ENOENT/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("the denial message names nothing and never varies", () => {
  assert.equal(DENIED_MESSAGE, "No secret by that name is available to you.");
  assert.ok(!/exist|authori|permission|denied/i.test(DENIED_MESSAGE.replace(/available/, "")),
    "must not hint at which failure occurred");
});
