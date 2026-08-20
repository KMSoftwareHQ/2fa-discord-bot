import test from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { ENC_VERSION, generateMasterKeyHex, open, seal, wipe } from "./crypto";

/** Returns a copy with one byte flipped — strict index access makes in-place awkward. */
function flipByte(buf: Buffer, index = 0): Buffer {
  const copy = Buffer.from(buf);
  copy[index] = (copy[index] ?? 0) ^ 0xff;
  return copy;
}

const KEY = Buffer.alloc(32, 0x11);
const OTHER_KEY = Buffer.alloc(32, 0x22);
const SEED = Buffer.from("JBSWY3DPEHPK3PXP", "utf8");

test("seal/open round-trips under the same key and name", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  assert.equal(sealed.version, ENC_VERSION);
  assert.equal(sealed.nonce.length, 12);
  assert.equal(sealed.tag.length, 16);
  assert.deepEqual(open(sealed, KEY, "aws-root"), SEED);
});

test("the ciphertext does not contain the plaintext", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  assert.ok(
    !sealed.ciphertext.includes(SEED),
    "plaintext seed must not be recoverable by grepping the blob",
  );
});

test("a fresh nonce is used per seal, so identical seeds differ on disk", () => {
  const a = seal(SEED, KEY, "aws-root");
  const b = seal(SEED, KEY, "aws-root");
  assert.notDeepEqual(a.nonce, b.nonce);
  assert.notDeepEqual(a.ciphertext, b.ciphertext);
});

test("open rejects a ciphertext moved to another secret's row (AAD binding)", () => {
  // The attack: someone who can write the DB but not read the key copies the
  // aws-root blob into a row they ARE authorised for. Without AAD this decrypts
  // happily and the bot hands back the root account's code.
  const sealed = seal(SEED, KEY, "aws-root");
  assert.throws(
    () => open(sealed, KEY, "demo-account"),
    /unable to authenticate|unsupported state/i,
  );
});

test("open rejects a tampered ciphertext", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  const tampered = { ...sealed, ciphertext: flipByte(sealed.ciphertext) };
  assert.throws(() => open(tampered, KEY, "aws-root"));
});

test("open rejects a tampered auth tag", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  const tampered = { ...sealed, tag: flipByte(sealed.tag) };
  assert.throws(() => open(tampered, KEY, "aws-root"));
});

test("open rejects a tampered nonce", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  const tampered = { ...sealed, nonce: flipByte(sealed.nonce) };
  assert.throws(() => open(tampered, KEY, "aws-root"));
});

test("open rejects the wrong master key", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  assert.throws(() => open(sealed, OTHER_KEY, "aws-root"));
});

test("open rejects an unknown encryption version", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  assert.throws(
    () => open({ ...sealed, version: 99 }, KEY, "aws-root"),
    /Unsupported encryption version/,
  );
});

test("seal and open reject a key that is not 32 bytes", () => {
  const short = randomBytes(16);
  assert.throws(() => seal(SEED, short, "aws-root"), /must be 32 bytes/);
  const sealed = seal(SEED, KEY, "aws-root");
  assert.throws(() => open(sealed, short, "aws-root"), /must be 32 bytes/);
});

test("open rejects a malformed nonce or tag length", () => {
  const sealed = seal(SEED, KEY, "aws-root");
  assert.throws(
    () => open({ ...sealed, nonce: Buffer.alloc(8) }, KEY, "aws-root"),
    /Nonce must be 12 bytes/,
  );
  assert.throws(
    () => open({ ...sealed, tag: Buffer.alloc(8) }, KEY, "aws-root"),
    /Auth tag must be 16 bytes/,
  );
});

test("wipe zeroes buffers and tolerates undefined", () => {
  const buf = Buffer.from("sensitive", "utf8");
  wipe(buf, undefined);
  assert.deepEqual(buf, Buffer.alloc(buf.length, 0));
});

test("generateMasterKeyHex produces 64 distinct hex chars", () => {
  const a = generateMasterKeyHex();
  const b = generateMasterKeyHex();
  assert.match(a, /^[0-9a-f]{64}$/);
  assert.notEqual(a, b);
  assert.equal(Buffer.from(a, "hex").length, 32);
});
