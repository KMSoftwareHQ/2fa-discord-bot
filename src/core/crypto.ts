import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * AES-256-GCM envelope for TOTP seeds at rest.
 *
 * The interesting part is the AAD. Every ciphertext is authenticated against
 * `v<version>|<secret name>`, which binds a blob to the row it lives in.
 * Without that binding, anyone who can WRITE the database file — but not read
 * the master key — could copy the `aws-root` ciphertext into the row for some
 * throwaway secret they are on the ACL for, then ask the bot for a code and get
 * the root account's. Encryption alone does not stop that; the AAD does, because
 * decryption under the wrong name fails authentication outright.
 */

export const ENC_VERSION = 1;

const ALGORITHM = "aes-256-gcm";
const KEY_BYTES = 32;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;

export interface SealedSecret {
  version: number;
  nonce: Buffer;
  ciphertext: Buffer;
  tag: Buffer;
}

function assertKey(key: Buffer): void {
  if (key.length !== KEY_BYTES) {
    throw new Error(
      `Master key must be ${KEY_BYTES} bytes, got ${key.length}`,
    );
  }
}

/** The associated data a ciphertext is bound to. Not secret — just authenticated. */
function aad(version: number, name: string): Buffer {
  return Buffer.from(`v${version}|${name}`, "utf8");
}

export function seal(
  plaintext: Buffer,
  key: Buffer,
  name: string,
): SealedSecret {
  assertKey(key);
  const nonce = randomBytes(NONCE_BYTES);
  const cipher = createCipheriv(ALGORITHM, key, nonce);
  cipher.setAAD(aad(ENC_VERSION, name));
  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);
  return {
    version: ENC_VERSION,
    nonce,
    ciphertext,
    tag: cipher.getAuthTag(),
  };
}

/**
 * Throws on any tampering, on the wrong key, and — the case that matters — on a
 * ciphertext that was moved to a different secret's row.
 */
export function open(
  sealed: SealedSecret,
  key: Buffer,
  name: string,
): Buffer {
  assertKey(key);
  if (sealed.version !== ENC_VERSION) {
    throw new Error(`Unsupported encryption version: ${sealed.version}`);
  }
  if (sealed.nonce.length !== NONCE_BYTES) {
    throw new Error(`Nonce must be ${NONCE_BYTES} bytes`);
  }
  if (sealed.tag.length !== TAG_BYTES) {
    throw new Error(`Auth tag must be ${TAG_BYTES} bytes`);
  }
  const decipher = createDecipheriv(ALGORITHM, key, sealed.nonce);
  decipher.setAAD(aad(sealed.version, name));
  decipher.setAuthTag(sealed.tag);
  // .final() is what raises on a bad tag — never skip it.
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
}

/**
 * Best-effort overwrite of plaintext once we are done with it.
 *
 * This is genuinely best-effort in Node: the GC may already have relocated the
 * bytes, and V8 makes no promise about copies. It shortens the window, it does
 * not close it. SECURITY.md says so rather than implying a guarantee.
 */
export function wipe(...buffers: (Buffer | undefined)[]): void {
  for (const buf of buffers) {
    if (buf) buf.fill(0);
  }
}

/** A fresh master key, hex-encoded for pasting into .env. */
export function generateMasterKeyHex(): string {
  return randomBytes(KEY_BYTES).toString("hex");
}
