import { authenticator } from "otplib";
import { HashAlgorithms } from "@otplib/core";

/**
 * TOTP generation and `otpauth://` parsing.
 *
 * Per-secret algorithm/digits/period are carried through rather than assumed.
 * Plenty of real services issue 8-digit or SHA256 TOTP, and hardcoding
 * 6/30/SHA1 does not fail loudly for those — it silently produces a
 * well-formed code that the service rejects, which is a miserable thing to
 * debug at a login prompt.
 */

export type TotpAlgorithm = "SHA1" | "SHA256" | "SHA512";

export interface TotpParams {
  algorithm: TotpAlgorithm;
  digits: number;
  period: number;
}

export interface ParsedOtpauth extends TotpParams {
  secret: string;
  issuer: string;
  account: string;
}

export const DEFAULT_TOTP_PARAMS: TotpParams = {
  algorithm: "SHA1",
  digits: 6,
  period: 30,
};

const BASE32_RE = /^[A-Z2-7]+=*$/;
const VALID_ALGORITHMS: readonly TotpAlgorithm[] = ["SHA1", "SHA256", "SHA512"];
const VALID_DIGITS: readonly number[] = [6, 7, 8];

/**
 * Authenticator apps and password managers export seeds with spaces and in
 * mixed case; padding is optional. Normalise before validating so a
 * copy-paste from a "can't scan the QR?" panel just works.
 */
export function normalizeBase32Secret(raw: string): string {
  const cleaned = raw.replace(/[\s-]/g, "").toUpperCase();
  if (cleaned.length === 0) {
    throw new Error("Secret is empty");
  }
  if (!BASE32_RE.test(cleaned)) {
    throw new Error(
      "Secret is not valid base32 (expected characters A-Z and 2-7)",
    );
  }
  // Base32 encodes 5 bits per character; a stripped seed must be a whole
  // number of 8-character groups' worth of content to decode cleanly.
  const unpadded = cleaned.replace(/=+$/, "");
  if (unpadded.length < 8) {
    throw new Error("Secret is too short to be a valid TOTP seed");
  }
  return unpadded;
}

export function validateTotpParams(params: TotpParams): void {
  if (!VALID_ALGORITHMS.includes(params.algorithm)) {
    throw new Error(
      `Unsupported algorithm: ${params.algorithm} (expected one of ${VALID_ALGORITHMS.join(", ")})`,
    );
  }
  if (!VALID_DIGITS.includes(params.digits)) {
    throw new Error(
      `Unsupported digit count: ${params.digits} (expected one of ${VALID_DIGITS.join(", ")})`,
    );
  }
  if (!Number.isInteger(params.period) || params.period < 1 || params.period > 300) {
    throw new Error(`Period must be an integer between 1 and 300 seconds`);
  }
}

export interface GeneratedCode {
  code: string;
  /** Whole seconds until this code stops being valid. */
  expiresInSeconds: number;
}

export function generateCode(
  secret: string,
  params: TotpParams,
  nowMs: number,
): GeneratedCode {
  validateTotpParams(params);
  const instance = authenticator.clone({
    digits: params.digits,
    step: params.period,
    // The enum keys are exactly SHA1/SHA256/SHA512, so this maps without a cast.
    algorithm: HashAlgorithms[params.algorithm],
    epoch: nowMs,
  });
  return {
    code: instance.generate(secret),
    expiresInSeconds: secondsRemaining(params.period, nowMs),
  };
}

/** Seconds left in the current step. Always in 1..period. */
export function secondsRemaining(period: number, nowMs: number): number {
  const elapsed = Math.floor(nowMs / 1000) % period;
  return period - elapsed;
}

/** Milliseconds until the next step begins. */
export function msUntilNextStep(period: number, nowMs: number): number {
  const stepMs = period * 1000;
  return stepMs - (nowMs % stepMs);
}

/** Group a code for readability: 482913 -> "482 913", 12345678 -> "1234 5678". */
export function formatCode(code: string): string {
  if (code.length === 6) return `${code.slice(0, 3)} ${code.slice(3)}`;
  if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
  return code;
}

/**
 * Parse an `otpauth://totp/...` URI as produced by every authenticator QR code.
 *
 * Reading the parameters out of the URI is what keeps the 8-digit and SHA256
 * cases correct — the QR already carries them, so there is no reason to ask a
 * human to retype them and get it wrong.
 */
export function parseOtpauthUri(uri: string): ParsedOtpauth {
  let url: URL;
  try {
    url = new URL(uri.trim());
  } catch {
    throw new Error("Not a valid URI");
  }

  if (url.protocol !== "otpauth:") {
    throw new Error(`Expected an otpauth:// URI, got ${url.protocol}//`);
  }
  // URL puts the part before the first slash in .hostname for these.
  const kind = url.hostname.toLowerCase();
  if (kind !== "totp") {
    throw new Error(
      `Only time-based (totp) URIs are supported, got "${kind}". ` +
        `Counter-based HOTP cannot be served this way.`,
    );
  }

  const rawSecret = url.searchParams.get("secret");
  if (!rawSecret) {
    throw new Error("URI has no secret parameter");
  }
  const secret = normalizeBase32Secret(rawSecret);

  // Label is "Issuer:account" or just "account"; the issuer query parameter
  // wins when both are present, per the Key Uri Format spec.
  const label = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const sep = label.indexOf(":");
  const labelIssuer = sep >= 0 ? label.slice(0, sep).trim() : "";
  const account = (sep >= 0 ? label.slice(sep + 1) : label).trim();
  const issuer = (url.searchParams.get("issuer") ?? labelIssuer).trim();

  const algorithm = (
    url.searchParams.get("algorithm") ?? DEFAULT_TOTP_PARAMS.algorithm
  ).toUpperCase() as TotpAlgorithm;
  const digits = parseIntParam(
    url.searchParams.get("digits"),
    DEFAULT_TOTP_PARAMS.digits,
    "digits",
  );
  const period = parseIntParam(
    url.searchParams.get("period"),
    DEFAULT_TOTP_PARAMS.period,
    "period",
  );

  const params: TotpParams = { algorithm, digits, period };
  validateTotpParams(params);

  return { ...params, secret, issuer, account };
}

function parseIntParam(
  raw: string | null,
  fallback: number,
  label: string,
): number {
  if (raw === null || raw === "") return fallback;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) {
    throw new Error(`Invalid ${label} parameter: ${raw}`);
  }
  return n;
}
