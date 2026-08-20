import winston from "winston";
import { config } from "./config";

/**
 * JSON to stdout; the supervisor and `docker compose logs` own rotation.
 *
 * The redaction format below is a BACKSTOP, not the control. The actual control
 * is that seed material never reaches the logger: seeds live in Buffers that
 * are wiped after use, and services/audit.ts takes a fixed field set with no
 * parameter that could carry one. This exists because "never" is a property of
 * today's code, and log statements get added by people in a hurry.
 */

const SENSITIVE_KEY_RE =
  /(secret|seed|token|password|passphrase|master|otpauth|^code$|_code$|apikey|api_key)/i;
const BASE32_SEED_RE = /^[A-Z2-7]{16,}=*$/;
const MAX_STRING = 2000;

function redactString(value: string): string {
  if (BASE32_SEED_RE.test(value)) return "[redacted:base32]";
  if (value.includes("otpauth://")) return "[redacted:otpauth]";
  if (value.length > MAX_STRING) return `${value.slice(0, MAX_STRING)}…[truncated]`;
  return value;
}

function redactValue(value: unknown, depth: number): unknown {
  if (depth > 6) return "[deep]";

  // Buffers first. Winston serialises a Buffer as
  // {"type":"Buffer","data":[74,66,83,...]} — the seed, fully recoverable, in a
  // shape nobody scans for during a log review. This is the leak most worth
  // catching.
  if (Buffer.isBuffer(value)) return `[buffer:${value.length}b]`;
  if (value instanceof Error) return { name: value.name, message: value.message };
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));

  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      out[key] = SENSITIVE_KEY_RE.test(key)
        ? "[redacted]"
        : redactValue(val, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Mutates `info` in place rather than returning a fresh object.
 *
 * That is not a style choice: a winston info object carries Symbol.for("level")
 * and Symbol.for("message") alongside its string keys, and the transports read
 * those symbols. Spreading into a new object literal silently drops them and
 * the logger stops emitting anything at all.
 */
const redact = winston.format((info) => {
  if (typeof info.message === "string") {
    info.message = redactString(info.message);
  }

  const bag = info as unknown as Record<string, unknown>;
  for (const key of Object.keys(bag)) {
    if (key === "level" || key === "message" || key === "timestamp" || key === "stack") {
      continue;
    }
    bag[key] = SENSITIVE_KEY_RE.test(key)
      ? "[redacted]"
      : redactValue(bag[key], 0);
  }
  return info;
});

export const logger = winston.createLogger({
  level: config.logLevel,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    redact(),
    winston.format.json(),
  ),
  transports: [new winston.transports.Console()],
});
