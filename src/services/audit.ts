import type { VaultDatabase } from "../db";

/**
 * The audit trail.
 *
 * Note the deliberate asymmetry with the user-facing denial message: a denied
 * request replies with a sentence that names nothing, but records the REAL
 * requested name here. The requester learns nothing; the operator learns
 * everything. That asymmetry is the whole reason for having both.
 *
 * The field set is fixed rather than an open `Record<string, unknown>`. That is
 * a containment decision, not a style one: with an open object, some future
 * caller eventually writes `{ ...secret }` into it and the seed lands in the
 * audit table forever. There is no parameter here that can carry one.
 */

export type AuditOutcome =
  | "allowed"
  | "denied"
  | "not_found"
  | "rate_limited"
  | "error";

export interface AuditEvent {
  /** "discord:<snowflake>" or "cli:<os user>" */
  actor: string;
  /** Best-effort human label at the time of the request. */
  actorLabel?: string;
  command: string;
  /** The real name requested, even when the reply was a uniform denial. */
  secretName?: string | null;
  outcome: AuditOutcome;
  /** Short, machine-ish. Never seed material, never an issued code. */
  detail?: string;
  /** "dm" or the guild id. */
  context?: string;
}

export interface AuditRow extends AuditEvent {
  id: number;
  ts: number;
}

/**
 * Written synchronously, before the credential is handed over.
 *
 * Fire-and-forget logging is fine for a notification. An audit record that can
 * be lost to a crash between issuing a credential and recording it is not an
 * audit record. better-sqlite3 is synchronous, so this costs microseconds.
 */
export function recordAudit(
  db: VaultDatabase,
  event: AuditEvent,
  nowMs: number = Date.now(),
): void {
  db.prepare(
    `INSERT INTO audit_log
       (ts, actor, actor_label, command, secret_name, outcome, detail, context)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  ).run(
    nowMs,
    event.actor,
    event.actorLabel ?? "",
    event.command,
    event.secretName ?? null,
    event.outcome,
    event.detail ?? "",
    event.context ?? "",
  );
}

export interface AuditQuery {
  actor?: string;
  secretName?: string;
  sinceMs?: number;
  limit?: number;
}

export function queryAudit(db: VaultDatabase, query: AuditQuery = {}): AuditRow[] {
  const where: string[] = [];
  const params: (string | number)[] = [];

  if (query.actor) {
    // Accept a bare snowflake as well as the full "discord:<id>" form.
    where.push("(actor = ? OR actor = ?)");
    params.push(query.actor, `discord:${query.actor}`);
  }
  if (query.secretName) {
    where.push("secret_name = ?");
    params.push(query.secretName);
  }
  if (query.sinceMs !== undefined) {
    where.push("ts >= ?");
    params.push(query.sinceMs);
  }

  const sql =
    `SELECT id, ts, actor, actor_label, command, secret_name, outcome, detail, context
       FROM audit_log
      ${where.length ? `WHERE ${where.join(" AND ")}` : ""}
      ORDER BY ts DESC, id DESC
      LIMIT ?`;
  params.push(query.limit ?? 50);

  const rows = db.prepare(sql).all(...params) as Array<{
    id: number;
    ts: number;
    actor: string;
    actor_label: string;
    command: string;
    secret_name: string | null;
    outcome: string;
    detail: string;
    context: string;
  }>;

  return rows.map((r) => ({
    id: r.id,
    ts: r.ts,
    actor: r.actor,
    actorLabel: r.actor_label,
    command: r.command,
    secretName: r.secret_name,
    outcome: r.outcome as AuditOutcome,
    detail: r.detail,
    context: r.context,
  }));
}

export function purgeAuditOlderThan(db: VaultDatabase, cutoffMs: number): number {
  return db.prepare("DELETE FROM audit_log WHERE ts < ?").run(cutoffMs).changes;
}
