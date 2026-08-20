import type { VaultDatabase } from "../db";
import type { AclStore } from "../core/acl";

/**
 * Everything the Discord handlers need, passed explicitly rather than imported
 * as module state — which is what lets the vault core be tested without a
 * gateway connection.
 */
export interface BotContext {
  db: VaultDatabase;
  aclStore: AclStore;
  masterKey: Buffer;
  /** Empty means "no guild restriction". */
  guildId: string;
  /** Wait out the step boundary below this many seconds remaining. */
  minRemainingSeconds: number;
}
