/**
 * The one definition of a secret name, shared by the ACL, the database primary
 * key, and the crypto AAD.
 *
 * The character set is deliberately narrow. `crypto.ts` builds its AAD as
 * `v1|<name>`, which is only unambiguous because a name can never contain `|`.
 * Widening this regex without revisiting that is how you reintroduce the
 * row-swap attack the AAD exists to prevent.
 */
export const SECRET_NAME_RE = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function isValidSecretName(name: string): boolean {
  return SECRET_NAME_RE.test(name);
}

export function assertValidSecretName(name: string): void {
  if (!isValidSecretName(name)) {
    throw new Error(
      `Invalid secret name "${name}": use 1-64 characters, starting with a ` +
        `lowercase letter or digit, then lowercase letters, digits, dot, ` +
        `underscore or hyphen.`,
    );
  }
}

/** Discord snowflakes are 17-20 digits today; the format is stable. */
export const SNOWFLAKE_RE = /^\d{17,20}$/;

export function isValidSnowflake(value: string): boolean {
  return SNOWFLAKE_RE.test(value);
}
