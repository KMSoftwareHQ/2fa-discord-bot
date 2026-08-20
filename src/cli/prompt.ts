/**
 * Reading secret material from a human, without it ever touching argv.
 *
 * A `--secret` flag would put the seed in shell history, in `ps` output for
 * every user on the host, and in tmux scrollback. There is deliberately no such
 * flag; see readSeedInput's rejection message in cli.ts.
 */

/** Read a line from a TTY without echoing it. Returns a Buffer, never a string. */
function readHiddenFromTty(promptText: string): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    process.stderr.write(promptText);

    const chunks: number[] = [];
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();

    const cleanup = (): void => {
      stdin.setRawMode(wasRaw ?? false);
      stdin.pause();
      stdin.removeListener("data", onData);
    };

    const onData = (data: Buffer): void => {
      for (const byte of data) {
        switch (byte) {
          case 0x03: // Ctrl-C
            cleanup();
            process.stderr.write("\n");
            process.exit(130);
            return;
          case 0x04: // Ctrl-D
            if (chunks.length === 0) {
              cleanup();
              process.stderr.write("\n");
              reject(new Error("No input"));
              return;
            }
            break;
          case 0x0d: // CR
          case 0x0a: // LF
            cleanup();
            process.stderr.write("\n");
            resolve(Buffer.from(chunks));
            return;
          case 0x7f: // Backspace
          case 0x08:
            chunks.pop();
            break;
          default:
            if (byte >= 0x20) chunks.push(byte);
        }
      }
    };

    stdin.on("data", onData);
    stdin.on("error", (err) => {
      cleanup();
      reject(err);
    });
  });
}

/** Read everything from a pipe. Supports `pass show x | vault add x`. */
function readAllFromPipe(): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (c: Buffer) => chunks.push(c));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks)));
    process.stdin.on("error", reject);
  });
}

/**
 * Read a seed or otpauth:// URI, from a hidden TTY prompt or from a pipe.
 *
 * The result is a Buffer so it can be wiped. It necessarily becomes a string
 * once it reaches otplib, which is documented in SECURITY.md.
 */
export async function readSeedInput(promptText: string): Promise<Buffer> {
  const raw = process.stdin.isTTY
    ? await readHiddenFromTty(promptText)
    : await readAllFromPipe();

  // Trim surrounding whitespace and any trailing newline from the pipe form,
  // in place, without creating an untracked string copy of the secret.
  let start = 0;
  let end = raw.length;
  const isSpace = (b: number): boolean =>
    b === 0x20 || b === 0x09 || b === 0x0a || b === 0x0d;
  while (start < end && isSpace(raw[start] ?? 0)) start += 1;
  while (end > start && isSpace(raw[end - 1] ?? 0)) end -= 1;

  const trimmed = Buffer.from(raw.subarray(start, end));
  raw.fill(0);
  if (trimmed.length === 0) {
    throw new Error("No input provided");
  }
  return trimmed;
}

/** A yes/no confirmation on stderr, so stdout stays pipeable. */
export async function confirm(question: string): Promise<boolean> {
  if (!process.stdin.isTTY) return false;
  process.stderr.write(`${question} [y/N] `);
  const answer = await new Promise<string>((resolve) => {
    process.stdin.resume();
    process.stdin.once("data", (d: Buffer) => {
      process.stdin.pause();
      resolve(d.toString("utf8").trim().toLowerCase());
    });
  });
  return answer === "y" || answer === "yes";
}
