import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from "fs";
import { homedir } from "os";
import { join } from "path";

const SSH_DIR = join(homedir(), ".ssh");
const PUBKEY_PATH = join(SSH_DIR, "id_ed25519.pub");
const AUTHORIZED_KEYS_PATH = join(SSH_DIR, "authorized_keys");

/**
 * Reads ~/.ssh/id_ed25519.pub and returns the key without the comment.
 * Format: "ssh-ed25519 <base64>"
 */
export function readPublicKey(): string {
  if (!existsSync(PUBKEY_PATH)) {
    throw new Error(`Public key not found at ${PUBKEY_PATH}`);
  }

  const contents = readFileSync(PUBKEY_PATH, "utf8").trim();

  // Split into parts: ["ssh-ed25519", "<base64>", "<optional-comment>"]
  const parts = contents.split(/\s+/);
  if (parts.length < 2) {
    throw new Error(`Unexpected public key format in ${PUBKEY_PATH}`);
  }

  // Return only type + key, strip comment
  return `${parts[0]} ${parts[1]}`;
}

/**
 * Appends a public key line to ~/.ssh/authorized_keys.
 * Creates ~/.ssh/ (mode 700) and authorized_keys (mode 600) if they don't exist.
 * Skips if the key is already present.
 */
export function appendAuthorizedKey(keyLine: string): void {
  // Ensure ~/.ssh exists with correct permissions
  if (!existsSync(SSH_DIR)) {
    mkdirSync(SSH_DIR, { recursive: true });
    chmodSync(SSH_DIR, 0o700);
  }

  // Normalize the incoming key line (strip comment if any slipped through)
  const parts = keyLine.trim().split(/\s+/);
  if (parts.length < 2) {
    throw new Error("Invalid key line format");
  }
  const normalizedKey = `${parts[0]} ${parts[1]}`;

  // Check for duplicate
  if (existsSync(AUTHORIZED_KEYS_PATH)) {
    const existing = readFileSync(AUTHORIZED_KEYS_PATH, "utf8");
    for (const line of existing.split("\n")) {
      const lineParts = line.trim().split(/\s+/);
      if (lineParts.length >= 2) {
        const normalizedLine = `${lineParts[0]} ${lineParts[1]}`;
        if (normalizedLine === normalizedKey) {
          console.log("Key is already present in authorized_keys. Nothing to do.");
          return;
        }
      }
    }
  } else {
    // Create the file with correct permissions
    writeFileSync(AUTHORIZED_KEYS_PATH, "", { mode: 0o600 });
  }

  // Append the key, ensuring it ends with a newline
  const existing = readFileSync(AUTHORIZED_KEYS_PATH, "utf8");
  const needsNewline = existing.length > 0 && !existing.endsWith("\n");
  const entry = (needsNewline ? "\n" : "") + normalizedKey + "\n";

  writeFileSync(AUTHORIZED_KEYS_PATH, existing + entry, { mode: 0o600 });
  chmodSync(AUTHORIZED_KEYS_PATH, 0o600);

  console.log(`Public key added to ${AUTHORIZED_KEYS_PATH}`);
}
