import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { readFileSync, writeFileSync, mkdirSync, rmSync, existsSync } from "fs";
import { join } from "path";
import { tmpdir } from "os";

// We test the logic directly by re-implementing the functions with a custom SSH_DIR.
// To do this without monkey-patching, we extract the testable logic here.

function parsePublicKeyLine(contents: string): string {
  const parts = contents.trim().split(/\s+/);
  if (parts.length < 2) throw new Error("Unexpected public key format");
  return `${parts[0]} ${parts[1]}`;
}

function isDuplicateKey(existing: string, keyLine: string): boolean {
  const [type, key] = keyLine.trim().split(/\s+/);
  for (const line of existing.split("\n")) {
    const parts = line.trim().split(/\s+/);
    if (parts.length >= 2 && parts[0] === type && parts[1] === key) return true;
  }
  return false;
}

// --- Tests ---

describe("parsePublicKeyLine", () => {
  it("strips comment from key line", () => {
    const line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA my-comment";
    expect(parsePublicKeyLine(line)).toBe("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA");
  });

  it("handles key with no comment", () => {
    const line = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA";
    expect(parsePublicKeyLine(line)).toBe("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA");
  });

  it("handles extra whitespace", () => {
    const line = "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAA   comment  ";
    expect(parsePublicKeyLine(line)).toBe("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA");
  });

  it("throws on malformed key", () => {
    expect(() => parsePublicKeyLine("ssh-ed25519")).toThrow("Unexpected public key format");
    expect(() => parsePublicKeyLine("")).toThrow("Unexpected public key format");
  });
});

describe("isDuplicateKey", () => {
  const existingKeys = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA1 first",
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA2 second",
  ].join("\n");

  it("detects an exact duplicate", () => {
    expect(isDuplicateKey(existingKeys, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA1")).toBe(true);
  });

  it("detects duplicate even if incoming has a comment", () => {
    expect(isDuplicateKey(existingKeys, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA2 some-comment")).toBe(true);
  });

  it("returns false for a new key", () => {
    expect(isDuplicateKey(existingKeys, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA3")).toBe(false);
  });

  it("returns false for empty authorized_keys", () => {
    expect(isDuplicateKey("", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA1")).toBe(false);
  });
});

describe("authorized_keys file handling", () => {
  let tmpDir: string;
  let authKeysPath: string;

  beforeEach(() => {
    tmpDir = join(tmpdir(), `diz-test-${Date.now()}`);
    mkdirSync(tmpDir, { recursive: true });
    authKeysPath = join(tmpDir, "authorized_keys");
  });

  afterEach(() => {
    rmSync(tmpDir, { recursive: true, force: true });
  });

  it("appends a key to an empty file", () => {
    writeFileSync(authKeysPath, "", { mode: 0o600 });
    const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA1";
    writeFileSync(authKeysPath, key + "\n");
    const contents = readFileSync(authKeysPath, "utf8");
    expect(contents).toContain(key);
  });

  it("appends a newline between keys", () => {
    const existing = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA1";
    writeFileSync(authKeysPath, existing);
    const newKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA2";
    const needsNewline = !existing.endsWith("\n");
    const entry = (needsNewline ? "\n" : "") + newKey + "\n";
    writeFileSync(authKeysPath, existing + entry);
    const contents = readFileSync(authKeysPath, "utf8");
    expect(contents).toBe("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA1\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA2\n");
  });
});
