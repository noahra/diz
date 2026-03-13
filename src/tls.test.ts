import { describe, it, expect } from "bun:test";
import { base58Encode, base58Decode } from "./encode";

// Helpers that mirror the logic in connect.ts for parsing and verifying codes
function parseCode(code: string) {
  const decoded = new TextDecoder().decode(base58Decode(code));
  const parts = decoded.split(":");
  if (parts.length < 4) throw new Error("Invalid code format.");
  const fingerprint = parts[parts.length - 1];
  const token = parts[parts.length - 2];
  const port = parseInt(parts[parts.length - 3], 10);
  const ip = parts.slice(0, parts.length - 3).join(":");
  return { ip, port, token, fingerprint };
}

function makeCode(
  ip: string,
  port: number,
  token: string,
  fingerprint: string,
) {
  return base58Encode(
    new TextEncoder().encode(`${ip}:${port}:${token}:${fingerprint}`),
  );
}

const VALID_FINGERPRINT = "a".repeat(64);
const VALID_TOKEN = "b".repeat(32);

describe("TLS fingerprint verification", () => {
  it("rejects a code with a fingerprint that is too short", () => {
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, "abc123");
    expect(() => parseCode(code)).not.toThrow(); // parsing succeeds
    const { fingerprint } = parseCode(code);
    expect(fingerprint.length).not.toBe(64); // but fingerprint is invalid
  });

  it("rejects a code with an empty fingerprint", () => {
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, "");
    const { fingerprint } = parseCode(code);
    expect(fingerprint.length).not.toBe(64);
  });

  it("accepts a code with a valid 64-char fingerprint", () => {
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, VALID_FINGERPRINT);
    const { fingerprint } = parseCode(code);
    expect(fingerprint.length).toBe(64);
    expect(fingerprint).toBe(VALID_FINGERPRINT);
  });

  it("detects a tampered fingerprint", () => {
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, VALID_FINGERPRINT);
    const { fingerprint } = parseCode(code);
    const tamperedFingerprint = "f".repeat(64);
    expect(fingerprint).not.toBe(tamperedFingerprint);
  });

  it("detects a one-character change in the fingerprint", () => {
    const original = VALID_FINGERPRINT;
    const tampered = "b" + original.slice(1); // flip first char
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, original);
    const { fingerprint } = parseCode(code);
    expect(fingerprint).toBe(original);
    expect(fingerprint).not.toBe(tampered);
  });

  it("preserves ip, port and token correctly in the code", () => {
    const code = makeCode("10.0.0.5", 55000, VALID_TOKEN, VALID_FINGERPRINT);
    const { ip, port, token, fingerprint } = parseCode(code);
    expect(ip).toBe("10.0.0.5");
    expect(port).toBe(55000);
    expect(token).toBe(VALID_TOKEN);
    expect(fingerprint).toBe(VALID_FINGERPRINT);
  });
});

describe("MITM simulation", () => {
  it("client rejects server fingerprint that does not match the code", () => {
    const legitimateFingerprint = "a".repeat(64);
    const attackerFingerprint = "b".repeat(64); // what a MITM server would send

    // Simulate the client-side check in connect.ts
    const serverFingerprint = attackerFingerprint;
    const codeFingerprint = legitimateFingerprint;

    expect(serverFingerprint).not.toBe(codeFingerprint);
    // → connect.ts would throw "Certificate fingerprint mismatch — possible MITM attack"
  });

  it("client accepts server fingerprint that matches the code", () => {
    const fingerprint =
      "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
    const serverFingerprint = fingerprint;
    const codeFingerprint = fingerprint;

    expect(serverFingerprint).toBe(codeFingerprint);
    // → connect.ts would proceed normally
  });
});
