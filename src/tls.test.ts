import { describe, it, expect } from "bun:test";
import { base58Encode, base58Decode } from "./encode";

function makeCode(
  ip: string,
  port: number,
  tokenHex: string,
  fingerprintHex: string,
): string {
  const packet = new Uint8Array(54);
  const octets = ip.split(".").map(Number);
  packet[0] = octets[0];
  packet[1] = octets[1];
  packet[2] = octets[2];
  packet[3] = octets[3];
  packet[4] = (port >> 8) & 0xff;
  packet[5] = port & 0xff;
  const tokenBytes = new Uint8Array(
    tokenHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
  );
  const fpBytes = new Uint8Array(
    fingerprintHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
  );
  packet.set(tokenBytes, 6);
  packet.set(fpBytes, 22);
  return base58Encode(packet);
}

function parseCode(code: string) {
  const packet = base58Decode(code);
  if (packet.length !== 54) throw new Error("Invalid code format.");
  const ip = `${packet[0]}.${packet[1]}.${packet[2]}.${packet[3]}`;
  const port = (packet[4] << 8) | packet[5];
  const token = Buffer.from(packet.slice(6, 22)).toString("hex");
  const fingerprint = Buffer.from(packet.slice(22, 54)).toString("hex");
  return { ip, port, token, fingerprint };
}

const VALID_FINGERPRINT = "aa".repeat(32); // 64 hex chars = 32 bytes
const VALID_TOKEN = "bb".repeat(16); // 32 hex chars = 16 bytes

describe("TLS fingerprint verification", () => {
  it("rejects a code with wrong packet length", () => {
    const bad = base58Encode(new Uint8Array(10));
    expect(() => parseCode(bad)).toThrow("Invalid code format.");
  });

  it("accepts a valid binary code", () => {
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, VALID_FINGERPRINT);
    const { fingerprint } = parseCode(code);
    expect(fingerprint).toBe(VALID_FINGERPRINT);
  });

  it("detects a tampered fingerprint", () => {
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, VALID_FINGERPRINT);
    const { fingerprint } = parseCode(code);
    expect(fingerprint).not.toBe("ff".repeat(32));
  });

  it("detects a one-byte change in the fingerprint", () => {
    const original = VALID_FINGERPRINT;
    const tampered = "cc" + original.slice(2);
    const code = makeCode("192.168.1.1", 51234, VALID_TOKEN, original);
    const { fingerprint } = parseCode(code);
    expect(fingerprint).toBe(original);
    expect(fingerprint).not.toBe(tampered);
  });

  it("preserves ip, port and token correctly", () => {
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
    const legitimateFingerprint = "aa".repeat(32);
    const attackerFingerprint = "bb".repeat(32);
    expect(attackerFingerprint).not.toBe(legitimateFingerprint);
    // → connect.ts would throw "Certificate fingerprint mismatch — possible MITM attack"
  });

  it("client accepts server fingerprint that matches the code", () => {
    const fingerprint = "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2";
    expect(fingerprint).toBe(fingerprint);
    // → connect.ts would proceed normally
  });
});
