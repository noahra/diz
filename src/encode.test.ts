import { describe, it, expect } from "bun:test";
import { base58Encode, base58Decode } from "./encode";

describe("base58Encode / base58Decode", () => {
  it("round-trips a simple string", () => {
    const input = new TextEncoder().encode("hello world");
    const encoded = base58Encode(input);
    const decoded = base58Decode(encoded);
    expect(new TextDecoder().decode(decoded)).toBe("hello world");
  });

  it("round-trips an SSH public key line", () => {
    const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBN9Bj7hTBxCOuHRn1kHPr0Lk8qBvBzIxXyZGz3eU+Fw";
    const input = new TextEncoder().encode(key);
    const encoded = base58Encode(input);
    const decoded = base58Decode(encoded);
    expect(new TextDecoder().decode(decoded)).toBe(key);
  });

  it("round-trips an ip:port:token string", () => {
    const input = new TextEncoder().encode("192.168.1.42:51234:abcdef1234567890abcdef1234567890");
    const encoded = base58Encode(input);
    const decoded = base58Decode(encoded);
    expect(new TextDecoder().decode(decoded)).toBe("192.168.1.42:51234:abcdef1234567890abcdef1234567890");
  });

  it("handles leading zero bytes", () => {
    const input = new Uint8Array([0, 0, 1, 2, 3]);
    const encoded = base58Encode(input);
    expect(encoded.startsWith("11")).toBe(true);
    const decoded = base58Decode(encoded);
    expect(decoded).toEqual(input);
  });

  it("handles empty input", () => {
    const input = new Uint8Array([]);
    const encoded = base58Encode(input);
    expect(encoded).toBe("");
    const decoded = base58Decode(encoded);
    expect(decoded).toEqual(input);
  });

  it("only uses valid base58 alphabet characters", () => {
    const input = new TextEncoder().encode("test string 123");
    const encoded = base58Encode(input);
    expect(encoded).toMatch(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]*$/);
  });

  it("throws on invalid base58 character", () => {
    expect(() => base58Decode("invalid!char")).toThrow("Invalid base58 character");
  });

  it("throws on character not in alphabet (0, O, I, l)", () => {
    expect(() => base58Decode("0abc")).toThrow("Invalid base58 character");
    expect(() => base58Decode("Oabc")).toThrow("Invalid base58 character");
    expect(() => base58Decode("Iabc")).toThrow("Invalid base58 character");
    expect(() => base58Decode("labc")).toThrow("Invalid base58 character");
  });
});
