// Base58 encoding/decoding (Bitcoin alphabet)
const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = BigInt(58);

export function base58Encode(bytes: Uint8Array): string {
  // Count leading zero bytes
  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeros++;
  }

  // Convert bytes to a big integer
  let num = BigInt(0);
  for (const byte of bytes) {
    num = num * BigInt(256) + BigInt(byte);
  }

  // Convert to base58 digits
  const digits: number[] = [];
  while (num > BigInt(0)) {
    const remainder = num % BASE;
    digits.push(Number(remainder));
    num = num / BASE;
  }

  // Build the result string: leading '1's for zero bytes, then digits in reverse
  return (
    "1".repeat(leadingZeros) +
    digits
      .reverse()
      .map((d) => ALPHABET[d])
      .join("")
  );
}

export function base58Decode(str: string): Uint8Array {
  // Count leading '1' characters (represent zero bytes)
  let leadingZeros = 0;
  for (const char of str) {
    if (char !== "1") break;
    leadingZeros++;
  }

  // Convert base58 string to a big integer
  let num = BigInt(0);
  for (const char of str) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base58 character: '${char}'`);
    }
    num = num * BASE + BigInt(index);
  }

  // Convert big integer to bytes
  const bytes: number[] = [];
  while (num > BigInt(0)) {
    bytes.push(Number(num % BigInt(256)));
    num = num / BigInt(256);
  }

  // Prepend leading zero bytes and reverse
  const result = new Uint8Array(leadingZeros + bytes.length);
  bytes.reverse().forEach((b, i) => {
    result[leadingZeros + i] = b;
  });

  return result;
}
