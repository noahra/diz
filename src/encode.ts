const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE = 58n;

export function base58Encode(bytes: Uint8Array): string {
  let leadingZeros = 0;
  for (const byte of bytes) {
    if (byte !== 0) break;
    leadingZeros++;
  }

  let num = 0n;
  for (const byte of bytes) {
    num = num * 256n + BigInt(byte);
  }

  const digits: number[] = [];
  while (num > 0n) {
    digits.push(Number(num % BASE));
    num /= BASE;
  }

  return (
    "1".repeat(leadingZeros) +
    digits
      .reverse()
      .map((d) => ALPHABET[d])
      .join("")
  );
}

export function base58Decode(str: string): Uint8Array {
  let leadingZeros = 0;
  for (const char of str) {
    if (char !== "1") break;
    leadingZeros++;
  }

  let num = 0n;
  for (const char of str) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) {
      throw new Error(`Invalid base58 character: '${char}'`);
    }
    num = num * BASE + BigInt(index);
  }

  const bytes: number[] = [];
  while (num > 0n) {
    bytes.push(Number(num % 256n));
    num /= 256n;
  }

  const result = new Uint8Array(leadingZeros + bytes.length);
  bytes.reverse().forEach((b, i) => {
    result[leadingZeros + i] = b;
  });

  return result;
}
