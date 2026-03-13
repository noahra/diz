import { base58Encode } from "./encode";
import { appendAuthorizedKey, getLocalIP, getUsername } from "./ssh";
import { readFileSync, unlinkSync, existsSync } from "fs";

const TIMEOUT_MS = 180_000;
const CERT_PATH = "/tmp/diz-cert.pem";
const KEY_PATH = "/tmp/diz-key.pem";

function randomPort(): number {
  return Math.floor(Math.random() * (65535 - 49152) + 49152);
}

function randomTokenBytes(): Uint8Array {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function encodeCode(
  ip: string,
  port: number,
  tokenBytes: Uint8Array,
  fingerprintBytes: Uint8Array,
): Uint8Array {
  // [4 bytes IP][2 bytes port big-endian][16 bytes token][32 bytes fingerprint]
  const packet = new Uint8Array(54);
  const octets = ip.split(".").map(Number);
  packet[0] = octets[0];
  packet[1] = octets[1];
  packet[2] = octets[2];
  packet[3] = octets[3];
  packet[4] = (port >> 8) & 0xff;
  packet[5] = port & 0xff;
  packet.set(tokenBytes, 6);
  packet.set(fingerprintBytes, 22);
  return packet;
}

function cleanupCerts(): void {
  if (existsSync(CERT_PATH)) {
    try {
      unlinkSync(CERT_PATH);
    } catch {}
  }
  if (existsSync(KEY_PATH)) {
    try {
      unlinkSync(KEY_PATH);
    } catch {}
  }
}

/**
 * Generates a temporary self-signed EC (P-256) certificate using openssl.
 * Returns { certPem, keyPem, fingerprint } where fingerprint is a 64-char lowercase hex string.
 */
function generateTLSCert(): {
  certPem: string;
  keyPem: string;
  fingerprintHex: string;
  fingerprintBytes: Uint8Array;
} {
  const genResult = Bun.spawnSync([
    "openssl",
    "req",
    "-x509",
    "-newkey",
    "ec",
    "-pkeyopt",
    "ec_paramgen_curve:P-256",
    "-keyout",
    KEY_PATH,
    "-out",
    CERT_PATH,
    "-days",
    "1",
    "-nodes",
    "-subj",
    "/CN=diz",
  ]);

  if (genResult.exitCode !== 0) {
    const errText = new TextDecoder().decode(genResult.stderr);
    throw new Error(`openssl cert generation failed: ${errText.trim()}`);
  }

  const certPem = readFileSync(CERT_PATH, "utf8");
  const keyPem = readFileSync(KEY_PATH, "utf8");

  const fpResult = Bun.spawnSync([
    "openssl",
    "x509",
    "-in",
    CERT_PATH,
    "-fingerprint",
    "-sha256",
    "-noout",
  ]);

  if (fpResult.exitCode !== 0) {
    const errText = new TextDecoder().decode(fpResult.stderr);
    throw new Error(`openssl fingerprint failed: ${errText.trim()}`);
  }

  // Output looks like: SHA256 Fingerprint=AA:BB:CC:...
  const fpOutput = new TextDecoder().decode(fpResult.stdout).trim();
  const eqIdx = fpOutput.indexOf("=");
  if (eqIdx === -1) {
    throw new Error(`Unexpected fingerprint output: ${fpOutput}`);
  }
  const fingerprintHex = fpOutput
    .slice(eqIdx + 1)
    .replace(/:/g, "")
    .toLowerCase();
  if (fingerprintHex.length !== 64) {
    throw new Error(`Unexpected fingerprint length: ${fingerprintHex}`);
  }
  const fingerprintBytes = new Uint8Array(
    fingerprintHex.match(/.{2}/g)!.map((b) => parseInt(b, 16)),
  );

  return { certPem, keyPem, fingerprintHex, fingerprintBytes };
}

/**
 * Copies text to the system clipboard.
 */
function copyToClipboard(text: string): void {
  const cmd =
    process.platform === "darwin" ? "pbcopy" : "xclip -selection clipboard";
  const proc = Bun.spawnSync(cmd.split(" "), {
    stdin: new TextEncoder().encode(text),
  });
  if (proc.exitCode !== 0) throw new Error("Failed to copy to clipboard.");
}

/**
 * Starts a TLS server on a random port, waits up to 3 minutes for one client
 * connection, verifies the one-time token, receives the client's public key,
 * adds it to authorized_keys, and responds with "OK <username>".
 *
 * The server first sends "CERT <fingerprint>\n" so the client can verify
 * the certificate before proceeding with the token exchange.
 */
export async function listen(pb = false): Promise<void> {
  let certPem: string;
  let keyPem: string;
  let fingerprintHex: string;
  let fingerprintBytes: Uint8Array;

  try {
    ({ certPem, keyPem, fingerprintHex, fingerprintBytes } =
      generateTLSCert());
  } catch (err) {
    cleanupCerts();
    throw err;
  }

  const ip = getLocalIP();
  const tokenBytes = randomTokenBytes();
  const token = bytesToHex(tokenBytes);

  // Find an available port before printing the code
  let port: number;
  for (let i = 0; i < 10; i++) {
    port = randomPort();
    try {
      // Try binding briefly to check availability
      const probe = Bun.listen<{ buf: string }>({
        hostname: "0.0.0.0",
        port,
        socket: { open() {}, data() {}, error() {}, close() {} },
      });
      probe.stop(true);
      break;
    } catch {
      if (i === 9)
        throw new Error("Could not find an available port after 10 attempts.");
    }
  }

  const code = base58Encode(encodeCode(ip, port!, tokenBytes, fingerprintBytes));
  console.log(`Share this code: ${code}`);
  if (pb) {
    copyToClipboard(code);
    console.log(`(copied to clipboard)`);
  }
  console.log(`Waiting for connection... (times out in 3 minutes)`);

  try {
    await new Promise<void>((resolve, reject) => {
      const server = Bun.listen<{ buf: string }>({
        hostname: "0.0.0.0",
        port: port!,
        tls: {
          cert: certPem,
          key: keyPem,
        },
        socket: {
          open(socket) {
            socket.data = { buf: "" };
            // Send fingerprint first so client can verify before token exchange
            socket.write(`CERT ${fingerprintHex}\n`);
          },
          data(socket, chunk) {
            socket.data.buf += new TextDecoder().decode(chunk);

            const newlineIdx = socket.data.buf.indexOf("\n");
            if (newlineIdx === -1) return;

            const line = socket.data.buf.slice(0, newlineIdx).trim();
            const spaceIdx = line.indexOf(" ");
            if (spaceIdx === -1) {
              socket.end();
              server.stop(true);
              reject(new Error("Malformed message from client."));
              return;
            }

            const receivedToken = line.slice(0, spaceIdx);
            const keyLine = line.slice(spaceIdx + 1);

            if (receivedToken !== token) {
              socket.end();
              server.stop(true);
              reject(new Error("Invalid token — connection rejected."));
              return;
            }

            try {
              appendAuthorizedKey(keyLine);
            } catch (err) {
              socket.end();
              server.stop(true);
              reject(err);
              return;
            }

            clearTimeout(timeout);
            const username = getUsername();
            socket.write(`OK ${username}\n`);
            socket.end();
            server.stop(true);
            resolve();
          },
          error(_socket, err) {
            clearTimeout(timeout);
            server.stop(true);
            reject(err);
          },
          close() {},
        },
      });

      const timeout = setTimeout(() => {
        server.stop(true);
        reject(new Error("Timed out after 30s — no client connected."));
      }, TIMEOUT_MS);
    });
  } finally {
    cleanupCerts();
  }
}
