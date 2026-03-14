import { base58Decode } from "./encode";
import { readPublicKey, generateKey } from "./ssh";
import { existsSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { createHash } from "crypto";

/**
 * Decodes the base58 code to "ip:port:token:fingerprint", connects to the TLS
 * server using a two-step handshake, verifies the certificate fingerprint,
 * sends the local public key, waits for "OK <username>", then spawns an
 * interactive SSH session.
 */
function decodeCode(code: string): {
  ip: string;
  port: number;
  token: string;
  fingerprint: string;
} {
  // Binary packet: [4 bytes IP][2 bytes port][16 bytes token][32 bytes fingerprint]
  const packet = base58Decode(code);
  if (packet.length !== 54) {
    throw new Error("Invalid code format.");
  }
  const ip = `${packet[0]}.${packet[1]}.${packet[2]}.${packet[3]}`;
  const port = (packet[4] << 8) | packet[5];
  const token = Buffer.from(packet.slice(6, 22)).toString("hex");
  const fingerprint = Buffer.from(packet.slice(22, 54)).toString("hex");
  return { ip, port, token, fingerprint };
}

/**
 * Step 1: Connect with rejectUnauthorized: false and retrieve the cert PEM
 * from the server's "CERT <fingerprintHex> <certPemBase64>" message.
 * Verifies the SHA-256 fingerprint of the DER-encoded cert against the
 * fingerprint embedded in the share code. Aborts on mismatch.
 */
function retrieveAndVerifyCert(
  ip: string,
  port: number,
  fingerprint: string,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    Bun.connect<{ buf: string }>({
      hostname: ip,
      port,
      tls: {
        // rejectUnauthorized is false only for cert retrieval. The received cert
        // PEM is verified against the SHA-256 fingerprint embedded in the share
        // code before any credentials are sent.
        rejectUnauthorized: false,
      },
      socket: {
        open(socket) {
          socket.data = { buf: "" };
        },
        data(socket, chunk) {
          socket.data.buf += new TextDecoder().decode(chunk);

          const newlineIdx = socket.data.buf.indexOf("\n");
          if (newlineIdx === -1) return;

          const line = socket.data.buf.slice(0, newlineIdx).trim();

          // Expect "CERT <fingerprintHex> <certPemBase64>"
          if (!line.startsWith("CERT ")) {
            socket.end();
            reject(new Error("Expected CERT message from server."));
            return;
          }

          const parts = line.slice(5).trim().split(" ");
          if (parts.length !== 2) {
            socket.end();
            reject(
              new Error(
                "Malformed CERT message: expected fingerprint and PEM.",
              ),
            );
            return;
          }

          const [serverFingerprint, certPemBase64] = parts;
          const certPem = Buffer.from(certPemBase64, "base64").toString("utf8");

          // Verify fingerprint: SHA-256 of the DER-encoded cert
          const derBase64 = certPem
            .replace(/-----[^-]+-----/g, "")
            .replace(/\s/g, "");
          const derBytes = Buffer.from(derBase64, "base64");
          const computedFingerprint = createHash("sha256")
            .update(derBytes)
            .digest("hex");

          if (computedFingerprint !== fingerprint) {
            socket.end();
            reject(
              new Error(
                "Certificate fingerprint mismatch — possible MITM attack",
              ),
            );
            return;
          }

          // Fingerprint verified — the server will close this connection
          socket.end();
          resolve(certPem);
        },
        error(_socket, err) {
          reject(err);
        },
        close() {},
      },
    }).catch(reject);
  });
}

/**
 * Step 2: Reconnect with rejectUnauthorized: true and ca set to the verified
 * cert PEM. Send the token and public key, wait for "OK <username>".
 */
function exchangeKey(
  ip: string,
  port: number,
  certPem: string,
  token: string,
  keyLine: string,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    Bun.connect<{ buf: string }>({
      hostname: ip,
      port,
      tls: {
        rejectUnauthorized: true,
        ca: certPem,
      },
      socket: {
        open(socket) {
          socket.data = { buf: "" };
          // Send token and public key immediately upon connection
          socket.write(`${token} ${keyLine}\n`);
        },
        data(socket, chunk) {
          socket.data.buf += new TextDecoder().decode(chunk);

          const newlineIdx = socket.data.buf.indexOf("\n");
          if (newlineIdx === -1) return;

          const line = socket.data.buf.slice(0, newlineIdx).trim();
          socket.end();
          resolve(line);
        },
        error(_socket, err) {
          reject(err);
        },
        close() {},
      },
    }).catch(reject);
  });
}

export async function connect(code: string, temp = false): Promise<void> {
  const { ip, port, token, fingerprint } = decodeCode(code);

  const privKeyPath = join(homedir(), ".ssh", "id_ed25519");
  const pubKeyPath = join(homedir(), ".ssh", "id_ed25519.pub");
  const keyExistedBefore = existsSync(privKeyPath);

  if (!keyExistedBefore) {
    console.log("No SSH key found, generating one...");
    await generateKey();
  }

  const keyLine = readPublicKey();

  // Step 1: retrieve and verify the server's certificate
  const certPem = await retrieveAndVerifyCert(ip, port, fingerprint);

  // Step 2: reconnect with full TLS verification and exchange the key
  const response = await exchangeKey(ip, port, certPem, token, keyLine);

  if (!response.startsWith("OK ")) {
    throw new Error(`Unexpected server response: "${response}"`);
  }

  const username = response.slice(3).trim();
  console.log(`Connected! Logging in as ${username}@${ip}...`);

  const ssh = Bun.spawn(["ssh", `${username}@${ip}`], {
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  });
  await ssh.exited;

  if (temp && !keyExistedBefore) {
    unlinkSync(privKeyPath);
    if (existsSync(pubKeyPath)) unlinkSync(pubKeyPath);
    console.log("Temporary session ended. SSH keys deleted.");
  }
}
