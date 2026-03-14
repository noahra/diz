import { base58Decode } from "./encode";
import { readPublicKey, generateKey } from "./ssh";
import { existsSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";
import { createHash } from "crypto";

function decodeCode(code: string): {
  ip: string;
  port: number;
  token: string;
  fingerprint: string;
} {
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

// Step 1: connect with rejectUnauthorized: false to retrieve the server's cert
// PEM. The fingerprint is verified against the share code before any
// credentials are sent, so the insecure connection is safe at this stage.
function retrieveAndVerifyCert(
  ip: string,
  port: number,
  fingerprint: string,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    Bun.connect<{ buf: string }>({
      hostname: ip,
      port,
      tls: { rejectUnauthorized: false },
      socket: {
        open(socket) {
          socket.data = { buf: "" };
        },
        data(socket, chunk) {
          socket.data.buf += new TextDecoder().decode(chunk);

          const newlineIdx = socket.data.buf.indexOf("\n");
          if (newlineIdx === -1) return;

          const line = socket.data.buf.slice(0, newlineIdx).trim();

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

          const [, certPemBase64] = parts;
          const certPem = Buffer.from(certPemBase64, "base64").toString("utf8");

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

// Step 2: reconnect with full TLS verification using the pinned cert, then
// send the token and public key and wait for "OK <username>".
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
  const certPem = await retrieveAndVerifyCert(ip, port, fingerprint);
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
