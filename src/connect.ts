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

// Single connection: receive the CERT from the server, verify its fingerprint
// against the share code, then send the token and public key on the same
// socket and wait for "OK <username>".
//
// Sending credentials over a rejectUnauthorized: false connection is safe here
// because we verify the fingerprint before writing anything — we know we are
// talking to the right machine.
function connectAndExchange(
  ip: string,
  port: number,
  fingerprint: string,
  token: string,
  keyLine: string,
): Promise<string> {
  return new Promise<string>((resolve, reject) => {
    Bun.connect<{ buf: string; certVerified: boolean }>({
      hostname: ip,
      port,
      tls: { rejectUnauthorized: false },
      socket: {
        open(socket) {
          socket.data = { buf: "", certVerified: false };
        },
        data(socket, chunk) {
          socket.data.buf += new TextDecoder().decode(chunk);

          const newlineIdx = socket.data.buf.indexOf("\n");
          if (newlineIdx === -1) return;

          const line = socket.data.buf.slice(0, newlineIdx).trim();
          socket.data.buf = socket.data.buf.slice(newlineIdx + 1);

          if (!socket.data.certVerified) {
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

            const certPem = Buffer.from(parts[1], "base64").toString("utf8");
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

            socket.data.certVerified = true;
            socket.write(`${token} ${keyLine}\n`);
            return;
          }

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
  const response = await connectAndExchange(
    ip,
    port,
    fingerprint,
    token,
    keyLine,
  );

  if (!response.startsWith("OK ")) {
    throw new Error(`Unexpected server response: "${response}"`);
  }

  const username = response.slice(3).trim();
  console.log(`Connected! Logging in as ${username}@${ip}...`);

  if (temp && !keyExistedBefore) {
    const ssh = Bun.spawn(["ssh", `${username}@${ip}`], {
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
    });
    await ssh.exited;
    unlinkSync(privKeyPath);
    if (existsSync(pubKeyPath)) unlinkSync(pubKeyPath);
    console.log("Temporary session ended. SSH keys deleted.");
  } else {
    Bun.spawnSync(["ssh", `${username}@${ip}`], {
      stdin: "inherit",
      stdout: "inherit",
      stderr: "inherit",
    });
  }
}
