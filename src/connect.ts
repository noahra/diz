import { base58Decode } from "./encode";
import { readPublicKey, generateKey } from "./ssh";
import { existsSync } from "fs";
import { join } from "path";
import { homedir } from "os";

/**
 * Decodes the base58 code to "ip:port:token:fingerprint", connects to the TLS
 * server, verifies the certificate fingerprint, sends the local public key,
 * waits for "OK <username>", then spawns an interactive SSH session.
 */
export async function connect(code: string): Promise<void> {
  const decoded = new TextDecoder().decode(base58Decode(code));
  const parts = decoded.split(":");

  // Format: ip:port:token:fingerprint
  // ip may contain colons (IPv6), so fingerprint is last, token second-to-last,
  // port third-to-last, ip is everything before that.
  if (parts.length < 4) {
    throw new Error(`Invalid code format.`);
  }

  const fingerprint = parts[parts.length - 1];
  const token = parts[parts.length - 2];
  const port = parseInt(parts[parts.length - 3], 10);
  const ip = parts.slice(0, parts.length - 3).join(":");

  if (isNaN(port)) {
    throw new Error(`Invalid port in code.`);
  }

  if (fingerprint.length !== 64) {
    throw new Error(`Invalid fingerprint in code.`);
  }

  if (!existsSync(join(homedir(), ".ssh", "id_ed25519"))) {
    console.log("No SSH key found, generating one...");
    await generateKey();
  }

  const keyLine = readPublicKey();

  const response = await new Promise<string>((resolve, reject) => {
    Bun.connect<{ buf: string; certVerified: boolean }>({
      hostname: ip,
      port,
      tls: {
        rejectUnauthorized: false,
      },
      socket: {
        open(socket) {
          socket.data = { buf: "", certVerified: false };
        },
        data(socket, chunk) {
          socket.data.buf += new TextDecoder().decode(chunk);

          // Process all complete lines in the buffer
          let newlineIdx: number;
          while ((newlineIdx = socket.data.buf.indexOf("\n")) !== -1) {
            const line = socket.data.buf.slice(0, newlineIdx).trim();
            socket.data.buf = socket.data.buf.slice(newlineIdx + 1);

            if (!socket.data.certVerified) {
              // Expect "CERT <fingerprint>" as the first message
              if (!line.startsWith("CERT ")) {
                socket.end();
                reject(new Error("Expected CERT message from server."));
                return;
              }
              const serverFingerprint = line.slice(5).trim();
              if (serverFingerprint !== fingerprint) {
                socket.end();
                reject(new Error("Certificate fingerprint mismatch — possible MITM attack"));
                return;
              }
              socket.data.certVerified = true;
              // Fingerprint verified — send token and public key
              socket.write(`${token} ${keyLine}\n`);
            } else {
              // This is the "OK <username>" response
              socket.end();
              resolve(line);
              return;
            }
          }
        },
        error(_socket, err) {
          reject(err);
        },
        close() {},
      },
    }).catch(reject);
  });

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
}
