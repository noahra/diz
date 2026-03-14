import { base58Decode } from "./encode";
import { readPublicKey, generateKey } from "./ssh";
import { existsSync, unlinkSync } from "fs";
import { join } from "path";
import { homedir } from "os";

/**
 * Decodes the base58 code to "ip:port:token:fingerprint", connects to the TLS
 * server, verifies the certificate fingerprint, sends the local public key,
 * waits for "OK <username>", then spawns an interactive SSH session.
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
                reject(
                  new Error(
                    "Certificate fingerprint mismatch — possible MITM attack",
                  ),
                );
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

  if (temp && !keyExistedBefore) {
    unlinkSync(privKeyPath);
    if (existsSync(pubKeyPath)) unlinkSync(pubKeyPath);
    console.log("Temporary session ended. SSH keys deleted.");
  }
}
