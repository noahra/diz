import { base58Encode } from "./encode";
import { appendAuthorizedKey, getLocalIP, getUsername } from "./ssh";

const TIMEOUT_MS = 30_000;

function randomPort(): number {
  return Math.floor(Math.random() * (65535 - 49152) + 49152);
}

function randomToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Buffer.from(bytes).toString("hex");
}

/**
 * Starts a TCP server on a random port, waits up to 30s for one client
 * connection, verifies the one-time token, receives the client's public key,
 * adds it to authorized_keys, and responds with "OK <username>".
 */
function copyToClipboard(text: string): void {
  const cmd = process.platform === "darwin" ? "pbcopy" : "xclip -selection clipboard";
  const proc = Bun.spawnSync(cmd.split(" "), { stdin: new TextEncoder().encode(text) });
  if (proc.exitCode !== 0) throw new Error("Failed to copy to clipboard.");
}

export async function listen(pb = false): Promise<void> {
  const ip = getLocalIP();
  const token = randomToken();

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

  const code = base58Encode(
    new TextEncoder().encode(`${ip}:${port!}:${token}`),
  );
  console.log(`Share this code: ${code}`);
  if (pb) {
    copyToClipboard(code);
    console.log(`(copied to clipboard)`);
  }
  console.log(`Waiting for connection... (times out in 30s)`);

  await new Promise<void>((resolve, reject) => {
    const server = Bun.listen<{ buf: string }>({
      hostname: "0.0.0.0",
      port: port!,
      socket: {
        open(socket) {
          socket.data = { buf: "" };
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
}
