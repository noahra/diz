import { base58Encode } from "./encode";
import { appendAuthorizedKey, getLocalIP, getUsername } from "./ssh";

/**
 * Starts a TCP server on port 7878, waits for one client connection,
 * receives the client's public key, adds it to authorized_keys, and
 * responds with "OK <username>".
 */
export async function listen(): Promise<void> {
  const ip = getLocalIP();
  const port = 7878;
  const code = base58Encode(new TextEncoder().encode(`${ip}:${port}`));
  console.log(`Share this code: ${code}`);

  await new Promise<void>((resolve, reject) => {
    const server = Bun.listen<{ buf: string }>({
      hostname: "0.0.0.0",
      port,
      socket: {
        open(socket) {
          socket.data = { buf: "" };
        },
        data(socket, chunk) {
          socket.data.buf += new TextDecoder().decode(chunk);

          const newlineIdx = socket.data.buf.indexOf("\n");
          if (newlineIdx === -1) return; // haven't received full line yet

          const keyLine = socket.data.buf.slice(0, newlineIdx).trim();

          try {
            appendAuthorizedKey(keyLine);
          } catch (err) {
            socket.end();
            server.stop(true);
            reject(err);
            return;
          }

          const username = getUsername();
          socket.write(`OK ${username}\n`);
          socket.end();
          server.stop(true);
          resolve();
        },
        error(_socket, err) {
          server.stop(true);
          reject(err);
        },
        close() {},
      },
    });
  });
}
