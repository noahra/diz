import { base58Decode } from "./encode";
import { readPublicKey } from "./ssh";

/**
 * Decodes the base58 code to "ip:port", sends the local public key to the
 * TCP server, waits for "OK <username>", then spawns an interactive SSH session.
 */
export async function connect(code: string): Promise<void> {
  const decoded = new TextDecoder().decode(base58Decode(code));
  const lastColon = decoded.lastIndexOf(":");
  if (lastColon === -1) {
    throw new Error(`Invalid code: could not parse "ip:port" from "${decoded}"`);
  }
  const ip = decoded.slice(0, lastColon);
  const port = parseInt(decoded.slice(lastColon + 1), 10);
  if (isNaN(port)) {
    throw new Error(`Invalid port in decoded code: "${decoded}"`);
  }

  const keyLine = readPublicKey();

  const response = await new Promise<string>((resolve, reject) => {
    Bun.connect<{ buf: string }>({
      hostname: ip,
      port,
      socket: {
        open(socket) {
          socket.data = { buf: "" };
          socket.write(keyLine + "\n");
        },
        data(socket, chunk) {
          socket.data.buf += new TextDecoder().decode(chunk);

          const newlineIdx = socket.data.buf.indexOf("\n");
          if (newlineIdx === -1) return; // haven't received full response yet

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
