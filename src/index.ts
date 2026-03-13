#!/usr/bin/env bun
import { Command } from "commander";
import { base58Encode, base58Decode } from "./encode";
import { readPublicKey, appendAuthorizedKey, generateKey } from "./ssh";
import { listen } from "./listen";
import { connect } from "./connect";

const program = new Command();

program
  .name("diz")
  .description("Share SSH public keys between machines via a compact passphrase")
  .version("0.1.0");

program
  .option("-gk, --generate-key", "Generate a new ~/.ssh/id_ed25519 key pair")
  .option("-l, --listen", "Start a TCP server to receive a client's public key (run on server)")
  .option("-c, --connect <code>", "Connect to a listening server using its share code (run on client)")
  .option("-r, --receive <passphrase>", "Decode a passphrase and add the key to authorized_keys");

program.parse(process.argv);

const opts = program.opts<{
  generateKey?: boolean;
  listen?: boolean;
  connect?: string;
  receive?: string;
}>();

if (opts.generateKey) {
  try {
    const pubKey = await generateKey();
    const bytes = new TextEncoder().encode(pubKey);
    const passphrase = base58Encode(bytes);
    console.log(passphrase);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
} else if (opts.listen) {
  try {
    await listen();
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
} else if (opts.connect !== undefined) {
  try {
    await connect(opts.connect);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
} else if (opts.receive !== undefined) {
  try {
    const bytes = base58Decode(opts.receive);
    const keyLine = new TextDecoder().decode(bytes);
    appendAuthorizedKey(keyLine);
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }
} else {
  program.help();
}
