#!/usr/bin/env bun
import { Command } from "commander";
import { base58Encode, base58Decode } from "./encode";
import { readPublicKey, appendAuthorizedKey } from "./ssh";

const program = new Command();

program
  .name("diz")
  .description("Share SSH public keys between machines via a compact passphrase")
  .version("0.1.0");

program
  .option("-c, --connect", "Encode your SSH public key into a passphrase and print it")
  .option("-r, --receive <passphrase>", "Decode a passphrase and add the key to authorized_keys");

program.parse(process.argv);

const opts = program.opts<{ connect?: boolean; receive?: string }>();

if (opts.connect) {
  try {
    const keyLine = readPublicKey();
    const bytes = new TextEncoder().encode(keyLine);
    const passphrase = base58Encode(bytes);
    console.log(passphrase);
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
