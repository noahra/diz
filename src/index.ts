#!/usr/bin/env bun
import { Command } from "commander";
import { listen } from "./listen";
import { connect } from "./connect";

const program = new Command();

program
  .name("diz")
  .description(
    "Share SSH public keys between machines via a compact passphrase",
  )
  .version("0.1.0");

program
  .option(
    "-l, --listen",
    "Start a TCP server to receive a client's public key (run on server)",
  )
  .option(
    "-c, --connect <code>",
    "Connect to a listening server using its share code (run on client)",
  );

program.parse(process.argv);

const opts = program.opts<{
  listen?: boolean;
  connect?: string;
}>();

if (opts.listen) {
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
} else {
  program.help();
}
