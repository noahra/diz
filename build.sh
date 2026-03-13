#!/usr/bin/env bash
set -euo pipefail
bun build --compile src/index.ts --outfile diz
