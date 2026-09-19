#!/usr/bin/env node
// raysieve — feed it proxy URIs, get back only the ones that actually work,
// renamed to their real exit location. Zero dependencies; downloads xray /
// sing-box cores automatically on first run.
import { run } from '../src/cli.js';

run(process.argv.slice(2)).catch((e) => {
  console.error('raysieve: fatal:', e?.stack || e);
  process.exit(1);
});
