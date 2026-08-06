#!/usr/bin/env node
// client-recon CLI: read one or more signal bundles (JSON) and print the derived
// claims, transport fingerprint, and anomaly verdict. Built for offline analysis
// of logged client telemetry — pipe a captured bundle in, or point it at a file.
//
//   node bin/client-recon.js fixtures/headless-puppeteer.json
//   cat bundle.json | node bin/client-recon.js --json
//
// A bundle is either a single {client, edge} object or an array of them.
import { readFileSync } from "node:fs";
import { analyze } from "../lib/index.js";

function usage() {
  console.error("usage: client-recon [--json] [--quiet] [file.json ...]   (stdin if no files)");
  process.exit(2);
}

const args = process.argv.slice(2);
const asJson = args.includes("--json");
const quiet = args.includes("--quiet");
const files = args.filter((a) => !a.startsWith("--"));
if (args.includes("--help") || args.includes("-h")) usage();

function readInput() {
  if (files.length) return files.map((f) => readFileSync(f, "utf8")).join("\n");
  return readFileSync(0, "utf8"); // fd 0 = stdin
}

let raw;
try {
  raw = readInput();
} catch (err) {
  console.error(`client-recon: cannot read input: ${err.message}`);
  process.exit(2);
}

let parsed;
try {
  parsed = JSON.parse(raw);
} catch (err) {
  console.error(`client-recon: input is not valid JSON: ${err.message}`);
  process.exit(2);
}

const bundles = Array.isArray(parsed) ? parsed : [parsed];
const results = bundles.map((b) => analyze(b));

if (asJson) {
  const payload = Array.isArray(parsed) ? results : results[0];
  process.stdout.write(JSON.stringify(payload, null, 2) + "\n");
} else {
  results.forEach((r, i) => {
    if (bundles.length > 1) console.log(`\n=== bundle #${i} ===`);
    console.log(`verdict:     ${r.verdict}  (score ${r.score}${r.hard ? ", hard" : ""})`);
    console.log(`fingerprint: ${r.fingerprint ?? "n/a"}`);
    console.log(`categories:  ${JSON.stringify(r.categories)}`);
    if (!quiet) {
      for (const c of r.claims) {
        console.log(`  [${c.confidence.padEnd(7)} w${c.weight}] ${c.id}`);
        console.log(`      ${c.text}`);
      }
    }
  });
}

// Non-zero exit when anything scored adversarial, so the CLI is usable as a gate.
process.exit(results.some((r) => r.verdict === "adversarial") ? 1 : 0);
