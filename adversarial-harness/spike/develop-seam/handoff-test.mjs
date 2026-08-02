// Integration test of the discovery->develop handoff through the real MCP seams
// against one shared munitions store. No docker needed (custody ops are pure).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { openStore } from "../munitions-store/store.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const STORE_DIR = mkdtempSync(join(tmpdir(), "handoff-store-"));
const KEY = "handoff-test-key";
const SPIKE = "/Users/kgalappatti/Apps/aegis-research/adversarial-harness/spike";
const common = { AEGIS_STORE: STORE_DIR, AEGIS_STORE_KEY: KEY, SEAM_MODE: "enforcing" };
const j = (r) => JSON.parse(r.content[0].text);

async function connect(dir, extraEnv) {
  const t = new StdioClientTransport({ command: "node", args: ["server.js"], cwd: join(SPIKE, dir),
    env: { ...process.env, ...common, ...extraEnv, MEDIATION_LOG: `${STORE_DIR}/${dir}.log` } });
  const c = new Client({ name: "t", version: "0" }, { capabilities: {} });
  await c.connect(t);
  return c;
}

// 1) DISCOVERY seam promotes a confirmed crash into the store.
const disc = await connect("mediation-seam", {});
const promoted = j(await disc.callTool({ name: "promote_finding", arguments: {
  reproducer_input_hex: "41".repeat(24), recipe: "clang -O0 -fsanitize=address vuln.c -o vuln",
  crash_report: "AddressSanitizer: stack-buffer-overflow", finding_id: "F-42" } }));
console.log("discovery promoted:", { id: promoted.id.slice(0, 8), state: promoted.custody_state, level: promoted.exploitation.level, events: promoted.events });
await disc.close();
const id = promoted.id;

// 2) DEVELOP seam ingests it (access), works it, records progress (update).
const dev = await connect("develop-seam", {});
const listed = j(await dev.callTool({ name: "list_munitions", arguments: {} }));
console.log("develop sees store:", listed.length, "munition(s)");
const ingested = j(await dev.callTool({ name: "ingest_munition", arguments: { id } }));
console.log("develop ingested reproducer:", ingested.artifact.crash_report, "| recipe present:", !!ingested.artifact.recipe);
const recorded = j(await dev.callTool({ name: "record_progress", arguments: {
  id, level: "exploit", primitives: ["pc-control"], mitigations_defeated: ["none"], reliability: 1.0 } }));
console.log("develop recorded:", { level: recorded.exploitation.level, reliability: recorded.exploitation.reliability, events: recorded.events });
await dev.close();

// 3) Inspect the shared store directly: the custody ledger is the through-line.
const store = openStore(STORE_DIR, { key: KEY });
const v = store.verify(id);
const m = store.list().find((x) => x.id === id);
console.log("custody verify:", v);

const actions = [];  // reconstruct the ledger action sequence from a fresh read
import("node:fs").then(({ readFileSync }) => {
  const rec = JSON.parse(readFileSync(join(STORE_DIR, "munitions", `${id}.json`), "utf8"));
  for (const e of rec.ledger) actions.push(e.action);
  console.log("ledger chain:", actions.join(" -> "));

  const ok = promoted.custody_state === "at_rest" && promoted.exploitation.level === "crash"
    && ingested.artifact.recipe && recorded.exploitation.level === "exploit"
    && v.ok === true && actions.join(",") === "create,access,update";
  console.log("\nHANDOFF TEST:", ok ? "PASS" : "FAIL");
  process.exit(ok ? 0 : 1);
});
