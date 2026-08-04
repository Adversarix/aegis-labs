// operator.mjs — the OPERATOR research loop, driven THROUGH the enforcing mediation
// seam (increment 2). This is an MCP client (like the ExploitGym adapter): it connects
// to operator/seam.js and calls hunt -> reproduce -> triage -> promote_finding, so
// EVERY op crosses the logged mediation gate with a signed marker, exactly like a
// develop run. An agent (Goose) could drive the same seam identically.
//
//   ingest       : a real target built into the sandbox image (Dockerfile)
//   hunt         : libFuzzer + ASan in a --network none container   [seam-mediated]
//   confirm      : deterministic replay of the reproducer            [seam-mediated]
//   characterize : honest crash classification                       [seam-mediated]
//   custody      : promote the reproducer to a signed munition       [seam-mediated]
//   disclose     : coordinated-disclosure DRAFT (STUB: §6.2 unbuilt) [client-side]
//
// The stb finding is a DoS-class uncontrolled-allocation bug; the loop characterizes
// it honestly as non-weaponizable. Disclosure remains a stub until increment 3.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { writeFileSync, mkdirSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openDisclosure } from "../disclosure/disclosure.js";
import { openStore } from "../munitions-store/store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };

const OUT = resolve(arg("--out", join(HERE, "runs", "stb")));
const HUNT_SECONDS = Number(arg("--seconds", "90"));
const STORE_DIR = resolve(arg("--store", join(OUT, "store")));
const STORE_KEY = process.env.AEGIS_STORE_KEY || "operator-walking-skeleton-key";
const MEDIATION_LOG = join(OUT, "mediation.log");
const TARGET = { name: "stb_image", version: "2.19", source: "github.com/nothings/stb",
  license: "MIT / public domain" };

const log = (stage, msg) => console.log(`[${stage.padEnd(12)}] ${msg}`);

// DISCLOSE: the real coordinated-disclosure workflow (increment 3; disclosure-policy.md,
// §6.2). The autonomous loop opens an EMBARGOED case and assembles the vendor package
// (metadata + minimal-reproducer description, NEVER the weapon), then STOPS: reporting
// requires a human disclosure owner (rule 1), which the loop demonstrably cannot self-supply.
function disclose(cls, munition) {
  const dir = join(OUT, "disclosure"); mkdirSync(dir, { recursive: true });
  const store = openStore(STORE_DIR, { key: STORE_KEY });   // sync disclosure_status onto the munition (§8)
  const d = openDisclosure(dir, { key: STORE_KEY, store });
  const vuln = { class: cls.class, cwe: cls.cwe,
    root_cause: cls.note || `${cls.class} in ${cls.function}`,
    minimal_reproducer_description: `reproducer held in custody as munition ${munition.id} (embargoed, not attached); ${cls.signal}` };
  const c = d.open({ id: munition.id, ownership: "third-party" }, { vuln, target: TARGET });
  writeFileSync(join(dir, "vendor-package.json"), JSON.stringify(d.packageForVendor(c.id), null, 2));
  writeFileSync(join(dir, "advisory.md"), d.advisory(c.id));
  // Rule 1: the autonomous loop cannot disclose on its own — prove the refusal.
  let selfReportRefused = false;
  try { d.report(c.id, {}); } catch (e) { selfReportRefused = e.code === "OWNER_REQUIRED"; }
  log("disclose", `case ${c.id} opened EMBARGOED; vendor package + advisory prepared (no weapon, rule 2)`);
  log("disclose", `self-report refused=${selfReportRefused} -> awaiting a human disclosure owner (rule 1); ledger ${JSON.stringify(d.verify(c.id))}`);
  return c;
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  writeFileSync(MEDIATION_LOG, "");   // fresh mediation log for this run
  console.log(`\n=== Operator research loop (seam-mediated) — target ${TARGET.name}@${TARGET.version} ===\n`);

  const transport = new StdioClientTransport({
    command: "node", args: ["seam.js"], cwd: HERE,
    env: { ...process.env, SEAM_MODE: "enforcing", MEDIATION_LOG, AEGIS_STORE: STORE_DIR,
      AEGIS_STORE_KEY: STORE_KEY, OPERATOR_IMAGE: process.env.OPERATOR_IMAGE || "aegis-operator-stb:latest",
      AEGIS_MARKER_KEY: process.env.AEGIS_MARKER_KEY || "operator-run-key" },
  });
  const client = new Client({ name: "operator", version: "0.1.0" }, { capabilities: {} });
  await client.connect(transport);
  const call = async (name, args = {}) => {
    const res = await client.callTool({ name, arguments: args });
    const text = res.content?.[0]?.text ?? "";
    if (res.isError) throw new Error(`seam ${name}: ${text}`);
    return JSON.parse(text);
  };

  try {
    log("hunt", `fuzzing ${TARGET.name}@${TARGET.version} up to ${HUNT_SECONDS}s (seam-mediated, --network none)`);
    const h = await call("hunt", { seconds: HUNT_SECONDS });
    if (!h.found) throw new Error(`no reproducer found in ${HUNT_SECONDS}s (try --seconds larger)`);
    log("hunt", `FOUND ${h.kind}: ${h.artifact}`);

    const r = await call("reproduce", { reproducer_hex: h.reproducer_hex });
    log("confirm", r.reproduced ? "reproduced deterministically" : "WARNING: did not reproduce");

    const cls = await call("triage", { report: r.report, kind: h.kind });
    log("characterize", `${cls.class} (${cls.cwe}) in ${cls.function} — ${cls.severity}; weaponizable=${cls.weaponizable}`);

    const m = await call("promote_finding", { reproducer_hex: h.reproducer_hex, report: r.report, classification: cls, target: TARGET });
    log("custody", `munition ${m.id} (third-party, embargoed); ledger verify ok=${m.verify?.ok} events=${m.verify?.events}`);

    disclose(cls, m);

    console.log(`\n=== loop complete: real bug in real code, seam-mediated, in custody, disclosure case embargoed ===`);
    console.log(`munition ${m.id} | class ${cls.class} (${cls.cwe}) | custody ${m.verify?.ok ? "VERIFIED" : "BROKEN"}`);
    console.log(`mediation log: ${MEDIATION_LOG}\n`);
    await client.close();
    return m.verify?.ok ? 0 : 1;
  } catch (e) {
    console.error(`operator loop failed: ${e.message}`);
    await client.close();
    return 1;
  }
}

process.exit(await main());
