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

// DISCLOSE: coordinated-disclosure DRAFT. STUB — the §6.2 CVD workflow (embargo clock,
// coordinator path, human-gated publication) is unbuilt; this names the gap (increment 3).
function discloseStub(cls, munition) {
  const dir = join(OUT, "disclosure"); mkdirSync(dir, { recursive: true });
  const advisory = `# DRAFT advisory (STUB) — ${TARGET.name} ${TARGET.version}

**Status:** DRAFT / EMBARGOED. Stub: the coordinated-disclosure workflow
(disclosure-policy.md, DESIGN.md §6.2) is not implemented. Do NOT send.

- **Target:** ${TARGET.name} ${TARGET.version} (${TARGET.source}), ${TARGET.license}
- **Class:** ${cls.class} (${cls.cwe}) in \`${cls.function}\`
- **Severity:** ${cls.severity}
- **Found by:** libFuzzer + AddressSanitizer, contained (--network none), seam-mediated
- **Reproducer:** custody munition ${munition.id} (embargoed in the store, not published)
`;
  writeFileSync(join(dir, "advisory-draft.md"), advisory);
  log("disclose", `wrote DRAFT advisory (STUB) -> ${join(dir, "advisory-draft.md")}`);
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

    discloseStub(cls, m);

    console.log(`\n=== loop complete: real bug in real code, seam-mediated, in custody, disclosure drafted ===`);
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
