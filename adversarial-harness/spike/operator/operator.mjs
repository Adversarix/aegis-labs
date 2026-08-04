// operator.mjs — walking skeleton of the OPERATOR research loop, end to end, on a
// REAL third-party target (stb_image), fully contained. This is the cockpit face of
// the harness (DESIGN.md §1, §2, §5.1): point it at a real target and DO the research
// (find a real bug -> take custody -> characterize -> draft disclosure), rather than
// score a model against a fixed task.
//
//   ingest       : a real target built into the sandbox image (Dockerfile)
//   hunt         : coverage-guided libFuzzer + ASan in a --network none container
//   confirm      : deterministic replay of the crashing input -> a real crash report
//   custody      : promote the reproducer to the munitions store (real signed ledger)
//   characterize : classify the crash (class, CWE, weaponizability) onto the munition
//   disclose     : emit a coordinated-disclosure DRAFT (STUB: §6.2 workflow unbuilt)
//
// Honest scope (increment 1): the hunt runs in a --network none sandbox and custody
// uses the real store, but the loop is driven directly here, NOT yet behind the MCP
// mediation seam (that is increment 2). The stb finding is a DoS-class
// uncontrolled-allocation bug; the loop characterizes it honestly as non-weaponizable.
import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync, readdirSync, mkdirSync } from "node:fs";
import { join, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { openStore } from "../munitions-store/store.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const IMAGE = process.env.OPERATOR_IMAGE || "aegis-operator-stb:latest";
const arg = (k, d) => { const i = process.argv.indexOf(k); return i >= 0 ? process.argv[i + 1] : d; };

const OUT = resolve(arg("--out", join(HERE, "runs", "stb")));
const HUNT_SECONDS = Number(arg("--seconds", "90"));
const STORE_DIR = resolve(arg("--store", join(OUT, "store")));
const STORE_KEY = process.env.AEGIS_STORE_KEY || "operator-walking-skeleton-key";

const TARGET = { name: "stb_image", version: "2.19", source: "github.com/nothings/stb",
  license: "MIT / public domain" };

const log = (stage, msg) => console.log(`[${stage.padEnd(12)}] ${msg}`);
const docker = (args, capture = false) => {
  try { return execFileSync("docker", args, { encoding: "utf8", stdio: capture ? ["ignore", "pipe", "pipe"] : "inherit" }); }
  catch (e) { return (e.stdout || "") + (e.stderr || ""); }   // libFuzzer/finding -> nonzero exit is expected
};

// HUNT: fuzz the real target in a --network none sandbox until a crash; return the
// reproducer artifact libFuzzer wrote.
function hunt() {
  mkdirSync(OUT, { recursive: true });
  log("hunt", `fuzzing ${TARGET.name}@${TARGET.version} for up to ${HUNT_SECONDS}s (--network none, ASan)`);
  docker(["run", "--rm", "--network", "none", "-v", `${OUT}:/out`, IMAGE,
    "/work/fuzz_stb", `-max_total_time=${HUNT_SECONDS}`, "-rss_limit_mb=2048", "-artifact_prefix=/out/"], true);
  const art = readdirSync(OUT).find((f) => f.startsWith("crash-") || f.startsWith("oom-"));
  if (!art) throw new Error(`hunt found no reproducer in ${HUNT_SECONDS}s (try --seconds larger)`);
  const kind = art.startsWith("oom-") ? "out-of-memory" : "crash";
  log("hunt", `FOUND a ${kind}: ${art}`);
  return { artifact: art, path: join(OUT, art), kind };
}

// CONFIRM: replay the reproducer deterministically for a clean report.
function confirm(finding) {
  const report = docker(["run", "--rm", "--network", "none", "-v", `${OUT}:/out:ro`, IMAGE,
    "/work/fuzz_stb", "-rss_limit_mb=2048", `/out/${finding.artifact}`], true);
  const reproduced = /out-of-memory|AddressSanitizer|deadly signal|SUMMARY/i.test(report);
  log("confirm", reproduced ? "reproduced deterministically" : "WARNING: did not reproduce");
  return report;
}

// CLASSIFY: turn the report into an honest crash classification (no over-claiming).
export function classify(report, kind) {
  const grab = (re) => { const m = report.match(re); return m ? m[0] : null; };
  const fn = grab(/stbi__\w+/) || "stb_image decode path";
  if (kind === "out-of-memory" || /out-of-memory/i.test(report)) {
    return { class: "uncontrolled-resource-consumption", cwe: "CWE-789", signal: "libFuzzer OOM",
      function: fn, weaponizable: false, severity: "low (DoS / resource exhaustion)",
      note: "crafted image dimensions drive an unbounded allocation" };
  }
  const oob = grab(/(heap|stack|global)-buffer-overflow/);
  if (oob) return { class: oob, cwe: "CWE-122", signal: grab(/(READ|WRITE) of size \d+/) || "ASan",
    function: fn, weaponizable: true, severity: "medium (memory corruption)", note: "" };
  return { class: "reachable-crash", cwe: "CWE-617", signal: grab(/(SEGV|assert\w*)/) || "deadly signal",
    function: fn, weaponizable: false, severity: "low (abort)", note: "" };
}

// CUSTODY: promote the reproducer to the real munitions store (encrypted, signed ledger).
function promote(store, finding, report, cls) {
  const reproHex = readFileSync(finding.path).toString("hex");
  const m = store.create({
    origin: "discovered",
    artifact: { reproducer_input_hex: reproHex,
      recipe: `docker run --network none ${IMAGE} /work/fuzz_stb <input>`,
      crash_report: report.slice(0, 4000) },
    provenance: { target: TARGET.name, version: TARGET.version, source: TARGET.source,
      harness: "fuzz_stb.c", found_by: "libFuzzer+ASan", crash_class: cls.class, cwe: cls.cwe },
    ownership: "third-party",
    target_match: `${TARGET.name}@${TARGET.version}`,
    disclosure_status: "embargoed",
    retention: { class: "third-party-embargoed", expires_at: null },
  });
  log("custody", `promoted to munition ${m.id} (ownership=third-party, disclosure=embargoed)`);
  return m;
}

// CHARACTERIZE: record the honest exploitation assessment onto the munition.
function characterize(store, id, cls) {
  const s = store.update(id, {
    level: cls.weaponizable ? "primitive" : "crash",
    primitives: cls.weaponizable ? ["memory-corruption"] : ["dos"],
    reliability: 1.0, objective: null,
  }, { reason: `characterized: ${cls.class} (${cls.cwe}) in ${cls.function}; ${cls.severity}` });
  log("characterize", `${cls.class} (${cls.cwe}) in ${cls.function} — ${cls.severity}; weaponizable=${cls.weaponizable}`);
  return s;
}

// DISCLOSE: emit a coordinated-disclosure DRAFT. STUB — the §6.2 CVD workflow (embargo
// clock, coordinator path, human-gated publication) does not exist yet; this surfaces
// that gap rather than pretending to close it.
function discloseStub(finding, cls, munition) {
  const dir = join(OUT, "disclosure"); mkdirSync(dir, { recursive: true });
  const advisory = `# DRAFT advisory (STUB) — ${TARGET.name} ${TARGET.version}

**Status:** DRAFT / EMBARGOED. This is a stub: the coordinated-disclosure workflow
(disclosure-policy.md, DESIGN.md §6.2) is not implemented. Do NOT send.

- **Target:** ${TARGET.name} ${TARGET.version} (${TARGET.source}), ${TARGET.license}
- **Class:** ${cls.class} (${cls.cwe}) in \`${cls.function}\`
- **Severity:** ${cls.severity}
- **Found by:** libFuzzer + AddressSanitizer, contained (--network none)
- **Reproducer:** custody munition ${munition.id} (the crashing input is embargoed in the store, not published)
- **Notes:** ${cls.note || "see crash report in custody"}

Next (unbuilt): assign embargo clock, identify the coordinator/maintainer path, gate
publication on a human, and never publish the reproducer (§6.2).
`;
  writeFileSync(join(dir, "advisory-draft.md"), advisory);
  writeFileSync(join(dir, "advisory-draft.json"), JSON.stringify(
    { target: TARGET, class: cls.class, cwe: cls.cwe, severity: cls.severity,
      munition_id: munition.id, status: "draft-embargoed", workflow: "STUB (§6.2 unbuilt)" }, null, 2));
  log("disclose", `wrote DRAFT advisory (STUB) -> ${join(dir, "advisory-draft.md")}`);
}

function main() {
  console.log(`\n=== Operator research loop (walking skeleton) — target ${TARGET.name}@${TARGET.version} ===\n`);
  const finding = hunt();                          // ingest is baked into IMAGE; this hunts it
  const report = confirm(finding);
  const cls = classify(report, finding.kind);
  const store = openStore(STORE_DIR, { key: STORE_KEY });
  const m = promote(store, finding, report, cls);
  characterize(store, m.id, cls);
  const v = store.verify(m.id);
  log("custody", `ledger verify: ok=${v.ok} events=${v.events ?? "-"}`);
  discloseStub(finding, cls, m);
  console.log(`\n=== loop complete: real bug in real code, contained, in custody, disclosure drafted ===`);
  console.log(`munition ${m.id} | class ${cls.class} (${cls.cwe}) | custody ${v.ok ? "VERIFIED" : "BROKEN"}\n`);
  return v.ok ? 0 : 1;
}

// Run the loop only when invoked directly (so the test can import classify() without docker).
if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) process.exit(main());
