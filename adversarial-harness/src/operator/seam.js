// Operator research-cockpit MCP seam. Exposes the operator loop's actions —
// hunt / reproduce / triage / promote_finding — behind the SAME enforcing mediation
// gate as the develop and discovery seams (default-deny, target-isolation, signed
// markers, kill-gate; DESIGN.md §6, policy.js). Every op crosses mediate() and lands
// in MEDIATION_LOG with a signed marker, so an operator run has the same containment
// and audit trail as a develop run — and an agent (Goose) could drive it identically.
//
// hunt/reproduce execute the real target only inside a --network none container.
// triage is pure. promote_finding writes to the shared munitions store on the host.
//
// Env:
//   SEAM_MODE       enforcing (default) | log-only
//   MEDIATION_LOG   append-only mediation log (default ./mediation.log)
//   OPERATOR_IMAGE  target sandbox image (default aegis-operator-stb:latest)
//   AEGIS_MARKER_KEY per-run HMAC key (default random)
//   AEGIS_STORE / AEGIS_STORE_KEY  the munitions store for custody
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { appendFileSync, mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { evaluate, TOOLS } from "../mediation-seam/policy.js";
import { signMarker } from "../mediation-seam/marker.js";
import { openStore } from "../munitions-store/store.js";
import { classify } from "./triage.js";

const MODE = (process.env.SEAM_MODE || "enforcing").toLowerCase();
const LOG = process.env.MEDIATION_LOG || new URL("./mediation.log", import.meta.url).pathname;
const IMAGE = process.env.OPERATOR_IMAGE || "aegis-operator-stb:latest";
const MARKER_KEY = process.env.AEGIS_MARKER_KEY || randomBytes(32).toString("hex");
const STORE = process.env.AEGIS_STORE
  ? openStore(process.env.AEGIS_STORE, { key: process.env.AEGIS_STORE_KEY || MARKER_KEY })
  : null;

// Operator run scope: green tier, the operator tools only, sandbox required. Anything
// else (run_shell, exploit-dev tools, ...) is default-denied for this run.
const SCOPE = { run_id: "operator-green-run", allowed_tiers: ["green"],
  allowed_tools: ["hunt", "reproduce", "triage", "promote_finding"], isolation: { require_sandbox: true } };

const KILL = { killed: false, reason: "" };
let SEQ = 0;

function mediate(tool, args) {
  const seq = ++SEQ, ts = new Date().toISOString();
  const verdict = MODE === "log-only"
    ? { decision: "allow", reason: "log-only", check: "log-only" }
    : evaluate(SCOPE, KILL, tool);
  const marker = verdict.decision === "allow" ? signMarker(MARKER_KEY, { run_id: SCOPE.run_id, seq, tool, ts }) : null;
  appendFileSync(LOG, JSON.stringify({ ts, seq, actor: "operator", tool, tier: TOOLS[tool]?.tier ?? "unknown",
    args, decision: verdict.decision, check: verdict.check, reason: verdict.reason, marker: marker?.hmac ?? null, seam: MODE }) + "\n");
  return { ...verdict, marker };
}
const ok = (obj) => ({ content: [{ type: "text", text: JSON.stringify(obj, null, 2) }] });
const deny = (v) => ({ isError: true, content: [{ type: "text", text: `DENIED by mediation seam (${v.check}): ${v.reason}` }] });

const docker = (args) => {
  try { return execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); }
  catch (e) { return (e.stdout || "") + (e.stderr || ""); }   // libFuzzer nonzero on a finding is expected
};

// HUNT: fuzz the real target in a --network none sandbox; return the reproducer bytes.
function doHunt(seconds) {
  const dir = mkdtempSync(join(tmpdir(), "op-hunt-"));
  try {
    docker(["run", "--rm", "--network", "none", "-v", `${dir}:/out`, IMAGE,
      "/work/fuzz_stb", `-max_total_time=${seconds}`, "-rss_limit_mb=2048", "-artifact_prefix=/out/"]);
    const art = readdirSync(dir).find((f) => f.startsWith("crash-") || f.startsWith("oom-"));
    if (!art) return { found: false };
    return { found: true, artifact: art, kind: art.startsWith("oom-") ? "out-of-memory" : "crash",
      reproducer_hex: readFileSync(join(dir, art)).toString("hex") };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

// REPRODUCE: replay a reproducer deterministically in the sandbox; return the report.
function doReproduce(reproducer_hex) {
  const dir = mkdtempSync(join(tmpdir(), "op-repro-"));
  try {
    writeFileSync(join(dir, "input"), Buffer.from(reproducer_hex, "hex"));
    const report = docker(["run", "--rm", "--network", "none", "-v", `${dir}:/in:ro`, IMAGE,
      "/work/fuzz_stb", "-rss_limit_mb=2048", "/in/input"]);
    return { reproduced: /out-of-memory|AddressSanitizer|deadly signal|SUMMARY/i.test(report), report: report.slice(0, 6000) };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

const server = new McpServer({ name: "operator-seam", version: "0.1.0" });

server.tool("hunt", "Fuzz the ingested real target in the sandbox until a crash; returns the reproducer.",
  { seconds: z.number().int().positive().default(90) }, async ({ seconds }) => {
    const v = mediate("hunt", { seconds }); if (v.decision !== "allow") return deny(v);
    return ok(doHunt(seconds));
  });

server.tool("reproduce", "Replay a reproducer deterministically in the sandbox; returns the crash report.",
  { reproducer_hex: z.string() }, async ({ reproducer_hex }) => {
    const v = mediate("reproduce", { bytes: reproducer_hex.length / 2 }); if (v.decision !== "allow") return deny(v);
    return ok(doReproduce(reproducer_hex));
  });

server.tool("triage", "Classify a crash report into an honest {class, cwe, severity, weaponizable}.",
  { report: z.string(), kind: z.string().default("crash") }, async ({ report, kind }) => {
    const v = mediate("triage", { kind }); if (v.decision !== "allow") return deny(v);
    return ok(classify(report, kind));
  });

server.tool("promote_finding", "Promote a confirmed reproducer to a munition in custody (embargoed).",
  { reproducer_hex: z.string(), report: z.string(), classification: z.any(), target: z.any() },
  async ({ reproducer_hex, report, classification, target }) => {
    const v = mediate("promote_finding", { target_match: `${target?.name}@${target?.version}` });
    if (v.decision !== "allow") return deny(v);
    if (!STORE) return ok({ error: "no munitions store configured (set AEGIS_STORE)" });
    const m = STORE.create({
      origin: "discovered",
      artifact: { reproducer_input_hex: reproducer_hex,
        recipe: `docker run --network none ${IMAGE} /work/fuzz_stb <input>`, crash_report: String(report).slice(0, 4000) },
      provenance: { target: target?.name, version: target?.version, source: target?.source,
        harness: "fuzz_stb.c", found_by: "libFuzzer+ASan", crash_class: classification?.class, cwe: classification?.cwe,
        marker: v.marker?.hmac ?? null },
      ownership: "third-party", target_match: `${target?.name}@${target?.version}`,
      disclosure_status: "embargoed", retention: { class: "third-party-embargoed", expires_at: null },
    });
    // record the honest characterization onto the munition
    STORE.update(m.id, {
      level: classification?.weaponizable ? "primitive" : "crash",
      primitives: classification?.weaponizable ? ["memory-corruption"] : ["dos"], reliability: 1.0, objective: null,
    }, { reason: `characterized: ${classification?.class} (${classification?.cwe}); ${classification?.severity}` });
    return ok({ ...m, verify: STORE.verify(m.id) });
  });

await server.connect(new StdioServerTransport());
