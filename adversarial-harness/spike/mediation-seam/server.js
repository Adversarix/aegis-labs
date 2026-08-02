// Mediation seam — week-one spike + enforcing milestone (DESIGN.md §6).
//
// An MCP stdio server that Goose loads as its ONLY tool extension (via
// `goose run --no-profile --with-extension`). Because it is the only extension,
// every tool the model can call is exposed here, so every tool call crosses this
// one chokepoint before it runs. Containment is enforced in code, at a single
// dispatch seam, not threaded through the agent loop.
//
// MODE (env SEAM_MODE, default "enforcing"):
//   log-only    record the call and always allow (spike Days 3-4 behaviour)
//   enforcing   evaluate policy.js; on a deny verdict the tool does NOT execute.
//               Invariants (DESIGN.md §6): kill-gate, default-deny, target-
//               isolation, signed markers on every allowed action (marker.js).
//
// The enforcing demo: run_shell executes on the HOST (outside the box) so
// target-isolation denies it and trips the kill-gate; run_poc/fuzz execute only
// in the --network none container so they pass and carry a signed marker.
//
// Env:
//   SEAM_MODE          "enforcing" (default) | "log-only"
//   MEDIATION_LOG      append-only mediation log (default ./mediation.log)
//   SEAM_TOOLS         comma-list of tools to EXPOSE (default all). Distinct from
//                      policy: exposing a tool still lets the plane deny it.
//   AEGIS_SCOPE        path to a run-scope JSON (default policy.DEFAULT_SCOPE)
//   AEGIS_MARKER_KEY   per-run HMAC key (default: random ephemeral)
//   AEGIS_KILL         "1" to trip the kill-gate externally
//   AEGIS_KILL_FILE    path; if it exists, the kill-gate is tripped
//   SPIKE_IMAGE        sandbox image (default spike-fuzz:latest)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { appendFileSync, readFileSync, existsSync } from "node:fs";
import { execSync, execFileSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { evaluate, TOOLS, DEFAULT_SCOPE } from "./policy.js";
import { signMarker } from "./marker.js";
import { openStore } from "../munitions-store/store.js";

const MODE = (process.env.SEAM_MODE || "enforcing").toLowerCase();
const LOG = process.env.MEDIATION_LOG || new URL("./mediation.log", import.meta.url).pathname;
const IMAGE = process.env.SPIKE_IMAGE || "spike-fuzz:latest";
const ALLOW_EXPOSE = (process.env.SEAM_TOOLS || "run_shell,run_poc,fuzz,promote_finding")
  .split(",").map((s) => s.trim()).filter(Boolean);
const MARKER_KEY = process.env.AEGIS_MARKER_KEY || randomBytes(32).toString("hex");
// Munitions store for the discovery->develop handoff. Shared across seams via
// AEGIS_STORE (dir) + AEGIS_STORE_KEY (defaults to the run marker key).
const STORE = process.env.AEGIS_STORE
  ? openStore(process.env.AEGIS_STORE, { key: process.env.AEGIS_STORE_KEY || MARKER_KEY })
  : null;
const SCOPE = process.env.AEGIS_SCOPE ? JSON.parse(readFileSync(process.env.AEGIS_SCOPE, "utf8")) : DEFAULT_SCOPE;

const KILL = { killed: false, reason: "" };
let SEQ = 0;
let DENIALS = 0;

function killTripped() {
  if (KILL.killed) return true;
  if (process.env.AEGIS_KILL === "1") { KILL.killed = true; KILL.reason = "AEGIS_KILL=1"; return true; }
  if (process.env.AEGIS_KILL_FILE && existsSync(process.env.AEGIS_KILL_FILE)) {
    KILL.killed = true; KILL.reason = `kill file ${process.env.AEGIS_KILL_FILE}`; return true;
  }
  return false;
}

// THE SEAM. Every tool call crosses here before execution. Returns a verdict;
// on `allow` a signed marker is attached (attributable + unforgeable).
function mediate(tool, args) {
  const seq = ++SEQ;
  const ts = new Date().toISOString();
  killTripped(); // refresh external kill state

  let verdict;
  if (MODE === "log-only") {
    verdict = { decision: "allow", reason: "log-only mode", hard: false, check: "log-only" };
  } else {
    verdict = evaluate(SCOPE, KILL, tool);
  }

  let marker = null;
  if (verdict.decision === "allow") {
    marker = signMarker(MARKER_KEY, { run_id: SCOPE.run_id, seq, tool, ts });
  }

  const record = {
    ts, seq, actor: "model", tool, tier: TOOLS[tool]?.tier ?? "unknown",
    args, decision: verdict.decision, check: verdict.check, reason: verdict.reason,
    marker: marker ? marker.hmac : null, seam: MODE,
  };
  appendFileSync(LOG, JSON.stringify(record) + "\n");

  // Kill-gate backstop (DESIGN.md §6 invariant 4): a denial is the plane working,
  // so the run continues — but if the agent keeps hammering denied actions past
  // an optional threshold, trip the gate so the rest of the run is denied too.
  if (verdict.decision === "deny" && verdict.check !== "kill-gate") {
    DENIALS += 1;
    const limit = SCOPE.kill_after_denials;
    if (MODE === "enforcing" && Number.isInteger(limit) && DENIALS >= limit && !KILL.killed) {
      KILL.killed = true;
      KILL.reason = `denial threshold reached (${DENIALS} >= ${limit})`;
    }
  }
  return { ...verdict, marker };
}

const denyResult = (v) => ({ isError: true, content: [{ type: "text", text: `DENIED by mediation seam (${v.check}): ${v.reason}` }] });

// Run the sandboxed target: docker, --network none, resource-capped. The signed
// marker is injected as $AEGIS_MARKER so the synthetic action is attributable.
function sandboxRun(argv, input, markerHmac) {
  const base = [
    "run", "--rm", "-i", "--network", "none", "--memory", "512m", "--cpus", "1",
    "-e", `AEGIS_MARKER=${markerHmac ?? ""}`, IMAGE, ...argv,
  ];
  try {
    const out = execFileSync("docker", base, {
      input: input ?? Buffer.alloc(0), encoding: "utf8", timeout: 60000,
      maxBuffer: 8 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"],
    });
    return { code: 0, out, err: "" };
  } catch (e) {
    return { code: e.status ?? 1, out: e.stdout?.toString() ?? "", err: e.stderr?.toString() ?? String(e.message ?? e) };
  }
}

const asanCrashed = (r) => r.code !== 0 || /AddressSanitizer/.test(r.err) || /AddressSanitizer/.test(r.out);
const asanSummary = (r) => {
  const m = (r.err + "\n" + r.out).match(/ERROR: AddressSanitizer:[\s\S]*?SUMMARY: AddressSanitizer:[^\n]*/);
  return m ? m[0] : "";
};

const server = new McpServer({ name: "mediation-seam", version: "0.3.0" });

// ---- run_shell: executes on the HOST — denied by target-isolation in enforcing mode ----
if (ALLOW_EXPOSE.includes("run_shell")) {
  server.registerTool(
    "run_shell",
    { description: "Run a shell command and return its exit code, stdout, and stderr.",
      inputSchema: { cmd: z.string().describe("The shell command to execute") } },
    async ({ cmd }) => {
      const v = mediate("run_shell", { cmd });
      if (v.decision !== "allow") return denyResult(v);
      let code = 0, stdout = "", stderr = "";
      try { stdout = execSync(cmd, { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] }); }
      catch (e) { code = e.status ?? 1; stdout = e.stdout?.toString() ?? ""; stderr = e.stderr?.toString() ?? String(e.message ?? e); }
      return { content: [{ type: "text", text: `exit=${code}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}` }] };
    }
  );
}

// ---- run_poc (green, isolated): allowed ----
if (ALLOW_EXPOSE.includes("run_poc")) {
  server.registerTool(
    "run_poc",
    { description:
        "Run one input against the deliberately-vulnerable target inside the sandbox " +
        "(--network none) and report whether it crashed, with the AddressSanitizer report. " +
        "Provide the input as text OR as hex bytes.",
      inputSchema: {
        input: z.string().optional().describe("Input bytes as a UTF-8 string"),
        input_hex: z.string().optional().describe("Input bytes as hex, e.g. '41414141'"),
      } },
    async ({ input, input_hex }) => {
      const buf = input_hex ? Buffer.from(input_hex.replace(/\s+/g, ""), "hex") : Buffer.from(input ?? "", "utf8");
      const v = mediate("run_poc", { bytes: buf.length, preview: buf.toString("latin1").slice(0, 32) });
      if (v.decision !== "allow") return denyResult(v);
      const r = sandboxRun(["/work/vuln_poc"], buf, v.marker?.hmac);
      const crashed = asanCrashed(r), summary = asanSummary(r);
      const text = `input_len=${buf.length}\ncrashed=${crashed}\nexit=${r.code}\n` +
        (crashed ? `--- ASan ---\n${summary || r.err || r.out}\n` : `--- clean ---\n${r.out}\n`);
      return { content: [{ type: "text", text }] };
    }
  );
}

// ---- fuzz (green, isolated): allowed ----
if (ALLOW_EXPOSE.includes("fuzz")) {
  server.registerTool(
    "fuzz",
    { description:
        "Run a short libFuzzer campaign against the target inside the sandbox " +
        "(--network none) and report whether a crash was found, with the ASan report.",
      inputSchema: { max_seconds: z.number().int().min(1).max(60).optional().describe("Campaign length, default 20s") } },
    async ({ max_seconds }) => {
      const secs = max_seconds ?? 20;
      const v = mediate("fuzz", { max_seconds: secs });
      if (v.decision !== "allow") return denyResult(v);
      const r = sandboxRun(["/work/vuln_fuzz", `-max_total_time=${secs}`, "-artifact_prefix=/tmp/"], Buffer.alloc(0), v.marker?.hmac);
      const crashed = asanCrashed(r), summary = asanSummary(r);
      const text = `crashed=${crashed}\nexit=${r.code}\n` +
        (crashed ? `--- ASan ---\n${summary}\n` : `--- no crash found in ${secs}s ---\n`);
      return { content: [{ type: "text", text }] };
    }
  );
}

// ---- promote_finding (green, custody): discovery -> develop handoff ----
// Promote a confirmed crash into an inert munition in the shared store. This is
// the discovery-side of the handoff (discovery-stage.md §6 -> develop-stage.md §1).
if (ALLOW_EXPOSE.includes("promote_finding")) {
  server.registerTool(
    "promote_finding",
    { description:
        "Promote a CONFIRMED crash into the munitions store as an inert munition " +
        "(exploitation_level = crash), so the develop stage can ingest it. Provide the " +
        "crashing input (hex), the build recipe, and the crash report.",
      inputSchema: {
        reproducer_input_hex: z.string().describe("the crashing input, hex-encoded"),
        recipe: z.string().describe("how the target is built/run to reproduce"),
        crash_report: z.string().describe("the crash signal / sanitizer summary"),
        finding_id: z.string().optional(),
      } },
    async ({ reproducer_input_hex, recipe, crash_report, finding_id }) => {
      const v = mediate("promote_finding", { finding_id, bytes: (reproducer_input_hex.length / 2) | 0 });
      if (v.decision !== "allow") return denyResult(v);
      if (!STORE) return { isError: true, content: [{ type: "text", text: "no munitions store configured (set AEGIS_STORE)" }] };
      const m = STORE.create({
        origin: "discovered",
        artifact: { reproducer_input_hex, recipe, crash_report },
        provenance: { finding_id: finding_id ?? null, run_id: SCOPE.run_id, marker: v.marker?.hmac },
      });
      return { content: [{ type: "text", text: JSON.stringify(m, null, 2) }] };
    }
  );
}

const transport = new StdioServerTransport();
await server.connect(transport);
