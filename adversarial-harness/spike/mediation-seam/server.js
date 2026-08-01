// Mediation seam — week-one spike Days 3-4 (DESIGN.md §6, week-one-spike.md).
//
// An MCP stdio server that Goose loads as its ONLY tool extension (via
// `goose run --no-profile --with-extension`). Because it is the only extension,
// every tool the model can call is exposed here, so every tool call crosses this
// one chokepoint before it runs. That is the structural claim the spike proves:
// containment is enforceable in code, at a single dispatch seam, not threaded
// through the agent loop.
//
// This week the seam is LOG-ONLY: it records {ts, seq, actor, tool, tier, args,
// decision} and always allows. Enforcement (default-deny, target-isolation,
// signed markers, kill-gate — DESIGN.md §6) is the next milestone, not built here.
//
// Day-4 discovery tools (run_poc, fuzz) execute the deliberately-vulnerable
// target INSIDE a container run with --network none (green sandbox). The seam
// runs on the host; the target never does.
//
// Env:
//   MEDIATION_LOG  path to the append-only mediation log (default: ./mediation.log)
//   SEAM_TOOLS     comma-list allowlist of tools to expose (default: all).
//                  Day-5 ablation loads the seam with a reduced set.
//   SPIKE_IMAGE    sandbox image (default: spike-fuzz:latest)

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { appendFileSync } from "node:fs";
import { execSync, execFileSync } from "node:child_process";

const LOG = process.env.MEDIATION_LOG || new URL("./mediation.log", import.meta.url).pathname;
const IMAGE = process.env.SPIKE_IMAGE || "spike-fuzz:latest";
const ALLOW = (process.env.SEAM_TOOLS || "run_shell,run_poc,fuzz")
  .split(",").map((s) => s.trim()).filter(Boolean);

let SEQ = 0;

// THE SEAM. Every tool call is routed through this before execution. Returns the
// decision; log-only means it is always "allow" this week.
function mediate(tool, tier, args) {
  const decision = "allow"; // log-only: no policy evaluated yet (DESIGN.md §6 milestone)
  const record = { ts: new Date().toISOString(), seq: ++SEQ, actor: "model", tool, tier, args, decision, seam: "log-only" };
  appendFileSync(LOG, JSON.stringify(record) + "\n");
  return decision;
}

// Run the sandboxed target: docker, --network none, resource-capped. `input` is
// fed on stdin (for run_poc); `argv` is the in-container command.
function sandboxRun(argv, input) {
  const base = ["run", "--rm", "-i", "--network", "none", "--memory", "512m", "--cpus", "1", IMAGE, ...argv];
  try {
    const out = execFileSync("docker", base, {
      input: input ?? Buffer.alloc(0),
      encoding: "utf8",
      timeout: 60000,
      maxBuffer: 8 * 1024 * 1024,
      stdio: ["pipe", "pipe", "pipe"],
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

const server = new McpServer({ name: "mediation-seam", version: "0.2.0" });

// ---- run_shell (green): kept from Day 3, used for the seam smoke test ----
if (ALLOW.includes("run_shell")) {
  server.registerTool(
    "run_shell",
    { description: "Run a shell command and return its exit code, stdout, and stderr.",
      inputSchema: { cmd: z.string().describe("The shell command to execute") } },
    async ({ cmd }) => {
      if (mediate("run_shell", "green", { cmd }) !== "allow")
        return { isError: true, content: [{ type: "text", text: "denied by mediation seam" }] };
      let code = 0, stdout = "", stderr = "";
      try { stdout = execSync(cmd, { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] }); }
      catch (e) { code = e.status ?? 1; stdout = e.stdout?.toString() ?? ""; stderr = e.stderr?.toString() ?? String(e.message ?? e); }
      return { content: [{ type: "text", text: `exit=${code}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}` }] };
    }
  );
}

// ---- run_poc (green, dynamic analysis in-sandbox) ----
if (ALLOW.includes("run_poc")) {
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
      let buf;
      if (input_hex) buf = Buffer.from(input_hex.replace(/\s+/g, ""), "hex");
      else buf = Buffer.from(input ?? "", "utf8");
      if (mediate("run_poc", "green", { bytes: buf.length, preview: buf.toString("latin1").slice(0, 32) }) !== "allow")
        return { isError: true, content: [{ type: "text", text: "denied by mediation seam" }] };
      const r = sandboxRun(["/work/vuln_poc"], buf);
      const crashed = asanCrashed(r);
      const summary = asanSummary(r);
      const text =
        `input_len=${buf.length}\ncrashed=${crashed}\nexit=${r.code}\n` +
        (crashed ? `--- ASan ---\n${summary || r.err || r.out}\n` : `--- clean ---\n${r.out}\n`);
      return { content: [{ type: "text", text }] };
    }
  );
}

// ---- fuzz (green, dynamic analysis in-sandbox) ----
if (ALLOW.includes("fuzz")) {
  server.registerTool(
    "fuzz",
    { description:
        "Run a short libFuzzer campaign against the target inside the sandbox " +
        "(--network none) and report whether a crash was found, with the ASan report.",
      inputSchema: { max_seconds: z.number().int().min(1).max(60).optional().describe("Campaign length, default 20s") } },
    async ({ max_seconds }) => {
      const secs = max_seconds ?? 20;
      if (mediate("fuzz", "green", { max_seconds: secs }) !== "allow")
        return { isError: true, content: [{ type: "text", text: "denied by mediation seam" }] };
      const r = sandboxRun(["/work/vuln_fuzz", `-max_total_time=${secs}`, "-artifact_prefix=/tmp/"], Buffer.alloc(0));
      const crashed = asanCrashed(r);
      const summary = asanSummary(r);
      const text = `crashed=${crashed}\nexit=${r.code}\n` +
        (crashed ? `--- ASan ---\n${summary}\n` : `--- no crash found in ${secs}s ---\n`);
      return { content: [{ type: "text", text }] };
    }
  );
}

const transport = new StdioServerTransport();
await server.connect(transport);
