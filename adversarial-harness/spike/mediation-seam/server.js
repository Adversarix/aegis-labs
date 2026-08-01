// Mediation seam — week-one spike Day 3 (DESIGN.md §6, week-one-spike.md Day 3).
//
// An MCP stdio server that Goose loads as its ONLY tool extension (via
// `goose run --no-profile --with-extension`). Because it is the only extension,
// every tool the model can call is exposed here, so every tool call crosses this
// one chokepoint before it runs. That is the structural claim the spike must
// prove: containment is enforceable in code, at a single dispatch seam, not
// threaded through the agent loop.
//
// This week the seam is LOG-ONLY: it records {ts, actor, tool, args, decision}
// and always allows. Enforcement (default-deny, target-isolation, signed markers,
// kill-gate — DESIGN.md §6) is the next milestone, deliberately not built here.

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { appendFileSync } from "node:fs";
import { execSync } from "node:child_process";

const LOG = process.env.MEDIATION_LOG || new URL("./mediation.log", import.meta.url).pathname;

// THE SEAM. Every tool call is routed through this function before execution.
// Returns the decision; log-only means it is always "allow" this week.
function mediate(tool, args) {
  const decision = "allow"; // log-only: no policy evaluated yet (DESIGN.md §6 milestone)
  const record = {
    ts: new Date().toISOString(),
    actor: "model",
    tool,
    args,
    decision,
    seam: "log-only",
  };
  appendFileSync(LOG, JSON.stringify(record) + "\n");
  return decision;
}

const server = new McpServer({ name: "mediation-seam", version: "0.1.0" });

server.registerTool(
  "run_shell",
  {
    description: "Run a shell command and return its exit code, stdout, and stderr.",
    inputSchema: { cmd: z.string().describe("The shell command to execute") },
  },
  async ({ cmd }) => {
    if (mediate("run_shell", { cmd }) !== "allow") {
      return { isError: true, content: [{ type: "text", text: "denied by mediation seam" }] };
    }
    let code = 0, stdout = "", stderr = "";
    try {
      stdout = execSync(cmd, { encoding: "utf8", timeout: 30000, stdio: ["ignore", "pipe", "pipe"] });
    } catch (e) {
      code = e.status ?? 1;
      stdout = e.stdout?.toString() ?? "";
      stderr = e.stderr?.toString() ?? String(e.message ?? e);
    }
    return { content: [{ type: "text", text: `exit=${code}\n--- stdout ---\n${stdout}\n--- stderr ---\n${stderr}` }] };
  }
);

const transport = new StdioServerTransport();
await server.connect(transport);
