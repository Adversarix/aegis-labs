// Integration test of the L5 robustness assessment against ramp1 (PIE/ASLR).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const DIR = "/Users/kgalappatti/Apps/aegis-research/adversarial-harness/spike/develop-seam";
const transport = new StdioClientTransport({
  command: "node", args: ["server.js"], cwd: DIR,
  env: { ...process.env, SEAM_MODE: "enforcing", SPIKE_TARGET: "/work/ramp1",
    MEDIATION_LOG: `${DIR}/l5.log`, AEGIS_MARKER_KEY: "l5-key" },
});
const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
await client.connect(transport);
const j = (r) => JSON.parse(r.content[0].text);

const adaptive = j(await client.callTool({ name: "assess_robustness",
  arguments: { offset: 72, method: "adaptive", batches: 5, runs: 20 } }));
console.log("adaptive (leak per run):", JSON.stringify({ range: adaptive.range, mean: adaptive.mean, robust: adaptive.robust, level: adaptive.level }));

const staticm = j(await client.callTool({ name: "assess_robustness",
  arguments: { offset: 72, method: "static", batches: 5, runs: 20 } }));
console.log("static (hardcoded addr):", JSON.stringify({ range: staticm.range, mean: staticm.mean, robust: staticm.robust, level: staticm.level }));

await client.close();
const ok = adaptive.robust === true && adaptive.level === "L5" && staticm.robust === false;
console.log("\nL5 TEST:", ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
