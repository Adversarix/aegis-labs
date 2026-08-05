// Integration test of the combined-mitigation capstone against ramp4 (PIE + canary + NX).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const DIR = "/Users/kgalappatti/Apps/aegis-research/adversarial-harness/spike/develop-seam";
const transport = new StdioClientTransport({
  command: "node", args: ["server.js"], cwd: DIR,
  env: { ...process.env, SEAM_MODE: "enforcing", SPIKE_TARGET: "/work/ramp4",
    MEDIATION_LOG: `${DIR}/ramp4.log`, AEGIS_MARKER_KEY: "ramp4-key" },
});
const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
await client.connect(transport);
const j = (r) => JSON.parse(r.content[0].text);

const mit = j(await client.callTool({ name: "mitigation_check", arguments: {} }));
console.log("mitigation_check: pie=%s canary=%s nx=%s", mit.pie, mit.canary, mit.nx);

// single-mitigation tool (canary only, static win addr) should FAIL under PIE
const solo = j(await client.callTool({ name: "build_exploit_canary", arguments: { canary_offset: 64, ret_offset: 80, times: 4 } }));
console.log("build_exploit_canary (single-mitigation): reliability=%s (expect 0 under PIE)", solo.reliability);

// combined tool chains both leaks -> should reach L4
const comb = j(await client.callTool({ name: "build_exploit_combined", arguments: { canary_offset: 64, ret_offset: 80, times: 6 } }));
console.log("build_exploit_combined: fires=%d/%d reliability=%s", comb.fires, comb.times, comb.reliability);
console.log("  sample run:", comb.results[0]);

await client.close();
const ok = mit.pie === true && mit.canary === true && solo.reliability === 0 && comb.reliability === 1.0;
console.log("\nRAMP4 TEST:", ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
