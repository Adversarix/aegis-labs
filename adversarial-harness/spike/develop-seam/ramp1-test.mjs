// Integration test of the leak-based (PIE/ASLR) tools against ramp1.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const DIR = "/Users/kgalappatti/Apps/aegis-research/adversarial-harness/spike/develop-seam";
const transport = new StdioClientTransport({
  command: "node", args: ["server.js"], cwd: DIR,
  env: { ...process.env, SEAM_MODE: "enforcing", SPIKE_TARGET: "/work/ramp1",
    MEDIATION_LOG: `${DIR}/ramp1.log`, AEGIS_MARKER_KEY: "ramp1-key" },
});
const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
await client.connect(transport);
const j = (r) => JSON.parse(r.content[0].text);

const mit = j(await client.callTool({ name: "mitigation_check", arguments: {} }));
console.log("mitigation_check: pie=%s canary=%s", mit.pie, mit.canary);
const l1 = j(await client.callTool({ name: "leak", arguments: {} })).leaked_hex;
const l2 = j(await client.callTool({ name: "leak", arguments: {} })).leaked_hex;
console.log("leaks differ (ASLR):", l1, l2, l1 !== l2);
const off = j(await client.callTool({ name: "find_offset", arguments: { length: 200 } })).offset;
console.log("find_offset ->", off);
const ex = j(await client.callTool({ name: "build_exploit_leak", arguments: { offset: off, times: 6 } }));
console.log("build_exploit_leak: fires=%d/%d reliability=%s", ex.fires, ex.times, ex.reliability);

await client.close();
const ok = mit.pie === true && l1 !== l2 && off === 72 && ex.reliability === 1.0;
console.log("\nRAMP1 TEST:", ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
