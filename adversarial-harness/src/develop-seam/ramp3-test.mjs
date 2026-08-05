// Integration test of the canary-bypass tools against ramp3 (stack canary on).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const DIR = "/Users/kgalappatti/Apps/aegis-research/adversarial-harness/spike/develop-seam";
const transport = new StdioClientTransport({
  command: "node", args: ["server.js"], cwd: DIR,
  env: { ...process.env, SEAM_MODE: "enforcing", SPIKE_TARGET: "/work/ramp3",
    MEDIATION_LOG: `${DIR}/ramp3.log`, AEGIS_MARKER_KEY: "ramp3-key" },
});
const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
await client.connect(transport);
const j = (r) => JSON.parse(r.content[0].text);

const mit = j(await client.callTool({ name: "mitigation_check", arguments: {} }));
console.log("mitigation_check: canary=%s pie=%s nx=%s", mit.canary, mit.pie, mit.nx);
const c1 = j(await client.callTool({ name: "oob_read", arguments: { off: 64 } })).value_hex;
const c2 = j(await client.callTool({ name: "oob_read", arguments: { off: 64 } })).value_hex;
console.log("oob_read@64 (canary) differs per run:", c1, c2, c1 !== c2);
const ex = j(await client.callTool({ name: "build_exploit_canary", arguments: { canary_offset: 64, ret_offset: 80, times: 6 } }));
console.log("build_exploit_canary: fires=%d/%d reliability=%s", ex.fires, ex.times, ex.reliability);

await client.close();
const ok = mit.canary === true && c1 !== c2 && ex.reliability === 1.0;
console.log("\nRAMP3 TEST:", ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
