// Realistic MCP client test of the develop-seam (keeps stdin open like Goose).
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

const DIR = "/Users/kgalappatti/Apps/aegis-research/adversarial-harness/spike/develop-seam";
const transport = new StdioClientTransport({
  command: "node", args: ["server.js"], cwd: DIR,
  env: { ...process.env, SEAM_MODE: "enforcing", MEDIATION_LOG: `${DIR}/client.log`, AEGIS_MARKER_KEY: "client-test-key" },
});
const client = new Client({ name: "t", version: "0" }, { capabilities: {} });
await client.connect(transport);

const tools = (await client.listTools()).tools.map((t) => t.name);
console.log("tools:", tools.join(","));

const text = (r) => r.content[0].text;
const j = (r) => JSON.parse(text(r));

const mit = j(await client.callTool({ name: "mitigation_check", arguments: {} }));
console.log("mitigation_check:", { arch: mit.arch, pie: mit.pie, canary: mit.canary, win: mit.symbols?.win });

// persistent debugger sets a breakpoint, then a SECOND call reads it back — proving state persists
console.log("debug break:", text(await client.callTool({ name: "debug", arguments: { cmd: "break vuln" } })).slice(0, 60).replace(/\s+/g, " "));
console.log("debug info breakpoints:", text(await client.callTool({ name: "debug", arguments: { cmd: "info breakpoints" } })).replace(/\s+/g, " ").slice(0, 90));

const off = j(await client.callTool({ name: "find_offset", arguments: { length: 200 } })).offset;
console.log("find_offset ->", off);

const ex = j(await client.callTool({ name: "build_exploit", arguments: { offset: off, win_symbol: "win", times: 5 } }));
console.log("build_exploit:", { win: ex.win, offset: ex.offset, fires: ex.fires, reliability: ex.reliability });

await client.close();
const ok = mit.canary === false && off === 72 && ex.reliability === 1.0;
console.log("\nCLIENT TEST:", ok ? "PASS" : "FAIL");
process.exit(ok ? 0 : 1);
