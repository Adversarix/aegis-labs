// Unit tests for the enforcing mediation plane (policy.js + marker.js).
// Pure logic, no MCP/Docker. Run: node test-policy.mjs
import { evaluate, DEFAULT_SCOPE } from "./policy.js";
import { signMarker, verifyMarker } from "./marker.js";

let pass = 0, fail = 0;
const ok = (name, cond) => { (cond ? (pass++, console.log(`  ok  ${name}`)) : (fail++, console.error(`FAIL  ${name}`))); };

const noKill = { killed: false, reason: "" };

// --- default-deny -------------------------------------------------------------
ok("unknown tool denied (default-deny)",
   evaluate(DEFAULT_SCOPE, noKill, "curl").check === "default-deny");
ok("tool outside scope denied (default-deny)",
   evaluate(DEFAULT_SCOPE, noKill, "run_shell").decision === "deny");

// --- target-isolation ---------------------------------------------------------
// run_shell is IN nobody's allowlist here, so widen the scope to prove the
// isolation check specifically fires (not just the allowlist).
const scopeWithShell = { ...DEFAULT_SCOPE, allowed_tools: ["run_shell", "run_poc", "fuzz"] };
const shellVerdict = evaluate(scopeWithShell, noKill, "run_shell");
ok("run_shell denied by target-isolation even when in allowlist",
   shellVerdict.decision === "deny" && shellVerdict.check === "target-isolation");

// --- allow --------------------------------------------------------------------
ok("run_poc allowed (in scope, green, isolated)",
   evaluate(DEFAULT_SCOPE, noKill, "run_poc").decision === "allow");
ok("fuzz allowed (in scope, green, isolated)",
   evaluate(DEFAULT_SCOPE, noKill, "fuzz").decision === "allow");

// --- kill-gate ----------------------------------------------------------------
const killed = { killed: true, reason: "external" };
ok("kill-gate denies an otherwise-allowed tool",
   evaluate(DEFAULT_SCOPE, killed, "run_poc").check === "kill-gate");

// --- signed markers -----------------------------------------------------------
const key = "test-key-0123456789";
const m = signMarker(key, { run_id: "r", seq: 1, tool: "run_poc", ts: "2026-08-01T00:00:00Z" });
ok("marker verifies with correct key", verifyMarker(key, m) === true);
ok("marker fails with wrong key", verifyMarker("other-key", m) === false);
ok("marker fails when a field is tampered", verifyMarker(key, { ...m, tool: "run_shell" }) === false);
ok("marker fails when hmac is stripped", verifyMarker(key, { ...m, hmac: undefined }) === false);
ok("field order does not change the mac",
   signMarker(key, { a: 1, b: 2 }).hmac === signMarker(key, { b: 2, a: 1 }).hmac);

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
