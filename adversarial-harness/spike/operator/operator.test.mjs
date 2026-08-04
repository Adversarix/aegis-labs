// Tests for the operator loop's pure classifier + the seam's mediation scope — no
// docker/fuzzing needed. The full seam-mediated loop is exercised live; see the FINDINGS.
// Run: node operator.test.mjs
import { classify } from "./triage.js";
import { evaluate } from "../mediation-seam/policy.js";

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? (pass++, console.log(`  ok  ${name}`)) : (fail++, console.error(`FAIL  ${name}`)); };

// --- OOM / uncontrolled allocation (the reliable stb finding) ---
const oom = "==1== ERROR: libFuzzer: out-of-memory (used: 2324Mb; limit: 2048Mb)\n" +
  "    #3 0x... in stbi__malloc\nSUMMARY: libFuzzer: out-of-memory";
const c1 = classify(oom, "out-of-memory");
ok("OOM -> uncontrolled-resource-consumption", c1.class === "uncontrolled-resource-consumption");
ok("OOM -> CWE-789", c1.cwe === "CWE-789");
ok("OOM is not weaponizable (honest)", c1.weaponizable === false);
ok("OOM keeps the stbi function", /stbi__/.test(c1.function));

// kind can be inferred from report text even if not passed
ok("OOM detected from report text alone", classify(oom, "crash").cwe === "CWE-789");

// --- heap-buffer-overflow (memory corruption) ---
const oob = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n" +
  "READ of size 4 at 0x...\n    #0 0x... in stbi__gif_load\nSUMMARY: AddressSanitizer: heap-buffer-overflow";
const c2 = classify(oob, "crash");
ok("OOB -> heap-buffer-overflow", c2.class === "heap-buffer-overflow");
ok("OOB -> CWE-122", c2.cwe === "CWE-122");
ok("OOB IS weaponizable", c2.weaponizable === true);
ok("OOB grabs the READ/WRITE size", /READ of size 4/.test(c2.signal));

// --- reachable assertion / other deadly signal ---
const ab = "fuzz_stb: stb_image.h:5327: stbi__bmp_load: Assertion failed.\nSUMMARY: libFuzzer: deadly signal";
const c3 = classify(ab, "crash");
ok("assert -> reachable-crash", c3.class === "reachable-crash");
ok("assert -> CWE-617", c3.cwe === "CWE-617");
ok("assert is not weaponizable", c3.weaponizable === false);

// --- seam mediation scope: operator tools allowed, everything else default-denied ---
const SCOPE = { run_id: "operator-green-run", allowed_tiers: ["green"],
  allowed_tools: ["hunt", "reproduce", "triage", "promote_finding"], isolation: { require_sandbox: true } };
const KILL = { killed: false };
for (const t of ["hunt", "reproduce", "triage", "promote_finding"])
  ok(`seam allows operator tool '${t}'`, evaluate(SCOPE, KILL, t).decision === "allow");
ok("seam default-denies run_shell", evaluate(SCOPE, KILL, "run_shell").decision === "deny");
ok("seam default-denies an unknown tool", evaluate(SCOPE, KILL, "exfiltrate").decision === "deny");
ok("seam default-denies a develop tool out of scope", evaluate(SCOPE, KILL, "build_exploit").decision === "deny");
ok("kill-gate denies an otherwise-allowed operator tool",
  evaluate(SCOPE, { killed: true, reason: "test" }, "hunt").decision === "deny");

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
