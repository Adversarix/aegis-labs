// Regression: the fuzz tool must surface a REPLAYABLE crash artifact, so the
// crashing input flows fuzz -> run_poc -> promote_finding without a human
// hand-carrying bytes out of the --rm sandbox.
//
// Two layers: pure parser tests (always run) + a real-sandbox end-to-end that
// runs libFuzzer and replays the recovered bytes through run_poc's target
// (Docker-gated: skips cleanly, does not fail, when docker/the image is absent).
// Run: node test-fuzz-artifact.mjs
import { fuzzArgv, extractReproHex, ARTIFACT_MARKER } from "./artifact.js";
import { execFileSync } from "node:child_process";

let pass = 0, fail = 0, skip = 0;
const ok = (name, cond) => { cond ? (pass++, console.log(`  ok  ${name}`)) : (fail++, console.error(`FAIL  ${name}`)); };
const skipMsg = (name, why) => { skip++; console.log(`  --  skip ${name} (${why})`); };

// --- pure: the wrapper emits the marker, the parser round-trips the bytes -------
const bytes = Buffer.from([0x8b, 0x8b, 0x8b, 0x0a]);
const b64 = bytes.toString("base64");
ok("fuzzArgv is an `sh -c` wrapper carrying the campaign + artifact marker",
   fuzzArgv(20)[0] === "sh" && fuzzArgv(20)[1] === "-c" &&
   fuzzArgv(20)[2].includes("-max_total_time=20") && fuzzArgv(20)[2].includes(ARTIFACT_MARKER));
ok("extractReproHex recovers the artifact bytes as hex",
   extractReproHex(`libfuzzer noise...\n${ARTIFACT_MARKER}\n${b64}\n`) === bytes.toString("hex"));
ok("extractReproHex tolerates CRLF",
   extractReproHex(`${ARTIFACT_MARKER}\r\n${b64}\r\n`) === bytes.toString("hex"));
ok("extractReproHex returns '' when no artifact is present (clean run)",
   extractReproHex("no crash found in 20s") === "");
ok("extractReproHex returns '' on empty/undefined input",
   extractReproHex("") === "" && extractReproHex(undefined) === "");

// --- integration: real sandbox, gated on Docker + the fuzz image ----------------
const IMAGE = process.env.SPIKE_IMAGE || "spike-fuzz:latest";
const haveImage = (() => {
  try { execFileSync("docker", ["image", "inspect", IMAGE], { stdio: "ignore", timeout: 8000 }); return true; }
  catch { return false; }
})();
const sandbox = (argv, input) => {
  try {
    const out = execFileSync("docker",
      ["run", "--rm", "-i", "--network", "none", "--memory", "512m", "--cpus", "1", IMAGE, ...argv],
      { input: input ?? Buffer.alloc(0), encoding: "utf8", timeout: 60000, maxBuffer: 8 * 1024 * 1024, stdio: ["pipe", "pipe", "pipe"] });
    return { code: 0, out, err: "" };
  } catch (e) { return { code: e.status ?? 1, out: e.stdout?.toString() ?? "", err: e.stderr?.toString() ?? "" }; }
};

if (!haveImage) {
  skipMsg("fuzz -> artifact -> run_poc end-to-end", `docker or ${IMAGE} unavailable`);
} else {
  // The campaign is nondeterministic: most runs crash via ASan (SIGABRT) and write
  // the artifact, but some inputs SIGSEGV so hard libFuzzer dies before writing it
  // (~1-in-4 empirically). Retry to obtain the artifact — a genuinely broken
  // surfacing path yields nothing on EVERY attempt, so 6 tries (~0.02% false-fail)
  // absorbs the fuzzer's signal variance without hiding a real regression.
  let hex = "";
  for (let attempt = 1; attempt <= 6 && !hex; attempt++) {
    hex = extractReproHex(sandbox(fuzzArgv(20), Buffer.alloc(0)).out);
  }
  ok("fuzz surfaces a non-empty reproducer_input_hex on a crash", hex.length > 0);
  ok("the surfaced artifact overflows the 16-byte buffer (>16 bytes)", (hex.length / 2) > 16);
  // Replay the EXACT recovered bytes through run_poc's target. The claim under test
  // is reproduction = the surfaced input crashes the target (non-zero exit), which
  // is deterministic for any >16-byte input. We do NOT assert the exact ASan string:
  // this target under x86_64 ASan crashes ~83% via an ASan stack-buffer-overflow
  // report and ~17% via a raw SIGSEGV with no report — both are the same bug
  // reproducing, so requiring the report text would be flaky. ASan is noted when seen.
  const pr = hex ? sandbox(["/work/vuln_poc"], Buffer.from(hex, "hex")) : { code: 0, out: "", err: "" };
  ok("run_poc reproduces the crash from the surfaced artifact (non-zero exit)",
     hex.length > 0 && pr.code !== 0);
  if (/AddressSanitizer: stack-buffer-overflow/.test(pr.err + pr.out))
    console.log("  ..  ASan confirmed the reproduction as stack-buffer-overflow");
}

console.log(`\n${pass} passed, ${fail} failed, ${skip} skipped`);
process.exit(fail === 0 ? 0 : 1);
