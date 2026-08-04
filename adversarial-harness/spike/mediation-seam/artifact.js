// Fuzz crash-artifact recovery — shared by the fuzz tool (server.js) and its
// regression test so the sandbox wrapper and the parser cannot drift apart.
//
// libFuzzer runs in a --rm sandbox, so a crash artifact it writes to /tmp/crash-*
// dies with the container and the crashing input never escapes the box. The
// wrapper below emits that artifact on stdout (base64, behind a marker line)
// AFTER the campaign, so run_poc can replay it and promote_finding can take it
// into custody. Isolation is unchanged: still one --network none docker run.

export const ARTIFACT_MARKER = "===AEGIS_ARTIFACT===";

// argv for `docker run <image> ...` that runs libFuzzer then, if it left a crash
// artifact, prints the marker line followed by the artifact bytes as base64.
export function fuzzArgv(secs) {
  const script =
    `/work/vuln_fuzz -max_total_time=${secs} -artifact_prefix=/tmp/ ; rc=$? ; ` +
    `for f in /tmp/crash-* /tmp/oom-* /tmp/timeout-* ; do ` +
    `[ -f "$f" ] && { printf '\\n${ARTIFACT_MARKER}\\n' ; base64 -w0 "$f" ; printf '\\n' ; break ; } ; done ; ` +
    `exit $rc`;
  return ["sh", "-c", script];
}

// Recover the crashing input from wrapped fuzz stdout, hex-encoded for run_poc
// (input_hex) and promote_finding (reproducer_input_hex). "" when no artifact.
export function extractReproHex(stdout) {
  const marker = ARTIFACT_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const m = (stdout || "").match(new RegExp(`${marker}\\r?\\n([A-Za-z0-9+/=]+)`));
  if (!m) return "";
  try { return Buffer.from(m[1], "base64").toString("hex"); } catch { return ""; }
}
