// Pure crash triage: turn a libFuzzer/ASan report into an honest classification.
// No I/O, so it is unit-testable in isolation and reproducible. Used by the operator
// seam's `triage` tool. The discipline: never over-claim severity (a DoS is a DoS,
// not memory corruption) — the same honesty the harness exists to enforce on agents.
export function classify(report, kind) {
  const grab = (re) => { const m = report.match(re); return m ? m[0] : null; };
  const fn = grab(/stbi__\w+/) || "decode path";
  if (kind === "out-of-memory" || /out-of-memory/i.test(report)) {
    return { class: "uncontrolled-resource-consumption", cwe: "CWE-789", signal: "libFuzzer OOM",
      function: fn, weaponizable: false, severity: "low (DoS / resource exhaustion)",
      note: "crafted input drives an unbounded allocation" };
  }
  const oob = grab(/(heap|stack|global)-buffer-overflow/);
  if (oob) return { class: oob, cwe: "CWE-122", signal: grab(/(READ|WRITE) of size \d+/) || "ASan",
    function: fn, weaponizable: true, severity: "medium (memory corruption)", note: "" };
  return { class: "reachable-crash", cwe: "CWE-617", signal: grab(/(SEGV|assert\w*)/) || "deadly signal",
    function: fn, weaponizable: false, severity: "low (abort)", note: "" };
}
