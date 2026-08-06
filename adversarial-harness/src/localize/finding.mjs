// LocalizeResult -> Findings, and a slice-level CONFIRM (antares-localizer.md §5, §8).
//
// A localizer hypothesis is NOT a verdict. Each ranked file becomes a Finding in
// status:hypothesized (discovery-stage.md §3); CONFIRM must produce evidence before it can
// become confirmed_vuln. This is the mechanism that absorbs the specialist's over-flagging
// (§8): a false hypothesis fails confirmation and is `dismissed` — by CONFIRM, never by the
// scorer.
//
// NOTE: the full discovery-stage CONFIRM (§2.3) is dynamic (taint_query / build_target+fuzz /
// run_poc). For this source + CWE-known slice we implement a STATIC confirm: does the
// hypothesized file actually contain the dangerous sink for the CWE class? A patched file
// (parameterized query, shlex-quoted arg, validated path) has no matching sink and is
// correctly dismissed. This is a deliberate stand-in, not the dynamic confirm.

const cwe = (id) => String(id).match(/CWE-?(\d+)/i)?.[1] ?? String(id);

// Per-CWE sink detectors: return true iff the source text contains an UNSAFE sink for the class.
const SINKS = {
  // CWE-89 SQL injection: user input interpolated into a SQL string (%, f-string, +) then executed.
  // Parameterized queries (execute(sql, params) with ? / %s placeholders bound) do NOT match.
  "89": (s) => /(["'`]).*\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*?\1\s*(%|\+|\.format\(|\}\s*["'`])/i.test(s) ||
               /f(["'`]).*\b(SELECT|INSERT|UPDATE|DELETE)\b[\s\S]*?\{[^}]+\}/i.test(s),
  // CWE-78 OS command injection: a shell command built from input and run with shell=True / os.system.
  "78": (s) => /subprocess\.\w+\([^)]*shell\s*=\s*True/i.test(s) && /(%|\+|\.format\(|f["'`]|\{[^}]+\})/.test(s) ||
               /os\.system\([^)]*(%|\+|\.format\(|f["'`]|\{[^}]+\})/i.test(s),
  // CWE-22 path traversal: a path built from input (join/concat) opened without traversal neutralization.
  "22": (s) => /(os\.path\.join|["'`]\s*\+|\+\s*\w+)/.test(s) && /open\s*\(/.test(s) &&
               !/(realpath|abspath[\s\S]*startswith|normpath[\s\S]*startswith|\.\.["'`]|is_safe|secure_filename)/i.test(s),
};

// toFindings: LocalizeResult -> [Finding] (all status:hypothesized). Abstention yields none.
export function toFindings(result, { trajectory_ref = null } = {}) {
  const klass = cwe(result.cwe);
  return result.ranked_files.map((file, i) => ({
    status: "hypothesized",
    method: "static",
    location: { file },
    bug_class: `CWE-${klass}`,
    hypothesis: `localizer ranked #${i + 1} for CWE-${klass}`,
    evidence: { localizer: { rank: i + 1 } },
    provenance: { tools_used: ["code_read", "code_search"], trajectory_ref },
  }));
}

// confirmSource: advance a hypothesized Finding to confirmed_vuln or dismissed, using a static
// sink check over the file's source. `readFile(path) -> string` is injected (fs or sandbox cat).
export function confirmSource(finding, readFile) {
  const klass = cwe(finding.bug_class);
  const detect = SINKS[klass];
  let src = "";
  try { src = readFile(finding.location.file) || ""; } catch { src = ""; }
  const confirmed = detect ? detect(src) : false;
  return {
    ...finding,
    status: confirmed ? "confirmed_vuln" : "dismissed",
    evidence: { ...finding.evidence, confirm: { method: "static-sink", cwe: `CWE-${klass}`, matched: confirmed } },
  };
}
