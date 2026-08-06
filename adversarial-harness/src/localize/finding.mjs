// LocalizeResult -> Findings (antares-localizer.md §5). A localizer hypothesis is NOT a verdict:
// each ranked file becomes a Finding in status:hypothesized (discovery-stage.md §3). CONFIRM
// (confirm.mjs) must produce dynamic evidence before it can become confirmed_vuln — the mechanism
// that absorbs the specialist's over-flagging (§8): a false hypothesis fails confirmation and is
// `dismissed` by CONFIRM, never by the scorer.

const cwe = (id) => String(id).match(/CWE-?(\d+)/i)?.[1] ?? String(id);

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
