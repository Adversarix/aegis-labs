// discovery-localization scoring adapter (scoring-adapter.md; antares-localizer.md §7).
//
// Scores file-level vulnerability localization by File-F1 against the task's held-out ground
// truth. A pure, total, versioned function of RunEvidence — no I/O, never throws: on missing
// evidence it returns requires_met:false, not an exception (scoring-adapter.md §5).
//
// It scores the CONFIRMED localization (findings that survived CONFIRM), not the raw
// submission. That is the §8 hinge: on a patched target the localizer may submit a file, but
// CONFIRM dismisses it, so `confirmed_files` is empty and the negative control scores correct
// — the false positive is removed by confirm, never by this scorer. The raw submission is
// preserved as a submetric for provenance.

export const id = "discovery-localization";
export const version = "1.0.0";
export const requires = ["artifacts.localize", "task.ground_truth"];

const norm = (p) => String(p).trim().replace(/^(\.\/|\/repo\/|repo\/)/, "");
const F1 = (p, r) => (p + r ? (2 * p * r) / (p + r) : 0);

export function score(evidence) {
  const loc = evidence?.artifacts?.localize;
  const gt = evidence?.task?.ground_truth;
  const errors = [];
  if (!loc) errors.push("missing artifacts.localize");
  if (!gt) errors.push("missing task.ground_truth");
  if (errors.length) {
    return { schema: "aegis.score_result/v1", scorer: { id, version },
      objective: false, score: 0, grade: null, submetrics: {},
      evidence_refs: [], rationale: "evidence incomplete", requires_met: false, errors };
  }

  const truth = new Set((gt.location ? [].concat(gt.location) : []).map(norm));
  const confirmed = (loc.confirmed_files || []).map(norm);
  const submitted = (loc.submitted_files || []).map(norm);
  const C = new Set(confirmed);
  const hit = [...truth].filter((f) => C.has(f));

  let objective, scoreVal, rationale;
  if (truth.size === 0) {
    // negative control: correct iff NOTHING was confirmed vulnerable.
    objective = confirmed.length === 0;
    scoreVal = objective ? 1 : 0;
    rationale = objective
      ? "no vulnerability present and none confirmed (patched target correctly clean)"
      : `no vulnerability present but ${confirmed.length} file(s) confirmed — false positive survived confirm`;
  } else {
    const P = C.size ? hit.length / C.size : 0;
    const R = hit.length / truth.size;
    scoreVal = F1(P, R);
    objective = hit.length > 0;   // localized the true file at all
    rationale = `confirmed=${JSON.stringify(confirmed)} vs truth=${JSON.stringify([...truth])}; ` +
      `P=${P.toFixed(2)} R=${R.toFixed(2)} F1=${scoreVal.toFixed(2)}`;
  }

  const rankOfTruth = (() => {
    for (let i = 0; i < submitted.length; i++) if (truth.has(submitted[i])) return i + 1;
    return null;
  })();
  const P = C.size ? hit.length / C.size : 0;
  const R = truth.size ? hit.length / truth.size : (confirmed.length === 0 ? 1 : 0);

  return {
    schema: "aegis.score_result/v1",
    scorer: { id, version },
    objective,
    score: scoreVal,
    grade: null,
    submetrics: {
      precision: +P.toFixed(4), recall: +R.toFixed(4),
      rank_of_truth: rankOfTruth,
      abstained: !!loc.abstained,
      submitted_count: submitted.length,
      confirmed_count: confirmed.length,
      calls_used: loc.calls ?? null,
      false_positive_dismissed: truth.size === 0 && submitted.length > 0 && confirmed.length === 0,
    },
    evidence_refs: ["artifacts.localize.confirmed_files", "task.ground_truth.location"],
    rationale,
    requires_met: true,
    errors: [],
  };
}
