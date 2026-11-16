// Evidence tap — the mediation seam's hook into the evidence store
// (evidence-custody-spec.md §5). Every tool that actually executes at the seam
// seals its I/O here, so the bytes the agent reasons over are already under
// custody and a later finding can bind to them. The seam is the only place the
// model's tools run, so it is the right and only place to seal (§5: capture at
// the seam, not self-reported by the agent).
//
// Kept as a tiny module so server.js stays free of test concerns: server.js
// connects a stdio transport at import, this does not, so the wiring is unit-
// testable in isolation.
import { openEvidenceStore } from "../evidence-store/store.js";

// Open a tap. With no `dir` the tap is disabled and seal() is a no-op returning
// null, so the seam runs unchanged when no evidence store is configured (mirrors
// how the munitions STORE is gated on AEGIS_STORE).
export function openEvidenceTap({ dir, key, run_id = null, captured_by = "mediation-seam" } = {}) {
  if (!dir) return { enabled: false, seal: () => null, store: null };
  const store = openEvidenceStore(dir, { key });
  return {
    enabled: true,
    store,
    // Seal one tool execution as a tool_io capture. `io` is the observed I/O
    // (argv, exit, stdout/stderr, input, any tool-specific fields). Returns the
    // content-addressed capture_id. Each execution is its own observation, so
    // these do not dedup (the timestamp makes every call distinct).
    seal(tool, io = {}, marker = null) {
      const doc = JSON.stringify({ tool, ...io, run_id, marker, ts: new Date().toISOString() });
      const { capture_id } = store.seal(doc, {
        media_type: "tool_io",
        captured_by,
        run_id,
        source_meta: { tool, marker },
      });
      return capture_id;
    },
  };
}

// The promote-gate (evidence-custody-spec.md §1, §11 criterion 1). Decides whether a
// finding may be promoted to a munition. When custody is not configured the gate does
// not apply and promotion proceeds (enforced:false), matching the opt-in posture of the
// rest of the evidence path. When it is configured the gate is fail-CLOSED: promotion is
// allowed only if the finding has an active probative binding to a sealed capture, and
// any error reading that binding denies. server.js calls this in the promote_finding
// handler; kept here with the tap so the rule is unit-testable without importing server.js
// (which connects a stdio transport at import).
export function promoteGate(tap, finding_id) {
  if (!tap || !tap.enabled) return { ok: true, enforced: false };
  try {
    if (finding_id && tap.store.hasProbativeBinding(finding_id)) {
      return { ok: true, enforced: true };
    }
  } catch (e) {
    return { ok: false, enforced: true, reason: `custody check failed: ${String(e?.message ?? e)}` };
  }
  return {
    ok: false,
    enforced: true,
    reason: finding_id
      ? `finding '${finding_id}' has no active probative binding to a sealed capture`
      : "promote_finding requires a finding_id bound to a sealed capture",
  };
}
