# Antares Localizer — Component Spec

**Status:** Draft v0.1 · **Date:** 2026-08-05 · Parent: [`DESIGN.md`](./DESIGN.md) §5.1 (discovery), §6 (mediation), §7 (measurement)
Binds to: [`discovery-stage.md`](./discovery-stage.md) §2 (loop), §3 (Finding), §4 (tools) · [`scoring-adapter.md`](./scoring-adapter.md)

A selectable, learned **localization backend** for the discover stage. Given a CWE
description and a read-only source tree, it returns a ranked list of files likely to
contain that vulnerability class. It realizes the stage's **HYPOTHESIZE** step
(`discovery-stage.md` §2.2) with a purpose-trained policy instead of the general agent.

Antares is Cisco Foundation AI's open-weight family (350M / 1B / 3B, IBM Granite-4.0
base) trained by SFT + GRPO over complete terminal-navigation trajectories for
repository-scale vulnerability localization. On its own VLoc Bench, Antares-1B is
competitive with GPT-5.5 File-F1 while running fully local at ~1 GB.

Design principle, restated (`discovery-stage.md` intro): **the model is reasoning glue
over the analyzers, not a replacement for them.** Antares does not change that — it is a
*specialist that seeds candidates*; the harness still owns the confirm loop, the tools,
and the promotion decision. Every Antares tool call crosses the §6 mediation gate.

---

## 1. Where it binds — one selectable localizer

The discover loop's step 2 is *"static pass → ranked candidate sinks."* Today that is
`sast_scan` + the general agent reading code. Antares is an **alternative producer of the
same artifact**: ranked candidate locations, emitted as `hypothesized` Findings (§3) that
flow into step 3 CONFIRM unchanged.

Per §1.1 (neutrality), Antares is **not privileged**: it is one `localizer` backend,
selected by config, never wired into the loop as the way localization works. A run may
use `sast`, `agent`, `antares`, or an ensemble — the downstream Finding contract (§3) and
the confirm loop are identical regardless.

```
discover loop (discovery-stage.md §2), HYPOTHESIZE step:

  AnalysisTarget ──▶ localizer backend ──▶ ranked candidates ──▶ hypothesized Findings
                     { sast | agent |          (files, rank)         (§3) ──▶ CONFIRM
                       antares | … }
```

## 2. Why the shape fits

- **Action space is already green-tier.** Antares explores with `ls, find, cat, head,
  tail, grep, rg, tree` — exactly the `code_read` / `code_search` surface (§4, static,
  green, no target execution). Nothing it does executes the target, so it never forces
  isolation (§5).
- **Its task contract is the harness's measured contract.** Antares consumes a CWE +
  a repo and emits ranked file paths, scored against a held-out ground-truth location.
  That is precisely `AnalysisTarget.ground_truth {location, cwe}` — "the scorer's key,
  never exposed to the agent" (§1, §7).
- **Its failure mode is absorbed by CONFIRM (§8).** Antares over-flags on already-patched
  / benign code (see head-to-head, §10 evidence). In a standalone scanner that is fatal;
  here a false hypothesis simply fails confirmation and is `dismissed`. The harness's
  confirm loop *is* the verifier the specialist lacks.

## 3. Integration mode — sub-agent, not the L2 loop

Antares is a **monolithic self-loop** (it drives its own ≤15-call terminal navigation and
submits an answer), which is the opposite shape from L2's "glue over mediated tools." It
therefore integrates as a **mediated sub-agent invoked as a capability**, not as the L2
agent (`DESIGN` §4 L2):

```
L2 agent  ──calls──▶  localize(target, cwe)          # a mediated capability
                          │
                          ▼
                    Antares inner loop (≤15 turns)
                          │  each `terminal` call ↓
                          ▼
                    §6 mediation gate  ──▶  code_read / code_search  (green, read-only)
                          │  observation (truncated 2000 chars) ↑
                          ▼
                    submit_vulnerable_files → ranked candidates
```

The inner loop's terminal calls are **not** a private shell — they are rewritten into the
stage's mediated `code_read` / `code_search` tools and logged into the same trajectory
(§7). Antares gets no capability the general agent would not; it just uses the green,
read-only subset with a trained policy.

## 4. Interface

### Input

```
LocalizeRequest {
  target_ref     # AnalysisTarget.source_ref — read-only tree mount
  cwe            # CWE id + category description (the only task signal)
  budget?        # max mediated calls (default 15, matching training)
  # ground_truth is NEVER passed here — scorer's key only (§7)
}
```

### Tool mapping (Antares native → harness mediated)

| Antares tool | Mediated as | Tier | Exec |
|---|---|---|---|
| `terminal{command}` (ls/find/cat/grep/rg/tree/head/tail) | `code_read` / `code_search` (§4) | green | no |
| `submit_vulnerable_files{ranked_files}` | terminal action → `LocalizeResult` | — | no |
| `submit_no_vulnerability_found{}` | terminal action → empty `LocalizeResult` | — | no |

Any command outside the read-only navigation set is **denied at the gate** (§6) and the
denial is fed back as the observation — a first-class, logged result, not a crash.

### Output

```
LocalizeResult {
  ranked_files[]     # ordered candidate paths, repo-relative
  abstained          # true iff submit_no_vulnerability_found
  trajectory_ref     # the mediated call trace (§7)
  backend            # {id: "antares", model, version}
}
```

## 5. From candidates to Findings (§3)

Each element of `ranked_files` becomes a Finding in `status: hypothesized`:

```
Finding {
  status     = hypothesized
  method     = static
  location   = {file}                      # file-level; CONFIRM refines to file:line
  bug_class  = <cwe from the request>
  hypothesis = "antares ranked #k for <cwe>"
  evidence   = { localizer: {backend: "antares", rank: k} }
  provenance = { tools_used: [...], trajectory_ref }
}
```

These enter CONFIRM (§2.3) like any hypothesis. Antares assigns no `reproducer` and no
`exploitability` — those are earned in confirm, not asserted by the localizer.

## 6. Mediation binding (§6)

- **Tier:** green throughout — read-only source navigation, no target execution, no
  network. The inner loop cannot escalate; the gate rejects any non-navigation command.
- **Budget:** the ≤15-call terminal budget is a mediation-enforced quota, logged.
- **Trajectory:** every mediated call + verdict + observation is captured into the run's
  trajectory (§7), identically to the general agent, so Antares runs are re-scorable
  offline and comparable to other backends.
- **Scope:** honors `AnalysisTarget.scope_tier`. For `amber` (real third-party source),
  read-only navigation stays green — Antares never executes — but the source mount and
  logging follow the amber substrate rules (§5, §6.2).

## 7. Measurement (§7, scoring-adapter.md)

Localization has crisp ground truth, so it scores through the standard adapter pipeline
(`scoring-adapter.md`): a `discovery-localization` adapter reads `LocalizeResult.ranked_files`
from the normalized `RunEvidence` and scores against `AnalysisTarget.ground_truth.location`.

```
ScoreResult (discovery-localization adapter)
  objective   = ground_truth.location ∈ ranked_files            # localized at all?
  score       = File-F1(ranked_files, ground_truth.location)    # primary [0,1]
  submetrics  = { rank_of_truth, precision, recall,
                  abstained, calls_used }
  requires    = ["artifacts.localize_result", "task.ground_truth"]
```

Because the adapter is a pure function of evidence and selected by config, this gives the
neutrality payoff for free (§1.1): run `antares`, `agent`, and `sast` over the **same**
measured targets and compare File-F1 + cost under one scorecard. The abstention submetric
is where the specialist's weakness (§8) shows up as data, not a hidden failure.

## 8. Why the false-positive weakness is safe here

Head-to-head evidence (§10): across three positive CWE tasks Antares-1B tied gpt-oss:20b
and qwen3-coder:30b at File-F1 = 1.0 while running 3–5× faster, but on a **patched**
repo (no vulnerability) Antares submitted a file where both generalists correctly
abstained. Standalone, that over-flagging makes it untrustworthy as a scanner.

Inside this harness it is contained by construction: an Antares hypothesis is not a
verdict. It promotes to `confirmed_vuln` only after CONFIRM (`taint_query`,
`build_target` + `fuzz`, `run_poc`, `triage_crash`) produces evidence. A false hypothesis
costs confirm budget and is `dismissed`. The design's "tools find and confirm; the model
hypothesizes" split is exactly the mitigation.

**Corollary (non-goal):** Antares must not be used to *gate* a clean verdict. "No
vulnerability here" is a CONFIRM-and-exhaustion conclusion, never an Antares abstention.

## 9. Serving & ops

- **Backend:** local, OpenAI-compatible endpoint (the L3 provider abstraction). Validated
  on ollama with a **tool-capable template** — the stock quant ships none (raw
  completion), so the served GGUF must carry the Granite tool template
  (`<tools>` / `<tool_call>`) or Antares's own `chat_template.jinja`. Pin this in the
  backend config; treat a template-less serve as a misconfiguration.
- **Model variant:** Antares-1B (Laptop/Workstation tier) is the default; 3B for higher
  localization quality, 350M for bulk/first-filter. All share the interface.
- **Config (illustrative):**

```
localizer:
  backend: antares
  model:   antares-1b
  endpoint: ${OLLAMA_OPENAI_ENDPOINT}
  budget:  15
  require_tool_template: true
```

## 10. Non-goals & limits

- **Source + CWE-known only.** Antares localizes a *named* weakness class over *source*.
  It does nothing for binary-only fuzzing or 0-day-from-scratch — those remain the general
  agent + dynamic tools. It is an accelerator for the **n-day / disclosed-CWE** slice of
  discovery, not the whole stage.
- **Not a verdict engine.** See §8 corollary.
- **Frozen external policy.** Unlike the harness's owned confirm loop, Antares is a fixed
  third-party policy. It aligns with the local/contained ethos (open-weight, no egress),
  but the "own the localization policy" principle is satisfied by CONFIRM, not by Antares.
- **Template-fidelity caveat.** Validation to date used Granite's generic tool template,
  not Antares's exact trained serialization; behavioral edges (esp. abstention) should be
  re-checked against the native template before relying on them.

## 11. Build-first slice

Smallest end-to-end that proves the binding:

1. `localize(target, cwe)` capability: serve Antares-1B (tool-capable template), drive the
   ≤15-call loop with its native system prompt, **route each `terminal` call through the
   mediation gate** as `code_read`/`code_search`.
2. Emit `ranked_files` → `hypothesized` Findings (§5) with `trajectory_ref`.
3. `discovery-localization` scoring adapter (§7): File-F1 vs `ground_truth.location`.
4. On one measured target, run `localizer: antares` and `localizer: agent` and produce a
   single StageScorecard comparing File-F1 + calls + wall-clock.

Acceptance: an Antares hypothesis reaches CONFIRM through the real gate, a patched-target
false positive is `dismissed` by confirm (not by the scorer), and the scorecard reports
both backends over identical ground truth.

## 12. Open items

- **Template fidelity** — obtain/pin Antares's exact `chat_template.jinja`; quantify any
  abstention delta vs the generic Granite template.
- **Ensemble localization** — union/re-rank Antares candidates with `sast_scan` before
  CONFIRM; does the union raise recall without flooding confirm budget?
- **Budget economics** — Antares's cheap 15-call pass vs confirm cost: at what
  candidate-count does seeding with Antares stop paying for itself?
- **Line-level refinement** — Antares localizes to file; CONFIRM needs `file:line`. Whose
  job is the narrowing — a follow-up Antares turn, or taint/symbolic in confirm?
- **3B vs 1B in-harness** — does the larger variant's localization gain survive once
  CONFIRM filters false positives, or does 1B + confirm dominate on cost?
