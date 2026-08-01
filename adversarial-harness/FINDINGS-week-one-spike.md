# Adversarial Harness — Week-One Spike Findings

**Status:** _template — fill during/after the run_ · Runbook: [`week-one-spike.md`](./week-one-spike.md)

Run dates: `<start> – <end>` (UTC), on `<host / GPU VM, region, project>`.
Spike scratch dir: `<path>`.

> Purpose (from `DESIGN.md` §8): resolve the tool-call **format risk + backend neutrality**
> (round-trip on a **local and a hosted** backend), the **fork decision**, and produce one
> **raw-vs-tool capability** data point — by building. Green tier only; no third-party
> targets, no microVM, no arming, no disclosure.

---

## TL;DR

- **Format risk + neutrality (round-trip on local + hosted):** `<resolved / blocked>` — `<one line>`
- **Fork chosen:** `<goose | opencode>` — `<one line why>`
- **Mediation interception clean?** `<yes / no>` — `<one line>`
- **Capability signal (found w/ tools vs without):** `<one line>`
- **Overall verdict:** `<stack viable to proceed / needs rework because …>`

---

## Setup

- **Local backend:** `<Ollama <ver> / model>` (workstation, no GPU) — tool-call config `<…>`.
- **Hosted backend:** `<provider / model>` — tool-call config `<…>`.
- **(Optional) GPU backend:** `<vLLM <ver> / model / GPU>` if used for the capability step.
- **CLIs evaluated:** Goose `<rev>`, OpenCode `<rev>`.
- **Sandbox:** Docker `<image>`, no network, `<cpu/mem caps>`.
- **Target (Day 4):** deliberately-vulnerable C (`vuln.c`, stack overflow) + clang
  libFuzzer/ASan.

---

## Day 1 — Inference up + raw round-trip

**ACCEPTANCE 1** (well-formed `tool_calls` with parseable args): `<PASS / FAIL>`

- What was served / how: `<…>`
- Raw `curl` result (`/tmp/spike_roundtrip.json`): `<emitted a tool_call? args parseable?>`
- Parser/template adjustments needed: `<none | …>`
- Notes / surprises: `<…>`

---

## Day 2 — Fork bake-off (Goose vs OpenCode)

**ACCEPTANCE 2** (≥1 CLI dispatches a tool call end-to-end): `<PASS / FAIL>`

| CLI | Provider config effort | Tool round-trip | Notes |
|---|---|---|---|
| Goose | `<…>` | `<clean / needed adapter / failed>` | `<…>` |
| OpenCode | `<…>` | `<clean / needed adapter / failed>` | `<…>` |

- **Decision:** `<goose | opencode>` because `<…>`.
- **Adapter required?** `<no | yes — describe the format translation>`.

---

## Day 3 — Mediation seam (log-only)

**ACCEPTANCE 3** (every tool call interceptable at one chokepoint, no bypass): `<PASS / FAIL>`

- Where the seam was inserted (loop ↔ tool dispatch): `<…>`
- Sample mediation log line: `<{actor, tool, args, decision:"allow"}>`
- Any dispatch path that bypassed the seam? `<none | …>`
- Implication for the fork decision (if any): `<…>`

---

## Day 4 — One security tool + one target

**ACCEPTANCE 4** (agent produces a confirmed crash via the tool loop): `<PASS / FAIL>`

- Tool(s) added behind the seam: `<run_poc | fuzz>`.
- Task given: _"Find an input that crashes this target."_
- Outcome: `<crashing input found? ASan report surfaced back to the model?>`
- Tool-calls / wall-clock to crash: `<…>`
- Notes: `<…>`

---

## Day 5 — Capability read (raw-vs-tool ablation)

**ACCEPTANCE 5** (documented delta on one task): `<PASS / FAIL>`

| Condition | Found crash? | Tool-calls to find | Wall-clock |
|---|---|--:|--:|
| (a) with `run_poc`/`fuzz` | `<y/n>` | `<…>` | `<…>` |
| (b) tools removed (reason-only) | `<y/n>` | `<…>` | `<…>` |

- **Delta / interpretation:** `<did the security-native tool move the needle?>`
- **Caveats:** `<single task, single model, non-determinism — treat as signal not proof>`

---

## Decision log (from the runbook)

- **Local backend + model:** `<…>`
- **Hosted backend + model:** `<…>`
- **Per-backend tool-call config (each):** `<…>`  ← the reusable artifact
- **Round-trip held on both?** `<…>`
- **Fork chosen + why:** `<…>`
- **Adapter needed?** `<…>`
- **Mediation interception clean?** `<…>`
- **Ablation result:** `<…>`

---

## Red herrings ruled out

_(cf. `exploitgym-eval/FINDINGS-gemini-smoke.md` — record anything that looked like a
result but wasn't.)_

- `<…>`

---

## Takeaways / next steps

- **Stack verdict:** `<proceed with this fork + inference config / rework because …>`
- **Format config to reuse:** `<the working parser/flags line>`
- **Immediate follow-on** (per stage specs): `<e.g. add the persistent debugger IAT →
  develop-stage build-first; or promote the crash to a Finding + custody record>`.
- **Deferred, as planned:** mediation *enforcement*, munitions store, microVM substrate,
  third-party targets, disclosure — none touched this week.
- **Open items this spike informs** (`DESIGN.md` §9): `<fork lock-in resolved; parser
  stability observed as …; anything new surfaced>`.
