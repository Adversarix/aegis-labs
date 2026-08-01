# Adversarial Harness — Week-One Spike Findings

**Status:** _in progress — Day 1 complete_ · Runbook: [`week-one-spike.md`](./week-one-spike.md)

Run dates: `2026-08-01 – <end>` (UTC), on macOS workstation (Apple Silicon, no GPU).
Spike scratch dir: [`spike/`](./spike/) (in-repo scaffolding); raw responses in `spike/out/` (gitignored).

> Purpose (from `DESIGN.md` §8): resolve the tool-call **format risk + backend neutrality**
> (round-trip on a **local and a hosted** backend), the **fork decision**, and produce one
> **raw-vs-tool capability** data point — by building. Green tier only; no third-party
> targets, no microVM, no arming, no disclosure.

---

## TL;DR

- **Format risk + neutrality (round-trip on local + hosted):** **resolved** — identical `run_shell` tool schema round-trips through Ollama `qwen3.6:latest` (local) and Fireworks `kimi-k3` (hosted); both emit well-formed `tool_calls` with parseable JSON args, only config swapped. No adapter needed.
- **Fork chosen:** `<goose | opencode>` — `<one line why>` _(Day 2, pending)_
- **Mediation interception clean?** `<yes / no>` — `<one line>` _(Day 3, pending)_
- **Capability signal (found w/ tools vs without):** `<one line>` _(Day 4–5, pending)_
- **Overall verdict:** `<stack viable to proceed / needs rework because …>` _(pending Days 2–5)_

---

## Setup

- **Local backend:** Ollama 0.31.2 / `qwen3.6:latest` (workstation, Apple Silicon, no GPU) —
  OpenAI-compatible `http://localhost:11434/v1`, `tool_choice: auto`, no key. No template/parser
  override needed.
- **Hosted backend:** Fireworks / `accounts/fireworks/models/kimi-k3` —
  OpenAI-compatible `https://api.fireworks.ai/inference/v1`, `tool_choice: auto`, bearer key from
  `exploitgym-eval/.env` (`FIREWORKS_API_KEY`). Same request shape as local.
- **(Optional) GPU backend:** not used — vLLM/`--tool-call-parser` re-check deferred to Day 4–5 (no NVIDIA GPU on this host).
- **CLIs evaluated:** Goose `<rev>`, OpenCode `<rev>` _(Day 2, pending)_.
- **Sandbox:** Docker 29.6.2 available; not exercised on Day 1 (nothing executes — round-trip only).
- **Target (Day 4):** deliberately-vulnerable C (`vuln.c`, stack overflow) + clang
  libFuzzer/ASan _(pending)_.
- **Day-1 harness:** [`spike/`](./spike/) — `run-day1.sh` → `roundtrip.sh {local,hosted}`,
  shared schema `spike/schema/run_shell.tool.json`, config `spike/backends.conf`.

---

## Day 1 — Inference up + raw round-trip

**ACCEPTANCE 1** (well-formed `tool_calls` with parseable args): **PASS (both backends)**

- What was served / how: identical request (shared `run_shell` schema + fixed prompt "What is the
  SHA-256 of /etc/hostname? Use the tool." + `tool_choice: auto`) POSTed to each backend's
  OpenAI-compatible `/v1/chat/completions`. Backend selection is config only (`spike/backends.conf`).
- Raw results (`spike/out/spike_roundtrip_{local,hosted}.json`):
  - **local** (`qwen3.6:latest`): `tool_calls[0].function.name = "run_shell"`,
    `arguments = {"cmd":"sha256sum /etc/hostname"}` — parses.
  - **hosted** (`kimi-k3`): `tool_calls[0].function.name = "run_shell"`,
    `arguments = {"cmd": "sha256sum /etc/hostname"}` — parses.
- Parser/template adjustments needed: **none.** Both backends return `arguments` as an
  OpenAI-style JSON *string*; only cosmetic whitespace differs. The provider abstraction has
  nothing to normalize at this layer for these two backends — the format risk did not
  materialize here (it may still surface on a different model/backend, e.g. a vLLM parser).
- Notes / surprises: first hosted attempt 404'd on a guessed model id
  (`qwen3-235b-a22b`, not deployed on this account); resolved by listing the account's Fireworks
  models and selecting the deployed `kimi-k3`. No prose-instead-of-tool-call failures; no
  early-exit signal (both models engaged the task untooled).

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

- **Local backend + model:** Ollama 0.31.2 / `qwen3.6:latest` (OpenAI-compatible, no GPU, no key).
- **Hosted backend + model:** Fireworks / `accounts/fireworks/models/kimi-k3` (OpenAI-compatible, bearer key).
- **Per-backend tool-call config (each):** both — OpenAI-compatible `/v1/chat/completions`,
  `tool_choice: auto`, shared schema `spike/schema/run_shell.tool.json`, no parser/template override.
  Reusable artifact captured in `spike/backends.conf`.
- **Round-trip held on both?** **Yes** — ACCEPTANCE 1 PASS on local and hosted; neutrality proven day one.
- **Fork chosen + why:** `<…>` _(Day 2, pending)_
- **Adapter needed?** **No** (at L3, for these two backends) — identical schema, identical response shape.
- **Mediation interception clean?** `<…>` _(Day 3, pending)_
- **Ablation result:** `<…>` _(Day 5, pending)_

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
