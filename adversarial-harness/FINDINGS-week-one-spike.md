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
- **Fork chosen:** **Goose 1.45.0** — both forks dispatched a tool end-to-end against Ollama, but Goose needs zero glue (native `ollama` provider) and its MCP-extension tools give the out-of-loop dispatch chokepoint the Day-3 mediation seam requires. OpenCode is the fallback.
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
- **CLIs evaluated:** Goose 1.45.0 (prebuilt `stable` aarch64-darwin binary), OpenCode 1.18.11
  (prebuilt darwin-arm64 binary). Both installed + run out-of-repo in the session scratchpad
  (`day2/`), configured against the same local Ollama endpoint; isolated via `XDG_*` dirs.
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

**ACCEPTANCE 2** (≥1 CLI dispatches a tool call end-to-end): **PASS (both CLIs)**

Both were installed as prebuilt binaries (no cargo/bun build) and pointed at the Day-1 local
Ollama endpoint. Each was given the same task ("run `echo <marker>`, report stdout"); both had
the model call a shell/bash tool, dispatched it, and returned the output to the model.

| CLI | Provider config effort | Tool round-trip | Notes |
|---|---|---|---|
| Goose 1.45.0 | **none** — native `ollama` provider via env (`GOOSE_PROVIDER=ollama`, `GOOSE_MODEL=qwen3.6:latest`) | **clean** | builtin `developer`/shell extension fired with zero config; single-shot `goose run` returned in seconds |
| OpenCode 1.18.11 | **small** — project `opencode.json` declaring an `ollama` provider (`@ai-sdk/openai-compatible`, `baseURL`, model list) | **clean (after warmup)** | first run stalled ~30-60s fetching the provider npm pkg (timed out at 2m on the first attempt); succeeded on a longer background run |

- **Decision:** **Goose.** Two reasons: (1) least glue — the native `ollama` provider round-trips
  with no config file and no adapter, vs OpenCode's provider block + first-run package-fetch
  latency; (2) the structural reason from `DESIGN.md` §4 L1 — Goose tools are **MCP extensions**, so
  the offensive tool layer *and the mediation plane* live outside the agent loop as a governed
  dispatch layer. That MCP dispatch chokepoint is exactly what Day 3's seam needs. OpenCode remains
  the viable fallback (`DESIGN.md` §9).
- **Adapter required?** **No** for either CLI — both parse the Ollama OpenAI-compatible tool format natively.

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
- **Fork chosen + why:** Goose 1.45.0 — least glue (native `ollama` provider, no config/adapter) + MCP-extension dispatch chokepoint for the mediation seam (`DESIGN.md` §4 L1). OpenCode fallback.
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
