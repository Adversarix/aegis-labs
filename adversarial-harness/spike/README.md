# Week-One Spike — scaffolding

Throwaway-friendly harness for the week-one spike (`../week-one-spike.md`,
`../DESIGN.md` §8). Green tier only: no third-party targets, no network egress,
no microVM, no arming, no disclosure. Day 1 executes nothing — it only checks
that a model *emits* a parseable tool call.

## Layout

| Path | Role |
|---|---|
| `schema/run_shell.tool.json` | the single shared tool schema (same for every backend) |
| `backends.conf` | per-backend endpoint + model — **the reusable neutrality artifact**. No secrets. |
| `roundtrip.sh <local\|hosted>` | Day-1 probe: send shared schema + fixed prompt, check ACCEPTANCE 1 |
| `run-day1.sh` | Day-1 gate: both backends must pass (neutrality is a day-one property) |
| `out/` | raw backend responses (gitignored; evidence for the findings doc) |

## Keys

`roundtrip.sh` resolves each backend's API key at run time from the `*_KEY_VAR`
env var named in `backends.conf`, sourcing the repo's existing
`exploitgym-eval/.env` and `ttp-benchmark/.env`. Nothing secret lives in this dir.

## Day 1 — run it

```bash
# prerequisites: Ollama serving locally (ollama serve), a hosted key in the repo .env
ollama pull qwen3.6:latest          # or any tool-calling model; update backends.conf
bash run-day1.sh                    # runs local + hosted, prints the neutrality verdict
```

**ACCEPTANCE 1:** both responses carry a well-formed `tool_calls[0].function`
with parseable JSON arguments. If one backend replies in prose or emits malformed
arguments, that is the format risk surfaced on day one — fix the backend's
tool-call flags/template or the abstraction's normalization, or drop to a smaller
known-good model. Do not proceed to Day 2 until both pass.

## Swapping backends

Selecting a backend is configuration only (`DESIGN.md` §1.1). To retarget, edit
`backends.conf` (`*_BASE_URL`, `*_MODEL`, `*_KEY_VAR`) — any OpenAI-compatible
`/v1/chat/completions` endpoint works (Ollama, vLLM, Fireworks, DashScope, ...).
The vLLM re-check (its `--tool-call-parser` is backend-specific) is deferred to
Day 4–5 per the runbook.

## Days 2–5 (complete — all gates passed)

- **Day 2 (fork bake-off):** Goose chosen over OpenCode. The fork binaries are large
  and throwaway, so they live outside the repo (installed into the session scratchpad).
- **Day 3 (mediation seam):** `mediation-seam/` — an MCP stdio server Goose loads as
  its only extension (`goose run --no-profile --with-extension`), so every tool call
  crosses one logged chokepoint. Log-only this week.
- **Day 4 (security tool + target):** `target/` — a deliberately-vulnerable C target in a
  `--network none` container; `run_poc` and `fuzz` tools behind the seam. The agent found
  and confirmed a stack-buffer-overflow.
- **Day 5 (ablation):** with the tools the crash is confirmed with the ASan signal; reason-only
  reaches the same root cause but cannot confirm it.

See `../FINDINGS-week-one-spike.md` for the full write-up.

### Post-spike milestone — enforcing seam

The seam is now **enforcing** by default (was log-only during the spike). It
evaluates `DESIGN.md` §6 invariants — default-deny, target-isolation, signed
markers, kill-gate — and on a `deny` verdict the tool does not execute. See
[`mediation-seam/README.md`](./mediation-seam/README.md) and run
`cd mediation-seam && npm test`. Still green-tier; amber/red and dry-run-first
remain deferred.

### Post-spike milestone — develop stage (exploit dev)

The develop-stage build-first slice (`../develop-stage.md` §8): a mitigations-off
ret2win target ([`develop/`](./develop/)) and the exploit-dev tools including the
**persistent-debugger Interactive Agent Tool**, behind the enforcing seam
([`develop-seam/`](./develop-seam/)). An agent climbed the exploitation ladder to
**L4** (working exploit firing a signed objective marker, 10/10). The
with/without-debugger ablation and the ARM64 substrate note are in
[`develop/FINDINGS-develop-stage.md`](./develop/FINDINGS-develop-stage.md).

### Reproduce Days 3–4

```bash
# build the sandbox image (apt clang at build time; runs are --network none)
( cd target && docker build -t spike-fuzz:latest . )
# install seam deps
( cd mediation-seam && npm install )
# run Goose with ONLY the mediation seam loaded, security tools behind it
goose run --no-profile --no-session \
  --with-extension "MEDIATION_LOG=$PWD/mediation-seam/day4.log SEAM_TOOLS=run_poc,fuzz node $PWD/mediation-seam/server.js" \
  -t "Find an input that crashes this target ... (source inline)"
# every tool call the model made is in day4.log
```

### Post-develop milestone — munitions store + discovery→develop handoff

A real custody store ([`munitions-store/`](./munitions-store/)) implements the munitions
custody policy in code: inert-by-default, an append-only HMAC-signed hash-chained ledger,
AES-256-GCM encryption at rest, human-gated dispose (the harness cannot self-authorize
arm/export/dispose), and verified crypto-shred disposal. It is the through-line for the
**discovery→develop handoff**: the discovery seam's `promote_finding` turns a confirmed crash into
an inert munition; the develop seam's `ingest_munition` / `record_progress` pick it up and climb
the ladder. Both seams share the store via `AEGIS_STORE` + `AEGIS_STORE_KEY`; every custody op
still crosses the enforcing gate. See [`munitions-store/README.md`](./munitions-store/README.md).

```bash
( cd munitions-store && node store.test.mjs )         # 20 store unit tests
( cd develop-seam && node handoff-test.mjs )          # end-to-end handoff through both seams
```

### Entry point — the `aegis` CLI

[`aegis/`](./aegis/) is a thin CLI over Goose that packages the seam wiring, scope, keys, model
selection, and the munitions store behind subcommands (`aegis develop --target ramp1
--interactive`, `aegis store dispose <id> --role custodian --actor alice`, `aegis doctor`). It does
not fork Goose. See [`aegis/README.md`](./aegis/README.md).

```bash
node aegis/bin/aegis.js init && node aegis/bin/aegis.js doctor
( cd aegis && node aegis.test.mjs )   # 20 CLI tests
```

### ExploitGym Path-B adapter

[`exploitgym-adapter/`](./exploitgym-adapter/) runs a model against an ExploitGym-style task
*through* the contained develop-seam (our tools + mediation), then emits an ExploitGym-compatible
result the `exploitgym-eval` scorer consumes — Path B to exploitgym-eval's Path A. The develop-seam
gained `AEGIS_TASK_BINARY` to mount an arbitrary target. Proven against a local aarch64 fixture (both
a scripted solver and a live agent capture the flag through our gated tools). Real ExploitGym tasks
need the ExploitGym clone + an x86_64 sandbox — see [`exploitgym-adapter/README.md`](./exploitgym-adapter/README.md).

### Cross-model comparison

[`compare/`](./compare/) runs the same develop task through the same contained seam across several
models (swapped by config) and produces a leaderboard, using the mediation log to turn "solved or
not" into "how it failed". First result on the PIE/ASLR task, spanning a local backend (Ollama) and two hosted ones (Fireworks, DashScope):
qwen3-max, kimi-k3, and the qwen3.6 family solved it cleanly in 3 calls (qwen3-max fastest at 11s), while the
smaller/older models failed by distinct traceable modes — all under identical containment (0 denials).
The neutrality claim holds local and hosted by a config swap; run-to-run non-determinism is visible
(a model flipped solved/failed across batches), which is why a converged comparison reports a range.
See [`compare/FINDINGS-cross-model.md`](./compare/FINDINGS-cross-model.md).

### Red-tier detonate stage (control plane)

[`detonate/`](./detonate/) implements the detonation chamber's substrate-agnostic control plane
(`../detonate-stage.md`, `../DESIGN.md` §6.1): the loop, the six invariants enforced in code, custody
arm/detonate/disarm, the T0 deception sinkhole, and marker injection — with a substrate abstraction.
`LocalHarnessSubstrate` (non-isolating) verifies the whole control plane on any machine, including
the build-first early-exit gate: **teardown guaranteed under a mid-detonation kill**. A real munition
is refused on it; that requires `FirecrackerSubstrate` (real microVM, Linux/KVM), which is
code-complete (`detonate/firecracker-host/`) and ready to deploy on the provisioned GCP host. See
[`detonate/FINDINGS-detonate-build-first.md`](./detonate/FINDINGS-detonate-build-first.md).

```bash
( cd detonate && node detonate.test.mjs )   # 16 tests incl. teardown-under-kill
```
