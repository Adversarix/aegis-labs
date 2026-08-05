# Week-One Spike — scaffolding (historical)

Throwaway-friendly harness for the week-one spike (`../week-one-spike.md`,
`../DESIGN.md` §8). Green tier only: no third-party targets, no network egress,
no microVM, no arming, no disclosure. Day 1 executes nothing — it only checks
that a model *emits* a parseable tool call.

> **Graduated.** The mature harness that grew out of this spike now lives in
> [`../src/`](../src) (the `aegis` CLI, the enforcing mediation seam, the develop
> and operator stages, the munitions store, detonate, and the disclosure workflow —
> see [`../src/README.md`](../src/README.md)). What remains in this directory is only
> the genuine Day-1..5 spike scaffolding, kept as a dated record.

## Layout

| Path | Role |
|---|---|
| `schema/run_shell.tool.json` | the single shared tool schema (same for every backend) |
| `backends.conf` | per-backend endpoint + model — **the reusable neutrality artifact**. No secrets. |
| `roundtrip.sh <local\|hosted>` | Day-1 probe: send shared schema + fixed prompt, check ACCEPTANCE 1 |
| `run-day1.sh` | Day-1 gate: both backends must pass (neutrality is a day-one property) |
| `target/` | Day-4 deliberately-vulnerable C target (the seam that drove it graduated to `../src/mediation-seam/`) |
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
- **Day 3 (mediation seam):** an MCP stdio server Goose loads as its only extension
  (`goose run --no-profile --with-extension`), so every tool call crosses one logged
  chokepoint. Log-only this week; now enforcing and graduated to
  [`../src/mediation-seam/`](../src/mediation-seam/).
- **Day 4 (security tool + target):** `target/` — a deliberately-vulnerable C target in a
  `--network none` container; `run_poc` and `fuzz` tools behind the seam. The agent found
  and confirmed a stack-buffer-overflow.
- **Day 5 (ablation):** with the tools the crash is confirmed with the ASan signal; reason-only
  reaches the same root cause but cannot confirm it.

See `../FINDINGS-week-one-spike.md` for the full write-up.

### Reproduce Days 3–4

```bash
# build the sandbox image (apt clang at build time; runs are --network none)
( cd target && docker build -t spike-fuzz:latest . )
# install seam deps (the seam graduated to ../src/mediation-seam)
( cd ../src/mediation-seam && npm install )
# run Goose with ONLY the mediation seam loaded, security tools behind it
goose run --no-profile --no-session \
  --with-extension "MEDIATION_LOG=$PWD/day4.log SEAM_TOOLS=run_poc,fuzz node $PWD/../src/mediation-seam/server.js" \
  -t "Find an input that crashes this target ... (source inline)"
# every tool call the model made is in day4.log
```

The milestones built after the spike (enforcing seam, develop stage, munitions store,
`aegis` CLI, cross-model compare, detonate, operator cockpit, disclosure) are documented
in [`../src/README.md`](../src/README.md).
