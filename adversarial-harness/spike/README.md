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

## Days 2–5

Not yet scaffolded — this dir currently covers Day 1 only. Day 2 (Goose vs
OpenCode fork bake-off) clones live outside the repo (they are large and
throwaway); point their provider `base_url` at the same local endpoint used here.
