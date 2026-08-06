# localize — Antares localizer slice

Build-first slice of [`antares-localizer.md`](../../antares-localizer.md) §11: a **mediated
vulnerability-localization sub-agent** for the discover stage. Given a CWE and a read-only
source tree, a backend drives a ≤15-call source-navigation loop **through the real §6
mediation gate**, its ranked files become `hypothesized` Findings, CONFIRM keeps or dismisses
each, and a File-F1 scorer reports a StageScorecard comparing backends over identical ground
truth. Neutral by construction — the same loop/prompt/tools/scorer run for every model
(`DESIGN.md` §1.1).

## What's here

| File | Role |
|---|---|
| `gate.mjs` | binds to the real gate — reuses `mediation-seam/policy.js` `evaluate()` + `marker.js`; routes each `terminal` call to `code_read`/`code_search` (added to the policy registry) |
| `sandbox.mjs` | read-only `--network none` Docker exec of a navigation command (cwd persists) |
| `backends.mjs` | shared system prompt (Antares report App A.1) + tool schemas + ollama chat |
| `localizer.mjs` | the mediated loop (deps injected → unit-testable without a model/Docker) |
| `finding.mjs` | `LocalizeResult` → `hypothesized` Findings; **CONFIRM** (static sink check; §8) |
| `../scorers/discovery-localization.mjs` | File-F1 scoring adapter (scoring-adapter.md contract) |
| `run.mjs` | head-to-head runner → `scorecard.{json,md}` |
| `fixtures/` | `webapp` (CWE-89 SQLi, ground truth `models/user.py`) + `webapp_patched` (negative control) |

The full discovery CONFIRM (§2.3) is dynamic (taint/fuzz/run_poc). This slice uses a **static
sink confirm** as a deliberate stand-in for the source + CWE-known case — enough to demonstrate
that a false positive is dismissed by CONFIRM, never by the scorer (§8).

## Test (CI-safe, no model/Docker)

```
cd src/localize && node localize.test.mjs      # 26 tests: gate routing, loop, confirm, scoring
```

## Head-to-head (needs ollama + Docker + the sandbox image)

```
docker build -t antares-sandbox - <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ripgrep tree ca-certificates && rm -rf /var/lib/apt/lists/*
EOF

node run.mjs \
  --backends antares=hf.co/DevQuasar/fdtn-ai.antares-1b-GGUF:Q8_0,agent=gpt-oss:20b \
  --endpoint http://<ollama-host>:11434 --image antares-sandbox --out runs/h2h
```

The served Antares model MUST carry a tool-capable template (§9); the stock quant ships none —
DevQuasar's GGUF embeds Granite's. Acceptance: an Antares hypothesis reaches CONFIRM through the
real gate, the patched-target false positive is `dismissed` by CONFIRM (not the scorer), and the
scorecard reports both backends over identical ground truth.
