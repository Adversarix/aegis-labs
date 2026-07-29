# TTP Extraction Benchmark

A model-agnostic test harness that measures how well different LLMs extract
**MITRE ATT&CK TTPs** from threat-intelligence reports. Built to compare
**Kimi K3 (Fireworks)** vs **Claude (Anthropic)** vs **Qwen (DashScope)** — and
anything else you add to `config.yaml`.

Part of [AEGIS Labs](https://github.com/Adversarix/aegis-labs), the open
research home of Adversarix: TTP extraction is the ingestion step that feeds the
Threat Knowledge Graph, so backend-model choice here directly affects advisory
quality downstream.

## What it measures

For each report, every model returns the same JSON — a list of ATT&CK
technique ids plus supporting evidence — scored against gold labels:

| Metric | Meaning |
|---|---|
| **F1 (strict)** | exact id match — `T1059.001` must equal `T1059.001` |
| **F1 (parent)** | technique-level — sub-technique collapsed (`T1059.001` → `T1059`), so "right technique, wrong sub-technique" still counts |
| **P / R** | micro-averaged precision / recall over the corpus |
| **macroF1** | mean of per-report F1 (weights every report equally) |
| **latency, tokens, cost** | operational cost of each model |

Strict vs parent tells you whether a model is missing techniques outright or
just picking the wrong sub-technique.

## Setup

```bash
cd ttp-benchmark
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env    # fill in the keys you have; then `set -a; . ./.env; set +a`
```

You only need keys for the models you want to run.

- **Claude** — `ANTHROPIC_API_KEY` (or an `ant auth login` profile).
- **Kimi K3** — `FIREWORKS_API_KEY`. Runs against Fireworks' OpenAI-compatible
  endpoint with model id `accounts/fireworks/models/kimi-k3` (already set in
  `config.yaml`). A Moonshot-direct route is included commented-out for anyone
  with a `MOONSHOT_API_KEY` instead.
- **Qwen** — `DASHSCOPE_API_KEY`.

## Run

```bash
python run_benchmark.py                          # all models, full corpus
python run_benchmark.py --models claude-opus-4-8 # just one
python run_benchmark.py --limit 2                # smoke test on 2 reports
python run_benchmark.py --no-cache               # ignore cached responses
```

Output:
- a **comparison table** on stdout + `results/summary.json`
- a **per-report drill-down** on stdout + `results/drilldown.md`
- every raw model response under `results/raw/<model>/<report>.json` (so reruns
  are free and you can eyeball *why* a model scored the way it did)

### Results (seed corpus snapshot, 2026-07-28)

A run over the 20-report seed corpus at `reasoning_effort: low`:

| model | F1(strict) | P | R | refusals/errs | avg s | cost $/run |
|---|---|---|---|---|---|---|
| kimi-k3-fireworks | 0.927 | 0.912 | 0.942 | 0/20 | 7.1 (median) | 0.133 |
| claude-opus-4-8 | 0.906 | 0.895 | 0.917 | 1/20 | 4.7 (median) | 0.262 |

Read these as directional, not definitive. Two things drive the headline gap:

- **Claude refused 1 report** (`stop_reason: refusal` on a benign ransomware
  writeup), which zeroed all 7 of its gold techniques. On the 19 reports both
  models processed, quality is a tie (Claude 0.933 vs K3 0.922 F1). A refusal is
  silent data loss in an ingestion pipeline, so it is scored as a miss here.
- **K3 is ~half the cost and never refused**; Claude is faster and marginally
  more accurate on what it accepts. Both make whole-technique errors far more
  often than sub-technique granularity slips (strict F1 ≈ parent F1 for each).

Reasoning effort does not help this task: at `high`, K3 drops to 0.870 F1
(precision 0.833) for 3x the cost, because the extra reasoning over-specifies
correct parent techniques into wrong sub-techniques. `low` is the right default.

### Per-report drill-down

After the summary table, the harness prints exactly what each model got wrong
on every report:

```
── rep-01  (6 gold) ──────────────────
   gold: T1003.001 T1041 T1059.001 T1204.002 T1547.001 T1566.001
   claude-opus-4-8  hit 6/6   miss: —                                   halluc: —
   kimi-k3          hit 2/6   miss: T1003.001 T1041 T1204.002 T1547.001  halluc: T1105
   qwen3-max        hit 5/6   miss: ~T1059.001                          halluc: ~T1059
```

- **miss** = a gold technique the model failed to predict (false negative).
- **halluc** = a technique the model predicted that isn't in gold (false positive).
- **`~ID`** = parent technique matched — the model got the right technique but the
  wrong sub-technique (`T1059` vs `T1059.001`). This is how you tell a genuine
  hallucination (`T1105` above, unrelated) from a near-miss that only strict
  scoring penalizes. Pass `--no-drill` to skip it.

## Architecture

```
run_benchmark.py          orchestrate: run each model over the corpus, score, tabulate
config.yaml               models under test (+ endpoints, prices)
data/corpus.jsonl         threat-intel reports with gold ATT&CK labels
harness/
  prompts.py              the single shared extraction prompt (identical for every model)
  schema.py               shared output JSON schema + pydantic model
  providers.py            AnthropicProvider (official SDK) + OpenAICompatibleProvider (Kimi/Qwen)
  evaluate.py             precision / recall / F1, strict + parent-level
```

Adding a model = one entry in `config.yaml`. Anything with an OpenAI-compatible
endpoint (most providers) needs no code — just `provider: openai_compatible`
plus its `base_url` and key env var.

## Extending the corpus

`data/corpus.jsonl` ships with **20 hand-labeled seed reports** (121 gold
labels, ~85 unique techniques) spanning phishing/macro chains, ransomware,
cloud/M365 identity attacks, Linux/ESXi, macOS stealers, supply-chain, AD
attacks (Kerberoasting, NTDS, GPO), BEC, insider exfil, and wipers. That's
enough to be directional; expand it for tighter confidence — each line is:

```json
{"id": "rep-07", "source": "...", "text": "<report text>", "gold_techniques": ["T1566.001", "T1059.001"]}
```

Good public sources to label: MITRE ATT&CK procedure examples, CISA advisories,
and the TRAM dataset. Keep gold labels to techniques the text *explicitly*
supports — the harness rewards precision, not actor-attribution guesses.

## Notes & caveats

- This harness is **not** the evaluation framework from the *Measuring TTP
  Extraction* whitepaper, and numbers are not comparable across the two. The
  paper scores the platform's extractor against ground truth auto-derived from
  CISA advisory tables, with half-credit parent matching, a substantiation
  split, and F1 reported as a range over multiple runs. This harness compares
  backend LLMs on a hand-labeled seed corpus and scores parent-level F1 by
  collapsing sub-techniques to their parent (full credit).
- The seed corpus is small; treat early numbers as directional. Score stabilizes
  as you add reports.
- `response_format=json_object` is used for OpenAI-compatible models and
  `output_config.format` (strict structured outputs) for Claude — both target
  the same schema. If a provider doesn't honor JSON mode, the harness still
  recovers JSON from fenced/prose output before failing.
- All models get the **same prompt**. If you tune it, re-run every model.
