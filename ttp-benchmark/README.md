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

A run over the 20-report seed corpus (K3 and DeepSeek reasoning-minimal):

| model | F1(strict) | F1(parent) | P | R | refusals/errs | median s | cost $/run | $/report |
|---|---|---|---|---|---|---|---|---|
| kimi-k3-fireworks | 0.927 | 0.932 | 0.912 | 0.942 | 0/20 | 7.1 | 0.133 | 0.0067 |
| claude-opus-4-8 | 0.906 | 0.927 | 0.895 | 0.917 | 1/20 | 4.7 | 0.262 | 0.0131 |
| deepseek-v4-pro | 0.844 | 0.907 | 0.862 | 0.826 | 0/20 | 3.9 | 0.027 | 0.0014 |

Read these as directional, not definitive. What drives the ranking:

- **K3 is the best quality-per-cost pick** — top F1, no refusals, ~half Claude's
  cost.
- **Claude refused 1 report** (`stop_reason: refusal` on a benign ransomware
  writeup), which zeroed all 7 of its gold techniques. On the 19 reports every
  model processed, Claude leads on quality (0.933 vs K3 0.922 vs DeepSeek 0.838
  F1). A refusal is silent data loss in an ingestion pipeline, so it is scored as
  a miss here.
- **DeepSeek-V4-Pro is the budget option** — 0.844 F1 at ~1/10th the cost
  ($0.0014/report), but recall-limited (0.826): it under-extracts, missing real
  techniques. Its parent F1 (0.907) is well above strict, so more of its errors
  are wrong-sub-technique near-misses; it closes much of the gap if you only need
  technique-level granularity downstream.
- Both Fireworks-served models show occasional serverless latency spikes (K3 to
  95s, DeepSeek to 32s) that the median hides; Claude (different infra) stayed
  tight.

Reasoning effort does not help this task: at `high`, K3 drops to 0.870 F1
(precision 0.833) for 3x the cost, because the extra reasoning over-specifies
correct parent techniques into wrong sub-techniques. `low` is the right default,
which is why DeepSeek runs with reasoning disabled here too.

### Results (CISA real-advisory corpus, 2026-07-29)

A run over the 25-report CISA corpus (`data/corpus_cisa.jsonl`, built by
`ingest_cisa.py`). This is real advisory prose with the ATT&CK tables and inline
id citations stripped, so it is genuine behavior-to-technique inference:

| model | F1(strict) | F1(parent) | P | R | refusals/errs | median s | cost $/run | $/report |
|---|---|---|---|---|---|---|---|---|
| claude-opus-4-8 | 0.529 | 0.677 | 0.506 | 0.554 | 0/25 | 21.3 | 2.30 | 0.092 |
| kimi-k3-fireworks | 0.496 | 0.647 | 0.517 | 0.477 | 0/25 | 22.9 | 0.84 | 0.034 |
| deepseek-v4-pro | 0.401 | 0.548 | 0.498 | 0.335 | 2/25 | 18.9 | 0.28 | 0.011 |
| qwen3-max | 0.359 | 0.478 | 0.473 | 0.290 | 1/25 | 24.0 | 0.18 | 0.0073 |

Real advisories are much harder than the seed corpus (every model roughly halved
its F1), and that is the point: the tight seed bunching opens into a clear,
stable ranking **Claude > K3 > DeepSeek > qwen3-max** (unchanged if you drop the
JSON-failure reports: 0.535 / 0.505 / 0.441 / 0.372). What the numbers say:

- **Claude is the quality leader** but at ~2.7x K3's cost and ~12x qwen3-max's.
  It refused **nothing** here, despite refusing the synthetic ransomware vignette
  on the seed corpus. The refusal risk appears tied to compact synthetic
  attack-recipe framing, not real advisories (defensive framing, attribution).
- **K3 is the value pick** — within ~0.03 F1 of Claude at a third the cost, zero
  refusals, reliable JSON.
- **qwen3-max finished last despite being Alibaba's proprietary flagship** —
  worst recall (0.290, finds under a third of gold techniques) and it hit the
  same invalid-JSON failure as DeepSeek on the densest advisory (42 gold). It is
  the cheapest ($0.0073/report) but quality-per-dollar it is dominated by K3
  (~4.5x the cost for +0.14 F1 and zero failures). The open-weight K3 beat the
  closed flagship outright.
- **DeepSeek is also hard to recommend** — low recall (0.335) and **invalid JSON
  on the two most technique-dense advisories** (54 and 42 gold), a reliability
  drop on long complex inputs, not truncation. Both budget models crack on the
  hardest real inputs while Claude and K3 stay clean across all 25.
- **Everyone loses ~0.12-0.15 F1 to sub-technique granularity** (parent F1 far
  above strict). If the downstream graph only needs technique-level resolution,
  all four are meaningfully better than the strict column.

Caveats: CISA tables are not exhaustive, so precision (~0.50 for all) is deflated
equally by models extracting real techniques that are described in prose but
absent from the curated table. Trust the ranking more than the absolute F1, and
do not compare these numbers to the seed corpus (different difficulty and label
philosophy) — score them as separate splits.

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
