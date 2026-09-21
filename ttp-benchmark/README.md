# TTP Extraction Benchmark

A model-agnostic test harness that measures how well different LLMs extract
**MITRE ATT&CK TTPs** from threat-intelligence reports. Built to compare
**Kimi K3 (Fireworks)**, **Claude (Anthropic)**, **DeepSeek**, and
**Qwen (DashScope)**, plus **Jev (TypeSafe)**, a calibrated System One model of a
different class (see [System One model](#system-one-model-jev-calibrated-classification)),
and anything else you add to `config.yaml`.

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
- **Jev (TypeSafe)** needs `TYPESAFE_API_KEY`. It is a System One model at
  `https://api.typesafe.ai/v1` (already in `config.yaml`) and uses the shipped
  candidate file `data/candidates_corpus.json`. Run it with
  `--models jev-typesafe`.

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

### Results (seed corpus snapshot, 2026-07-28; local + proprietary Qwen added 2026-08-17)

A run over the 20-report seed corpus (K3 and DeepSeek reasoning-minimal; local
`qwen3.8:27b` served on-box via Ollama with thinking disabled, so 0 API cost):

| model | F1(strict) | F1(parent) | P | R | refusals/errs | median s | cost $/run | $/report |
|---|---|---|---|---|---|---|---|---|
| kimi-k3-fireworks | 0.927 | 0.932 | 0.912 | 0.942 | 0/20 | 7.1 | 0.133 | 0.0067 |
| claude-opus-4-8 | 0.906 | 0.927 | 0.895 | 0.917 | 1/20 | 4.7 | 0.262 | 0.0131 |
| deepseek-v4-pro | 0.844 | 0.907 | 0.862 | 0.826 | 0/20 | 3.9 | 0.027 | 0.0014 |
| qwen3.8-27b-ollama | 0.764 | 0.838 | 0.795 | 0.736 | 1/20 | 347.4 | 0 | 0 |
| qwen3-max | 0.631 | 0.730 | 0.633 | 0.628 | 0/20 | 6.0 | 0.029 | 0.0014 |

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
- **Open-weight Qwen beats the proprietary Qwen flagship on this task.** Local
  `qwen3.8:27b` (open-weight, run on-box via Ollama) scores 0.764 F1 at zero API
  cost, well clear of the proprietary `qwen3-max` API (0.631, last in the field
  and recall-limited at 0.628). The catch is throughput, not quality: the local
  model runs on the Mac's 48GB unified memory at a 347s median per report and
  one report hit the 30-minute client timeout and returned nothing (the single
  error in its row), roughly 50-70x slower than the hosted models. Read it as a
  free, offline-capable option for batch or air-gapped extraction, not for
  latency-sensitive work.
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

#### By threat category

The 25 CISA reports sliced by type (strict F1, recall in parens):

| model | ransomware (n=8) | APT/nation-state (n=9) | red-team/hygiene (n=4) | other/ICS (n=4) |
|---|---|---|---|---|
| claude | 0.63 (0.62) | 0.47 (0.51) | 0.54 (0.54) | 0.34 (0.48) |
| k3 | 0.61 (0.55) | 0.43 (0.42) | 0.49 (0.48) | 0.33 (0.39) |
| deepseek | 0.52 (0.43) | 0.24 (0.18) | 0.48 (0.41) | 0.33 (0.42) |
| qwen3-max | 0.45 (0.36) | 0.28 (0.22) | 0.37 (0.29) | 0.27 (0.30) |

- **The ranking holds in every category — Claude > K3 uniformly.** No category
  where a cheaper model wins, so there is no model-routing arbitrage; the backend
  choice is a single decision, not per-report-type.
- **Difficulty is dominated by report type.** Every model scores far higher on
  ransomware (~0.6, the standardized #StopRansomware format with canonical TTPs)
  than on APT/nation-state (~0.45, bespoke techniques and freeform narrative). A
  corpus's category mix therefore drives its absolute F1 — read any single number
  in light of its mix.
- **K3 is closest to Claude on structured ransomware (0.61 vs 0.63); Claude's edge
  widens on hard APT.** The premium buys the most on the hardest material.
- **DeepSeek's collapse is concentrated in APT** (F1 0.24, recall 0.18 — both its
  JSON failures fell here). It is least reliable exactly where the hard intel
  lives. This is also why the overall DeepSeek > qwen3-max ordering is only
  ~90% stable: they swap by category (DeepSeek wins ransomware/red-team, qwen3-max
  edges APT).

Per-category n is small (8/9/4/4); ransomware and APT are the reliable slices,
red-team and other (n=4) are suggestive only.

### System One model (Jev): calibrated classification

Beyond the generative LLMs, the harness includes **Jev** (TypeSafe,
`provider: typesafe`), a System One model that returns typed decisions with
probabilities instead of text. It cannot enumerate, so extraction is reframed as
a **Noul sweep**: the report is the model state and it answers one "is technique X
present?" boolean per candidate technique (the 280-technique gold union in
`data/candidates_corpus.json`), keeping those above a probability threshold.
Because it is handed the candidate set, its precision is a closed-world
classification score, not directly comparable to the open-vocabulary LLMs.

On the real CISA advisories (threshold 0.5) Jev matches Claude's F1 (0.51) with
the highest recall of any model (0.80), at about 1/30 the cost ($0.07 vs $2.30
per 25 reports) and 15x the speed (1.5s median), with zero refusals. It
over-predicts on the synthetic seed corpus (0.47 F1).

Its confidence looks miscalibrated against the raw CISA tables (ECE 0.119), but
that is mostly label incompleteness. A blinded LLM-judge pass
(`adjudicate_jev_fp.py`, judge = Claude, not Jev) finds **70% of Jev's
high-confidence false positives are real, untabled techniques** (effective
precision at the 0.9 gate about 88%). Adjudicating the full candidate pool
(`emit_adjudicated_cisa.py`) adds **580 techniques to 635 table labels** and,
re-scored on corrected gold, lifts every model's precision from ~0.50 to
~0.75-0.80:

| model (CISA, adjudicated gold) | P | F1(strict) | F1(parent) |
|---|---|---|---|
| claude-opus-4-8 | 0.79 | 0.58 | 0.72 |
| kimi-k3-fireworks | 0.80 | 0.52 | 0.67 |
| deepseek-v4-pro | 0.75 | 0.39 | 0.55 |
| qwen3-max | 0.71 | 0.34 | 0.47 |
| jev-typesafe (thr 0.5) | 0.72 | 0.76 | 0.78 |

Jev tops F1 here, but that lead is inflated by pool construction: 22% of the
adjudicated gold was surfaced only by Jev, which counts as a miss for the others.
Precision is immune to that bias, and Jev is tunable across its threshold (P 0.72
at 0.5, 0.805 at 0.7 matching the frontier models, 0.895 at 0.9); even at the
precision-matched 0.7 it still leads on F1 by out-recalling the LLMs. The judge
was validated (100% quote grounding, 0/75 negative controls accepted; parent-level
verdicts solid, ~20-30% of sub-technique calls debatable). Full write-up in
`jev-systemone-eval.md`. Reproduce:

```bash
python run_benchmark.py --models jev-typesafe --corpus data/corpus_cisa.jsonl
python analyze_calibration.py                              # Brier / ECE / threshold sweep
python adjudicate_jev_fp.py --threshold 0.9               # high-confidence FP adjudication
python emit_adjudicated_cisa.py --judge claude-opus-4-8   # build corrected gold
python run_benchmark.py --corpus data/corpus_cisa_adjudicated.jsonl  # re-score all models
```

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
data/candidates_corpus.json         280-technique candidate set for the Jev Noul sweep
data/corpus_cisa_adjudicated.jsonl  CISA gold corrected for table incompleteness
analyze_calibration.py    Brier / ECE / reliability + threshold sweep (Jev noul probs)
adjudicate_jev_fp.py      blinded LLM-judge over Jev's high-confidence false positives
emit_adjudicated_cisa.py  build corrected CISA gold from the full candidate pool
jev-systemone-eval.md     the System One (Jev) evaluation note
harness/
  prompts.py              the single shared extraction prompt (identical for every model)
  schema.py               shared output JSON schema + pydantic model
  providers.py            AnthropicProvider + OpenAICompatibleProvider (Kimi/Qwen) + TypeSafeProvider (Jev)
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
