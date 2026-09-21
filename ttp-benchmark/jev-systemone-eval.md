# Evaluating a System One Model (Jev) for TTP Extraction: Calibrated Decisions vs Generative Extraction

**AEGIS Labs research note (draft) - 2026-09-21**

## Abstract

We evaluate TypeSafe's **Jev**, a "System One" model that returns typed decisions
with probabilities instead of text, as a backend for MITRE ATT&CK technique
extraction, alongside four generative LLMs (Claude Opus 4.8, Kimi K3,
DeepSeek-V4-Pro, Qwen3-Max). Because Jev cannot enumerate, we reframe extraction
as a **Noul sweep**: the report is the model state and we ask one "is technique X
present?" boolean per candidate technique, keeping those above a probability
threshold. We report five findings:

1. **On clean synthetic vignettes the generative LLMs dominate; on real CISA
   advisories Jev is competitive.** Jev trails badly on synthetic text (0.47 F1
   vs 0.91-0.93 for the top LLMs) but reaches parity on real advisories, where it
   leads on recall.
2. **Against the raw CISA tables, Jev's confidence looks badly miscalibrated**
   (ECE 0.119; a 0.9-1.0 stated-probability bin is correct only 60% of the time).
3. **That miscalibration is mostly a labeling artifact.** A blinded LLM-judge
   adjudication of Jev's high-confidence false positives finds 70% are
   real-but-untabled techniques the CISA tables simply did not tag. Corrected,
   Jev's effective precision at the 0.9 gate is about 88%, and its high-end
   calibration is close.
4. **The CISA tables under-count by roughly half.** Adjudicating the full
   candidate pool adds 580 substantiated techniques to 635 table labels across 25
   advisories. Re-scoring on corrected gold raises every model's precision from
   about 0.50 to 0.75-0.80: the tables were penalizing real extractions across
   the board.
5. **On corrected gold Jev is a strong, cheap, high-recall classifier, but its
   raw F1 lead is inflated by pool construction.** 22% of the adjudicated gold was
   surfaced only by Jev, which depresses the other models' recall. On the
   bias-immune precision axis Jev is tunable to match the LLMs; at a
   precision-matched threshold it still wins on F1, at about 1/30 the cost and 15x
   the speed.

We release the Jev provider, the calibration and adjudication tools, and the
adjudicated CISA corpus.

## 1. Background and method

**System One models.** Jev (`jev-1.13.0`, `POST /v1/systemone`) does not generate
text. It answers typed questions over a fixed answer space and returns a
probability per answer: `Choice` (pick one of N), `Score` (rate on a rubric), and
`Noul` (a single 0-1 truth value). Its stated advantage is *calibrated*
probabilities, produced by a training method the vendor calls RLCD (reinforcement
learning for calibrated decisions), plus a claimed 40-200x latency and cost
advantage from generating all outputs in a single non-autoregressive pass.

**The Noul-sweep reframing.** Extraction is open-vocabulary: a generative model
reads a report and emits whichever techniques it finds. Jev cannot do this, so we
invert it. The report becomes the model `state`, and we ask one Noul per candidate
technique ("does this report describe the adversary using technique X?"). The
predicted set is the techniques scoring at or above a threshold. Candidates are
the 280-technique union of the two corpora's gold labels, with names drawn from
the MITRE ATT&CK STIX catalog. Questions are batched across requests; a full sweep
is about 280 Nouls per report.

**Closed-world caveat.** This hands Jev the label space while the LLMs discover
techniques from open vocabulary. Jev's precision is therefore a multi-label
classification score, not a like-for-like extraction score, and is not directly
comparable to the generative models on that axis. We keep this caveat attached to
every Jev number below.

## 2. Setup

Provider `typesafe` in the existing harness (`config.yaml` key `jev-typesafe`),
threshold 0.5, batch size 40. All per-technique probabilities (positives and
negatives) are stored so calibration can be computed offline. Corpora: the
20-report synthetic seed set and the 25 real CISA advisories from the companion
note (`research-note.md`), both leakage-sanitized. Baselines are the four
generative models from that note, scored from cached predictions.

## 3. Synthetic vs real (raw table gold)

| model | seed F1 | CISA F1 | CISA P | CISA R |
|---|---|---|---|---|
| claude-opus-4-8 | 0.906 | 0.529 | 0.506 | 0.554 |
| kimi-k3-fireworks | 0.927 | 0.496 | 0.517 | 0.477 |
| deepseek-v4-pro | 0.844 | 0.401 | 0.498 | 0.335 |
| qwen3-max | 0.631 | 0.359 | 0.473 | 0.290 |
| **jev-typesafe** (thr 0.5) | 0.471 | 0.506 | 0.371 | **0.797** |

On synthetic text Jev over-predicts and trails. On real advisories it reaches
Claude's F1 and has the highest recall of any model by a wide margin, at the
lowest precision. This is the expected shape of a high-recall classifier tuned at
a permissive threshold, and it mirrors finding 2 of the companion note: synthetic
corpora do not discriminate, real advisories do.

## 4. Calibration: apparent failure, then resolution

Scoring Jev's raw noul probabilities against the raw CISA tables as probabilistic
predictions gives **Brier 0.072, ECE 0.119**, and a monotone overconfidence gap:
every stated-probability bin sits well above the observed frequency. Techniques
Jev calls 0.9-1.0 are gold only 60% of the time; 0.7-0.8 only 21%.

This is confounded by incomplete gold. CISA tables under-count, so a
high-confidence "false positive" may be a real technique the table omitted. To
test this, we ran a blinded LLM-judge adjudication (`adjudicate_jev_fp.py`, judge
= Claude, not Jev) over Jev's 170 high-confidence (>= 0.9) false positives,
asking whether the report **prose** substantiates each technique, with random
low-confidence non-gold techniques mixed in as blind negative controls.

| Jev >= 0.9 false positives | count | share |
|---|---|---|
| substantiated by prose (real, untabled) | 119 | 70.0% |
| genuinely wrong | 51 | 30.0% |
| negative controls accepted | 0 / 69 | 0.0% |

Substantiation rises with confidence (0.95-1.00: 79%; 0.90-0.95: 65%), so the
probability carries real signal. Correcting for untabled truth, Jev's **effective
precision at the 0.9 gate is about 88%** (not 60%), and the top-bin calibration
gap shrinks from roughly 35 points to about 7. The headline miscalibration was
mostly the labels, not the model. Jev remains loose in the mid bands (0.5-0.8),
which is acceptable for a confidence-gated deployment that sets the gate high.

## 5. Adjudicated re-score

We then adjudicated the **full** candidate pool (table gold union every model's
predictions) per report (`emit_adjudicated_cisa.py`), blinded so the judge cannot
tell which model proposed a candidate, keeping table labels as a trusted floor and
only adding substantiated techniques. This added **580 techniques to 635 table
labels** across 25 reports (controls 0/75 accepted): the tables captured roughly
half of what the advisories describe.

Re-scoring all models on corrected gold:

| model | P orig -> adj | R orig -> adj | F1 orig -> adj | F1 parent (adj) | cost | latency |
|---|---|---|---|---|---|---|
| claude-opus-4-8 | 0.51 -> **0.79** | 0.55 -> 0.45 | 0.53 -> 0.58 | 0.716 | $2.30 | 22.7s |
| kimi-k3-fireworks | 0.52 -> **0.80** | 0.48 -> 0.39 | 0.50 -> 0.52 | 0.674 | $0.84 | 24.0s |
| deepseek-v4-pro | 0.50 -> 0.75 | 0.34 -> 0.27 | 0.40 -> 0.39 | 0.550 | $0.28 | 19.9s |
| qwen3-max | 0.47 -> 0.71 | 0.29 -> 0.23 | 0.36 -> 0.34 | 0.472 | $0.18 | 23.8s |
| **jev-typesafe** (thr 0.5) | 0.37 -> 0.72 | 0.80 -> **0.80** | 0.51 -> **0.76** | **0.784** | **$0.07** | **1.5s** |

**The clean result** (precision is not affected by pool construction): correcting
the labels lifts every model's precision to 0.71-0.80. All five models are
precise on real CTI once scored against complete labels.

**The caveat on Jev's F1 lead.** The adjudicated gold can only contain techniques
some model proposed, and Jev proposed the most. **270 of 1215 gold techniques
(22.2%) were surfaced only by Jev**, which is counted as a miss for every other
model and inflates Jev's recall advantage. The F1 gap is an upper bound. Two
debiasing checks:

- Precision, which is immune to this bias, has Jev tunable across its threshold:
  P 0.716 at 0.5, **0.805 at 0.7** (matching the LLMs), 0.895 at 0.9.
- At the precision-matched threshold 0.7 Jev scores P 0.805 / R 0.635 / F1 0.710,
  still above Claude (0.577) and K3 (0.522) on F1, because its recall stays well
  above theirs (0.45 and 0.39).

So the defensible claim is: on real CTI Jev matches frontier LLMs on
per-prediction precision at a comparable operating point, with materially higher
recall, at about 1/30 the cost and 15x the speed. The frontier LLMs are more
precise per prediction at their default behavior; Jev finds more.

## 6. Validating the judge

The entire corrected comparison rests on the judge, so we checked it.

- **Quote grounding: 100%.** Every one of the 580 supporting quotes is a real
  sentence from the advisory (98.1% exact substring, 1.9% whitespace near-match,
  0% fabricated). The judge did not invent evidence.
- **Specificity: 0/75 negative controls accepted** across both adjudication runs.
- **Substantiation quality (18-item spot-read):** at parent-technique level the
  verdicts are largely correct. At sub-technique level roughly 20-30% are
  debatable or wrong-sub (for example, "cracked the password using a wordlist"
  cited for T1110.001 Password Guessing, which is really T1110.002 Password
  Cracking). This is the same failure mode the companion note found in reasoning
  models: correct parent, over-specified sub-technique.

**Consequence.** Trust the **parent-level** results (`F1 parent`) as solid; treat
strict exact-id numbers as approximate, since the adjudicated gold inherits
about 20-30% sub-technique noise. The relative ranking is stable because all
models are scored against the same gold. Publication-grade gold needs a human pass
over sub-technique assignments.

## 7. Limitations

- **Judge is a model, and one of the scored models.** Claude judged gold that
  Claude is scored against. Blinding and the 0% control rate mitigate this, but a
  clean version would use a held-out judge and a human sample.
- **Pool construction cannot recover techniques no model proposed**, so recall
  denominators are still slightly optimistic for everyone.
- **Closed-world advantage for Jev** on the extraction framing, as in Section 1.
- **Sub-technique noise** in the adjudicated gold, per Section 6.
- Single vendor snapshot (`jev-1.13.0`); vendor speed and cost claims are their
  own, though our measured cost and latency are consistent with them.

## 8. Recommendation

For a TTP-ingestion pipeline that feeds the Threat Knowledge Graph, Jev is a
credible **first-stage, high-recall, confidence-gated filter**: cheap and fast
enough to score every advisory against a large candidate set, catching techniques
the generative models miss, with a probability that carries real signal once the
gate is set high (about 88% precise at >= 0.9). A generative model remains better
for open-vocabulary discovery of techniques outside the candidate set and for
per-prediction precision at default settings. A two-stage design (Jev for recall
and triage, an LLM for adjudication and free-form extraction) is the natural next
experiment. The refusal-free, type-safe contract also sidesteps the framing-
dependent refusals documented for the strongest LLM in the companion note.

## Reproduce

```bash
# key in .env: TYPESAFE_API_KEY (see .env.example)
python run_benchmark.py --models jev-typesafe --corpus data/corpus.jsonl
python run_benchmark.py --models jev-typesafe --corpus data/corpus_cisa.jsonl
python analyze_calibration.py                       # Brier / ECE / threshold sweep
python adjudicate_jev_fp.py --threshold 0.9         # high-confidence FP adjudication
python emit_adjudicated_cisa.py --judge claude-opus-4-8   # build corrected gold
python run_benchmark.py --corpus data/corpus_cisa_adjudicated.jsonl \
  --models claude-opus-4-8 kimi-k3-fireworks deepseek-v4-pro qwen3-max jev-typesafe
```

**Provenance.** This note extends `research-note.md` (the four-model TTP
extraction study) with a System One model and a calibration analysis. It reuses
that note's candidate-pool adjudication method for non-exhaustive ground-truth
tables. New here: the Noul-sweep reframing of extraction as calibrated
classification, the confidence-vs-ground-truth calibration analysis, and the
judge-validation step. All data is public (CISA advisories, public models); no
product internals are included.
