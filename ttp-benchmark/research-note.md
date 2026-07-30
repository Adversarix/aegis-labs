# Measuring TTP Extraction on Real Threat Intelligence: Leakage, Synthetic-vs-Real, and Backend Selection

**AEGIS Labs research note (draft) — 2026-07-29**

## Abstract

We benchmark four frontier LLMs (Claude Opus 4.8, Kimi K3, DeepSeek-V4-Pro,
Qwen3-Max) on extracting MITRE ATT&CK techniques from threat-intelligence
reports, across a synthetic seed corpus and a corpus of 25 real CISA advisories.
We report four findings that bear on how such benchmarks should be built and how
a backend model should be chosen for a TTP-ingestion pipeline:

1. **Inline-ID leakage.** CISA advisories cite technique IDs inline in prose
   (e.g. "data exfiltration in bulk [T1114.002]"). A benchmark that feeds this
   text to a model without stripping the citations measures copy-paste, not
   extraction. This is easy to miss and inflates scores.
2. **Synthetic corpora do not discriminate models; real advisories do.** All four
   models bunch at 0.84-0.93 F1 on clean synthetic vignettes but spread to
   0.36-0.53 on real advisories, and a stable ranking only emerges on real data.
3. **Refusal is framing-dependent, not content-dependent.** The strongest model
   refused a synthetic ransomware vignette but zero of 25 real ransomware/APT
   advisories describing the same behaviors.
4. **Reasoning effort degrades extraction.** Raising a reasoning model's effort
   from low to high cost 3x and lowered F1, by over-specifying correct parent
   techniques into wrong sub-techniques.

We release the harness, a leakage-safe CISA ingest, and a candidate-pool
adjudication method for correcting non-exhaustive ground-truth tables.

**Provenance.** The core evaluation methodology here — CISA ATT&CK tables as
document-level ground truth, the strict/substantiated split, coverage-delta and
ground-truth re-vetting — is a sanitized public derivation of Adversarix's
internal extraction-evaluation framework. This note's new contributions are (i) a
more thorough input-sanitization step that removes all technique-ID tokens and
tables (not only bracketed citations) so no answer key reaches the model, and
(ii) the four-model comparison and its findings (Sections 3-5). All data used is
public (CISA advisories, public models); no product internals are included.

## 1. Setup

Every model receives the identical prompt and returns the same JSON schema (a
list of ATT&CK technique IDs plus supporting evidence), scored against gold
labels. We report micro-averaged precision/recall/F1 at two granularities:
**strict** (exact ID) and **parent** (sub-technique collapsed to its parent).
Two corpora:

- **Seed** — 20 hand-authored synthetic vignettes, one clean intrusion chain each.
- **CISA** — 25 real AA-series advisories, gold derived from each advisory's
  MITRE ATT&CK table, enterprise techniques only.

## 2. Inline-ID leakage (methodology)

CISA advisories tag behaviors with technique IDs inline in the narrative. If the
report text handed to the model contains "…exfiltration in bulk [T1114.002]",
extraction collapses to copying bracketed tokens, and every model scores near
ceiling regardless of capability. Our ingest strips both the ATT&CK tables and
the inline citations from the prose while leaving the behavior description
intact, so the task is genuine behavior-to-technique inference. After stripping,
0 gold IDs and 0 technique-ID tokens of any kind remain in the prose across all
25 reports.

This matters for any CISA-derived benchmark: the same advisory text is both the
model input and (via its tables/citations) the label source, so input and answer
key must be separated explicitly. The trap is partial stripping — removing
bracketed citations `[T1114.002]` but leaving bare `T1114.002` tokens or the
ATT&CK table in the input still leaks the answers. Complete sanitization removes
all three: bracketed citations, bare ID tokens, and the technique tables.

## 3. Synthetic vs real (results)

| corpus | claude | k3 | deepseek | qwen3-max | spread |
|---|---|---|---|---|---|
| seed (synthetic) | 0.906 | 0.927 | 0.844 | — | 0.08 |
| CISA (real) | 0.529 | 0.496 | 0.401 | 0.359 | 0.17 |

On synthetic vignettes the models are within 0.08 F1 and the ordering is noisy.
On real advisories every model roughly halves its F1 and the ranking becomes
clear and stable (bootstrap over 25 reports: Claude > K3 in 97% of resamples,
K3 > DeepSeek in 100%). **Synthetic TTP-extraction corpora, being clean and
canonical, are a ceiling that cannot separate frontier models.** Absolute F1 on
real advisories is additionally deflated by non-exhaustive CISA tables (Section
6), so the ranking is more trustworthy than the absolute numbers.

## 4. Refusal is framing-dependent (result)

The strongest model refused exactly one seed report — a compact synthetic
ransomware vignette (`stop_reason: refusal`, empty output) — zeroing its labels.
On the 25 real CISA advisories, which describe the same and worse adversary
behavior at far greater length, it refused nothing. The safety trigger tracked
the terse "attack-recipe" framing of the synthetic vignette, not the underlying
malicious content. For defensive pipelines this is reassuring (real advisories
pass) but operationally important: a refused report is silent data loss, so any
pipeline routing through a frontier model needs explicit refusal detection.

## 5. Reasoning effort and backend selection (results)

**Reasoning hurts this task.** Raising Kimi K3 from low to high reasoning effort
dropped strict F1 from 0.927 to 0.870 at 3x the cost and 3.5x the output tokens;
the extra reasoning over-specifies correct parent techniques into wrong
sub-techniques. Extraction is recognition, not multi-step reasoning, so
reasoning-minimal settings are correct.

**Backend selection (CISA, cost per report):**

| model | strict F1 | recall | errors | $/report |
|---|---|---|---|---|
| claude-opus-4-8 | 0.529 | 0.554 | 0/25 | 0.092 |
| kimi-k3-fireworks | 0.496 | 0.477 | 0/25 | 0.034 |
| deepseek-v4-pro | 0.401 | 0.335 | 2/25 | 0.011 |
| qwen3-max | 0.359 | 0.290 | 1/25 | 0.0073 |

The open-weight Kimi K3 lands within 0.03 F1 of Claude at a third the cost, with
zero refusals or malformed output, and it beat the proprietary Qwen3-Max
outright. Both budget models (DeepSeek, Qwen3-Max) emitted invalid JSON on the
most technique-dense advisories — a reliability failure concentrated on exactly
the hardest inputs. Per threat category, the ranking holds uniformly (no
model-routing arbitrage), and difficulty is dominated by report type: every
model scores ~0.6 on standardized ransomware advisories vs ~0.45 on bespoke
nation-state reports.

## 6. Correcting non-exhaustive ground truth (method)

CISA analysts tag a subset of techniques in the advisory table; the prose
typically describes more, so a model extracting a real-but-untabled technique is
scored a false positive, deflating precision (~0.50 for all four models). The
strict/substantiated split that addresses this (report F1 against all table
labels and against only text-substantiated labels) originates in Adversarix's
internal framework; we operationalize its label-vetting step as a released,
reproducible adjudication tool: build a candidate pool per report
(table gold union every model's predictions), surface the supporting prose per
candidate, and have a human keep/drop each against the text with a substantiation
tier (explicit vs inferable). The emitted corpus reports a table-incompleteness
delta (techniques added/removed vs the CISA table). This yields trustworthy
absolute precision/recall, not just a ranking, and quantifies how incomplete
auto-derived CISA ground truth is.

## 7. Takeaways

- CISA-derived TTP benchmarks must strip inline ID citations from model input.
- Evaluate on real advisories, not synthetic vignettes; report a
  strict/substantiated split because table labels are not all extractable.
- For a TTP-ingestion backend, an open-weight model (Kimi K3 here) is the
  quality-per-cost pick; frontier reasoning and proprietary flagship status did
  not help.
- LLM refusal on defensive-security content tracks framing; measure it on real
  data and handle it explicitly.

## Artifacts

Harness, leakage-safe CISA ingest (`ingest_cisa.py`), and adjudication tool
(`adjudicate.py`) released under Apache-2.0/MIT in the AEGIS Labs `ttp-benchmark`
directory. Corpora: 20 synthetic seed reports and 25 CISA advisories with gold
labels.

## Limitations

25 CISA advisories is a small sample; the tier structure is robust but the
Claude-vs-K3 gap magnitude is not tightly bounded (overlapping bootstrap CIs).
CISA tables are non-exhaustive (Section 6). Numbers are point-in-time for the
model versions listed and are not comparable across the two corpora.
