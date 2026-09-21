#import "/typst/aegis-whitepaper.typ": whitepaper, toc, callout, citation-block

#show: whitepaper.with(
  title: "Extracting ATT&CK from Real Advisories",
  subtitle: "A Leakage-Safe Benchmark and Backend-Model Comparison for TTP Ingestion",
  version: "0.2 (draft)",
  date: "September 2026",
  tiles: (
    ("K3", "open-weight backend matched the leader and beat the proprietary flagship"),
    ("real > synthetic", "only real advisories separate frontier models"),
    ("0 leaked IDs", "input sanitized so extraction is inference, not copy-paste"),
    ("Jev @ 1/30 cost", "a calibrated System One model matched frontier recall on real advisories"),
  ),
)

#toc()

= Executive Summary

Threat-intelligence ingestion increasingly leans on a large language model to read an advisory and return the MITRE ATT&CK techniques it describes. Choosing which model to run for that step, and measuring how well any of them does it, turns out to be harder than it looks, and most of the difficulty is in the benchmark rather than the models.

We benchmark four frontier models (Claude Opus 4.8, Kimi K3, DeepSeek-V4-Pro, Qwen3-Max) on extracting ATT&CK techniques from threat reports, across a synthetic seed corpus and a corpus of 25 real CISA advisories. We additionally evaluate a model of a different class, TypeSafe's Jev, a System One model that returns typed decisions with calibrated probabilities rather than generated text. Five findings shape both how such a benchmark should be built and which model a production ingestion pipeline should use.

#callout("Key Findings")[
  - *Inline-ID leakage.* CISA advisories cite technique IDs inline in the prose. If that text reaches the model unstripped, the benchmark measures copy-paste, not extraction, and every model scores near ceiling.
  - *Synthetic corpora do not discriminate models; real advisories do.* All four models bunch at 0.84–0.93 F1 on clean synthetic vignettes but spread to 0.36–0.53 on real advisories, where a stable ranking finally emerges.
  - *Refusal is framing-dependent, not content-dependent.* The strongest model refused a synthetic ransomware vignette but zero of 25 real advisories describing the same behavior.
  - *Reasoning effort degrades extraction.* Raising a reasoning model from low to high effort cost 3x and lowered F1, by over-specifying correct parent techniques into wrong sub-techniques.
  - *A calibrated classifier is a viable backend of a different shape.* Reframed as a per-technique classification sweep, the Jev System One model matched frontier recall on real advisories at about 1/30 the cost and 15x the speed, with no refusals. Its probabilities are usable once the ground truth is corrected for incompleteness (Section 9).
]

= Provenance

The core evaluation methodology here, using CISA ATT&CK tables as document-level ground truth with a strict/substantiated split, coverage-delta reporting, and ground-truth re-vetting, is a sanitized public derivation of Adversarix's internal extraction-evaluation framework. This paper's new contributions are a more thorough input-sanitization step that removes every technique-ID token and table from the model input (not only bracketed citations), and the four-model comparison in Sections 5–7. All inputs are public: CISA advisories and publicly available models. No product internals are included.

= What We Measured

Every model receives the identical prompt and returns the same JSON schema, a list of ATT&CK technique IDs plus supporting evidence, scored against gold labels. We report micro-averaged precision, recall, and F1 at two granularities: _strict_ (exact ID) and _parent_ (sub-technique collapsed to its parent). Two corpora carry the study: a _seed_ set of 20 hand-authored synthetic vignettes, one clean intrusion chain each, and a _CISA_ set of 25 real AA-series advisories whose gold is derived from each advisory's ATT&CK table, enterprise techniques only.

= Inline-ID Leakage

CISA advisories tag behaviors with technique IDs inline in the narrative, for example "data exfiltration in bulk [T1114.002]." If the report text handed to the model contains those tokens, extraction collapses to copying them, and every model scores near ceiling regardless of capability. Because the same advisory text is both the model input and, through its tables and citations, the label source, input and answer key must be separated explicitly.

The trap is _partial_ stripping. Removing the bracketed citation `[T1114.002]` but leaving the bare token `T1114.002`, or leaving the ATT&CK technique table in the input, still leaks the answer. Complete sanitization removes all three: bracketed citations, bare ID tokens, and the technique tables, while leaving the behavior description intact. After sanitization, zero gold IDs and zero technique-ID tokens of any kind remain in the prose across all 25 reports.

#callout("Why this is easy to get wrong")[
  A benchmark that harvests labels from the advisory's inline citations and then feeds the same advisory body to the model will report inflated, undiscriminating F1. The label pipeline and the input pipeline read the same tokens for opposite purposes; only the input side must be scrubbed.
]

= Synthetic Versus Real

#table(
  columns: (2.2fr, 1fr, 1fr, 1fr, 1.2fr, 1fr),
  table.header([Corpus], [Claude], [K3], [DeepSeek], [Qwen3-Max], [Spread]),
  [seed (synthetic)], [0.906], [0.927], [0.844], [—], [0.08],
  [CISA (real)], [0.529], [0.496], [0.401], [0.359], [0.17],
)

On synthetic vignettes the models sit within 0.08 F1 and the ordering is noisy. On real advisories every model roughly halves its F1 and the ranking becomes clear and stable: a bootstrap over the 25 reports puts Claude above K3 in 97% of resamples and K3 above DeepSeek in 100%. Clean, canonical synthetic corpora are a ceiling that cannot separate frontier models. Absolute F1 on real advisories is additionally deflated by non-exhaustive CISA tables (Section 8), so the ranking is more trustworthy than the absolute numbers.

= Refusal Is Framing-Dependent

The strongest model refused exactly one seed report, a compact synthetic ransomware vignette, returning an empty output and zeroing its labels. On the 25 real CISA advisories, which describe the same and worse adversary behavior at far greater length, it refused nothing. The safety trigger tracked the terse "attack-recipe" framing of the synthetic vignette, not the underlying malicious content. For defensive pipelines this is reassuring, since real advisories pass, but operationally important: a refused report is silent data loss, so any pipeline routing through a frontier model needs explicit refusal detection.

= Reasoning Effort and Backend Selection

Reasoning hurts this task. Raising Kimi K3 from low to high reasoning effort dropped strict F1 from 0.927 to 0.870 at 3x the cost and 3.5x the output tokens; the extra reasoning over-specifies correct parent techniques into wrong sub-techniques. Extraction is recognition, not multi-step reasoning, so reasoning-minimal settings are correct.

#table(
  columns: (2.2fr, 1.1fr, 1fr, 1fr, 1.2fr),
  table.header([Model (CISA)], [Strict F1], [Recall], [Errors], [\$/report]),
  [claude-opus-4-8], [0.529], [0.554], [0/25], [0.092],
  [kimi-k3-fireworks], [0.496], [0.477], [0/25], [0.034],
  [deepseek-v4-pro], [0.401], [0.335], [2/25], [0.011],
  [qwen3-max], [0.359], [0.290], [1/25], [0.007],
)

The open-weight Kimi K3 lands within 0.03 F1 of Claude at a third of the cost, with zero refusals or malformed output, and it beat the proprietary Qwen3-Max outright. Both budget models emitted invalid JSON on the most technique-dense advisories, a reliability failure concentrated on exactly the hardest inputs. Per threat category the ranking holds uniformly, so there is no model-routing arbitrage, and difficulty is dominated by report type: every model scores about 0.6 on standardized ransomware advisories versus about 0.45 on bespoke nation-state reports.

= Correcting Non-Exhaustive Ground Truth

CISA analysts tag a subset of techniques in the advisory table; the prose typically describes more, so a model extracting a real-but-untabled technique is scored a false positive, deflating precision to about 0.50 for all four models. The strict/substantiated split that addresses this, reporting F1 against all table labels and against only text-substantiated labels, originates in Adversarix's internal framework. We operationalize its label-vetting step as a released, reproducible adjudication tool: build a candidate pool per report (table gold union every model's predictions), surface the supporting prose per candidate, and have a human keep or drop each against the text with a substantiation tier. The emitted corpus reports a table-incompleteness delta, the techniques added or removed versus the CISA table, which both yields trustworthy absolute precision and recall and quantifies how incomplete auto-derived ground truth is.

= A System One Model: Calibrated Classification

A System One model does not generate text. It answers typed questions over a fixed answer space and returns a probability per answer, and its stated advantage is that those probabilities are calibrated. Jev cannot enumerate techniques, so we invert the task: the sanitized report becomes the model state, and we ask one boolean per candidate technique ("does this report describe the adversary using technique X?"), keeping those above a probability threshold. Candidates are the 280-technique union of both corpora's gold labels. This hands Jev the label space while the generative models discover techniques from open vocabulary, so Jev's precision is a multi-label classification score and is not directly comparable on that axis. On synthetic vignettes Jev over-predicts and trails badly (0.47 F1), but on real advisories it reaches Claude's F1 (0.51 versus 0.53) with the highest recall of any model (0.80), the expected shape of a high-recall classifier at a permissive threshold.

Scored against the raw CISA tables, Jev's confidence looks badly miscalibrated: an expected calibration error of 0.119, with techniques it rates 0.9 to 1.0 present only 60% of the time. This is confounded by the same table incompleteness as Section 8. To separate the two, we ran an automated, blinded variant of the adjudication tool with a judge model (Claude, not Jev) ruling on whether the prose substantiates each of Jev's 170 high-confidence false positives, with random low-confidence techniques mixed in as blind negative controls. Seventy percent of those false positives are real, untabled techniques; substantiation rises with confidence (79% in the 0.95 to 1.0 band); and the judge accepted zero of 69 controls. Corrected for untabled truth, Jev's effective precision at the 0.9 gate is about 88%, not 60%, and its high-end calibration is close. It remains loose in the mid bands, which is acceptable for a deployment that gates automatic action at high confidence and escalates the rest.

Adjudicating the full candidate pool (table gold union every model's predictions) added 580 substantiated techniques to 635 table labels across the 25 advisories: the tables captured roughly half of what the advisories describe. Re-scoring every model on corrected gold lifts all precisions from about 0.50 to the 0.71 to 0.80 range, confirming the tables were penalizing real extractions across the board.

#table(
  columns: (2.2fr, 1fr, 1.1fr, 1.1fr),
  table.header([Model (CISA, adjudicated)], [Precision], [Strict F1], [Parent F1]),
  [claude-opus-4-8], [0.79], [0.58], [0.72],
  [kimi-k3-fireworks], [0.80], [0.52], [0.67],
  [deepseek-v4-pro], [0.75], [0.39], [0.55],
  [qwen3-max], [0.71], [0.34], [0.47],
  [jev-typesafe (thr 0.5)], [0.72], [0.76], [0.78],
)

Jev tops F1 on corrected gold, but that lead is inflated by pool construction: the adjudicated gold can only contain techniques some model proposed, and 22% of it was surfaced only by Jev, which counts as a miss for every other model. Precision is immune to this bias, and on precision Jev is tunable: 0.72 at threshold 0.5, 0.805 at 0.7 (matching the frontier models), 0.895 at 0.9. Even at the precision-matched threshold 0.7 (recall 0.635) Jev still leads on F1, because its recall stays well above Claude's 0.45 and K3's 0.39. The defensible reading is that Jev matches frontier per-prediction precision at a comparable operating point while finding materially more, at about 1/30 the cost (\$0.07 versus \$2.30 per 25 reports for Claude) and 15x the speed. We validated the judge before trusting any of this: all 580 supporting quotes are verbatim sentences from the advisories (zero fabricated), and a manual spot-read found parent-technique verdicts solid but roughly 20 to 30% of sub-technique assignments debatable, the same over-specification failure seen in reasoning models. The corrected gold is therefore trustworthy at parent level and approximate at strict sub-technique level.

= Takeaways

- CISA-derived TTP benchmarks must strip inline ID citations, bare ID tokens, and technique tables from the model input.
- Evaluate on real advisories, not synthetic vignettes, and report a strict/substantiated split because table labels are not all extractable from text.
- For a TTP-ingestion backend, an open-weight model (Kimi K3 here) is the quality-per-cost pick; frontier reasoning and proprietary-flagship status did not help.
- LLM refusal on defensive-security content tracks framing; measure it on real data and handle it explicitly.
- A calibrated classification model (Jev here) is a credible first-stage, high-recall, confidence-gated filter over a known technique set, refusal-free and about 1/30 the cost; pairing it with a generative model for open-vocabulary discovery and per-prediction precision is the natural two-stage design.

= Artifacts and Limitations

The harness, the leakage-safe CISA ingest, the adjudication tool, the Jev provider and its calibration and false-positive-adjudication scripts, and the adjudicated CISA corpus are released under Apache-2.0/MIT in the AEGIS Labs `ttp-benchmark` directory, with 20 synthetic seed reports and 25 CISA advisories with gold labels. Twenty-five advisories is a small sample: the tier structure is robust, but the Claude-versus-K3 gap magnitude is not tightly bounded (overlapping bootstrap confidence intervals). CISA tables are non-exhaustive, as discussed. The Jev evaluation carries three additional caveats: the classification framing is closed-world (the model is given the candidate set); the automated adjudication judge is itself one of the scored models, mitigated by blinding and the zero control-acceptance rate but not eliminated; and the adjudicated gold carries sub-technique noise, so its strict scores are approximate while its parent-level scores are sound. All numbers are point-in-time for the model versions listed and are not comparable across the two corpora.

#citation-block[Extracting ATT&CK from Real Advisories: A Leakage-Safe Benchmark and Backend-Model Comparison for TTP Ingestion]
