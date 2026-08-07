#import "/typst/aegis-whitepaper.typ": whitepaper, toc, callout, citation-block

#show: whitepaper.with(
  title: "Measuring TTP Extraction",
  subtitle: "A Reproducible Evaluation Framework for ATT&CK Technique Extraction from Threat Reports",
  version: "1.1",
  date: "July 2026",
  tiles: (
    ("0.84–0.92", "F1 on CISA ground-truth techniques"),
    ("163", "Ground-truth techniques, zero manual labeling"),
    ("3 corpora", "Document- and sentence-level benchmarks"),
  ),
)

#toc()

= Executive Summary

Extracting adversary techniques, meaning MITRE ATT&CK TTPs, from unstructured threat reporting is a core primitive of any automated threat-intelligence pipeline. It is also notoriously hard to measure. Ground truth is expensive to annotate, published corpora label techniques at inconsistent sub-technique granularity, and the large-language-model extractors now doing the work are non-deterministic, so a single accuracy number is misleading.

This paper describes the evaluation framework the Adversarix platform uses to measure its TTP extractor, and the design decisions that make the measurement _reproducible_ and _honest_. Three ideas do most of the work. First, ground truth for document-level evaluation is _auto-derived_ from the ATT&CK tables that public CISA advisories already publish, eliminating manual annotation for the primary corpus. Second, scoring awards partial credit for a _parent-child_ technique match, resolving a systematic mismatch between how corpora annotate techniques and how extractors emit them. Third, a _substantiation_ flag separates the realistic ceiling for a text-only extractor from the strict set of every cited technique. The framework spans a document-level CISA corpus and two independent, open-source sentence-level corpora, so accuracy is measured both as "which techniques does the whole report contain" and as "does the extractor pick the right technique for a given sentence."

#callout("Key Finding")[
  On a five-advisory CISA corpus of 163 auto-derived ground-truth techniques, the extractor scores F1 0.84–0.92 on substantiated techniques with precision 0.92–0.94, so it rarely invents technique identifiers. The remaining error is concentrated in recall, and it is measured per-technique so prompt iteration can target the specific techniques being missed. Because the language model is non-deterministic, F1 is reported as a range across runs, not a point estimate.
]

= Why Technique Extraction Is Hard to Measure

An extractor reads a threat report and emits a set of ATT&CK technique identifiers. To know whether it is any good, you need a labeled corpus, a scoring rule, and a way to handle the extractor's non-determinism. Each is a trap.

- *Annotation cost.* Hand-labeling the techniques in a long advisory is slow expert work. A framework that depends on it does not scale, and small hand-labeled corpora produce noisy accuracy estimates.
- *Granularity mismatch.* ATT&CK techniques form a two-level hierarchy: a parent (T1059, Command and Scripting Interpreter) and its sub-techniques (T1059.001, PowerShell). Corpora annotate at different levels. Some label the bare parent, others the specific child. An extractor that emits the correct child against a corpus that labeled the parent is punished twice under exact-match scoring, once as a false positive for the child and once as a false negative for the parent, even though the answer is essentially right.
- *Text-only ceiling.* A published technique list may include techniques attributed from external incident response that the report's own prose never substantiates. No text-only extractor can recover those from the text alone. Scoring against the full list conflates extractor error with information that isn't in the input.
- *Non-determinism.* Modern extractors are language models. The same report scored twice yields different technique sets. A single F1 number invites over-fitting to one lucky run.

The framework is built to neutralize each of these.

#pagebreak()

= Corpus Construction Without Manual Annotation

The primary corpus is document-level: whole advisory in, technique set out. Its ground truth is derived automatically from a property of CISA advisories, namely that they publish their own ATT&CK technique tables. A build step fetches the advisory body, extracts every bracketed technique citation and every row of the technique table, captures the sentence-level evidence quote for each, and writes a ground-truth specification. For CISA-format sources the annotation effort is zero; adding a new advisory is a matter of pointing the fetcher at its URL.

The current corpus is five advisories spanning ransomware, nation-state APT, and critical-infrastructure scenarios, totaling 163 ground-truth techniques:

#table(
  columns: (2.2fr, 3.8fr, 1fr),
  table.header([Actor / campaign], [Scenario], [Techniques]),
  [BlackSuit (Royal)], [Phishing-led ransomware], [16],
  [Snake (Turla)], [Long-running espionage malware], [49],
  [Volt Typhoon], [Critical-infrastructure living-off-the-land], [68],
  [Black Basta], [Healthcare ransomware], [11],
  [Pioneer Kitten / Fox Kitten], [Ransomware enablement], [19],
)

All five actors are public, appearing in CISA's own published advisories; the corpus contains no private or customer data. Non-CISA sources, such as vendor reports and generic threat blogs, can be added but require manual annotation because they do not follow CISA's citation format; the framework estimates 20–30 minutes per such sample.

= Scoring: Parent Matching and Substantiation

== Two ground-truth variants

Every run reports two variants of ground truth:

- *Strict:* every technique cited in the advisory is in the ground truth.
- *Substantiated:* only techniques whose own prose supports them. This is the realistic ceiling for a text-only extractor.

For CISA advisories the two variants coincide, because every cited technique is present in the prose. The split earns its keep on non-CISA sources, where some labels are inferred from external incident response the text never states.

== Exact and parent matching

Within each variant, a predicted technique can match ground truth two ways:

- *Exact match:* the predicted identifier equals a ground-truth identifier. Full credit.
- *Parent match:* the predicted technique is the parent of a ground-truth sub-technique, or the child of a ground-truth parent. Half credit. Each ground-truth technique can be claimed at most once.

Parent matching is the framework's answer to the granularity-mismatch trap. It gives partial credit for being in the right technique family, a materially useful answer for an analyst, without treating a family-level match as a perfect one. The exact-match numbers are preserved unchanged so existing baselines remain comparable; the parent variant is reported additively alongside them.

= Multi-Level Benchmarking

Document-level accuracy answers "which techniques does this report contain." It does not directly test whether the extractor attaches the _right_ technique to a _given_ sentence. Two open-source, sentence-level corpora provide that independent view and guard against over-fitting to the CISA style:

#table(
  columns: (1fr, 5.4fr),
  table.header([Corpus], [Description]),
  [TRAM], [A community-curated corpus of roughly 11,300 human-labeled sentences mapped to about 50 ATT&CK techniques (Apache 2.0). A stratified-by-technique sampler draws balanced slices.],
  [AnnoCTR], [A research corpus of 400 real vendor CTI reports with entity, tactic, and ATT&CK technique spans (CC-BY-SA-4.0). A second, wilder benchmark useful for catching over-fitting to TRAM and CISA.],
)

Both sentence-level validators report exact micro metrics and the additive parent variant, mirroring the document-level harness. The parent variant is especially load-bearing for cross-corpus comparison: one corpus frequently labels the bare parent while the extractor emits the specific sub-technique, which exact-match scoring would wrongly count as both a false positive and a false negative. Using three corpora of different provenance, one auto-derived document-level corpus and two independently annotated sentence-level corpora, means an accuracy claim is not an artifact of one annotation style.

= Measuring the Downstream Effect

Extraction accuracy is a means, not an end. The reason to extract techniques is to keep a threat model current. The framework therefore includes a _coverage_ measurement that looks past F1 to the pipeline's actual output: what fraction of a report's ground-truth techniques survive into the active, auto-generated threat model above a relevance threshold.

This is measured two ways. A _snapshot_ asks what fraction of cited techniques are currently in the model. A _delta_ ingests the reports through the full production path, regenerates the model, and measures whether coverage moved. The delta is the honest test of whether extraction is actually feeding the downstream artifact, rather than producing technique lists that go nowhere.

#callout("A negative result worth reporting")[
  On the current corpus the coverage delta after re-ingestion is approximately zero, and that is a genuine finding, not a bug. Roughly 84% of the CISA-cited techniques are already present in the auto-generated model from actor- and campaign-level signals before any report is ingested. The report-level signal nudges relevance scores within the existing model rather than promoting new techniques across the threshold. The framework surfaces this rather than hiding it: to observe a positive delta, one raises the threshold, uses a domain-specific corpus, or includes actors not yet represented in the graph.
]

= Reproducibility and Practice

Several choices make the framework usable as a standing measurement harness rather than a one-off:

- *Mock mode.* A deterministic mock extractor returns a fixed fraction of each sample's substantiated ground truth, with no model calls. It lets the metric pipeline be sanity-checked in continuous integration after a refactor, with no API key and no live system, so the metric code is tested independently of the extractor.
- *Prompt versioning.* The active extractor prompt carries a version identifier. Every result file is tagged with it, so accuracy deltas can be attributed to specific prompt iterations rather than to drift, and a comparison view lays runs side by side.
- *Averaging over runs.* Because the extractor is non-deterministic, observed F1 swings by roughly ±0.05 across consecutive runs on the same corpus. The framework's guidance is explicit: average at least three runs before treating an F1 change as a real tuning result.
- *Pure, tested metric primitives.* The scoring primitives, meaning exact and parent matching, micro and macro aggregation, the substantiation split, and each corpus loader, carry their own unit tests that run without network access, so the measurement itself is trustworthy.

= Baseline Results

Captured against a fixed extractor-prompt version on the five-advisory CISA corpus:

#table(
  columns: (2.6fr, 1.9fr),
  table.header([Metric], [Value]),
  [F1 (substantiated)], [0.836 – 0.918 (run-to-run variance)],
  [Precision], [0.92 – 0.94],
  [Recall], [0.77 – 0.90],
  [Threat-model coverage (snapshot)], [0.84],
  [Coverage delta after re-ingest], [≈ 0.00],
)

The high precision says the extractor rarely hallucinates technique identifiers, a critical property for a system whose output drives downstream simulation and detection. The gap is in recall, and because the framework reports the per-technique false-negative list in every result, prompt iteration can target the specific techniques being missed rather than optimizing a scalar. On the sentence-level corpora, the same extractor and prompt improvements that closed sub-technique-sibling confusion moved macro F1 on a stratified TRAM slice materially upward, confirming that document-level gains were not an artifact of the CISA annotation style.

= Conclusion

Measuring TTP extraction well is mostly a matter of refusing four temptations: to hand-annotate a small corpus, to score exact-match only, to ignore the text-only ceiling, and to trust a single non-deterministic run. The Adversarix evaluation framework declines each. It auto-derives ground truth from public advisories, awards partial credit for parent-child matches, separates substantiated from strict ground truth, and reports F1 as a range with explicit multi-run guidance. It measures both document- and sentence-level accuracy across three corpora of different provenance, and it looks past F1 to whether extraction actually moves the downstream threat model. Published together with its baseline numbers, including a near-zero coverage delta that is a real result rather than a defect, it is offered as a reproducible template for anyone measuring technique extraction from threat reporting.

#pagebreak()

#citation-block[Measuring TTP Extraction: A Reproducible Evaluation Framework for ATT&CK Technique Extraction from Threat Reports]

#{
  set text(size: 8pt, fill: rgb("#8a949a"))
  set par(justify: true)
  [*Corpora.* TRAM (Apache 2.0) and AnnoCTR (CC-BY-SA-4.0) are third-party open-source corpora used under their respective licenses. MITRE ATT&CK is a trademark of The MITRE Corporation.]
}
