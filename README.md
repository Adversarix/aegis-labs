# AEGIS Labs

AEGIS Labs is the home for open-sourced research projects spun out of the commercial
work we do at [Adversarix](https://adversarix.com), an autonomous threat intelligence
and response platform built around a live Threat Knowledge Graph.

Adversarix continuously ingests threat intelligence, simulates adversarial behavior
against an organization's real infrastructure topology, identifies detection gaps, and
synthesizes prioritized advisories without waiting for human initiation. The papers and
projects here document the methods behind that platform (the simulation models, the
measurement frameworks, and the threat-modeling approaches) for public reference,
citation, and reuse.

---

## Publications

### Defending Against Polymorphic Attack Chains: How Autonomous Adversarial Simulation Closes the Detection Gap
**July 2026 · Version 2.1**

[→ Download PDF](./polymorphic-attack-chains/Adversarix_Polymorphic_Attack_Chains_Whitepaper.pdf)

Modern threat actors don't follow a single kill chain. They maintain technique
repertoires and rotate between them in response to what your detection stack catches.
This paper examines how the Adversarix platform addresses polymorphic attack chains
through a six-agent autonomous pipeline built on a live Threat Knowledge Graph, running
five distinct adversarial simulation strategies and Monte Carlo probability modeling to
characterize the full adversarial option space, not just a single representative path. It
also details the platform's procedure-level fidelity (sub-technique execution modules
parameterized to named-actor procedures) and walks an end-to-end critical-CVE response
from disclosure to advisory in under 90 seconds.

**Key findings:**
- Reduced mean time from threat indicator ingestion to actionable advisory from 4–8 analyst hours to under 90 seconds
- Increased simulated attack path coverage by more than 300% vs. manual simulation workflows
- A critical RCE CVE on a perimeter mail server raised Monte Carlo campaign success probability by 34% across all polymorphic kill chain variants
- Procedure-intelligence extraction validated at F1 > 0.89 on structured incident-response reports, grounding simulation at sub-technique granularity

**Topics:** polymorphic kill chain taxonomy · five-strategy simulation framework · Monte Carlo probability modeling · procedure-level fidelity & actor emulation · detection gap analysis · human-in-the-loop governance

---

### Agentic Identity Pivots: Modeling Credential-Borne Lateral Movement in Breach Simulation
**July 2026 · Version 1.1**

[→ Download PDF](./agentic-identity-pivots/Adversarix_Agentic_Identity_Pivots_Whitepaper.pdf)

As enterprise estates go agentic, with autonomous agents holding credentials, invoking tools,
and reaching capability through MCP servers, shared-credential pivots become the dominant
lateral-movement surface. Most threat models represent credential abuse only as a technique
label, which cannot express how far a compromise actually spreads. This paper describes how
Adversarix adds an agent–credential–tool topology to the Threat Knowledge Graph and makes
the Monte Carlo breach simulation *traverse* it, so agentic lateral movement becomes a real,
quantified term in breach probability.

**Key findings:**
- Pivot-success probability is governed by credential *posture*, not technique label: a static shared key scores 0.90, a delegation-attenuated token 0.20, a 4.5× spread a technique-only model collapses
- A unified heterogeneous walk lets a single attack path interleave technique steps and credential pivots, with detection applied to pivots via the technique they realize
- A structural regression lock guarantees the model is purely additive: estates with no identity topology reproduce the prior breach probability exactly

**Topics:** agentic AI threat modeling · credential posture priors · MCP/tool reachability · heterogeneous graph traversal · bounded path explosion · regression-locked risk scoring

---

### Measuring TTP Extraction: A Reproducible Evaluation Framework for ATT&CK Technique Extraction from Threat Reports
**July 2026 · Version 1.1**

[→ Download PDF](./ttp-extraction-eval/Adversarix_TTP_Extraction_Eval_Whitepaper.pdf)

Extracting MITRE ATT&CK techniques from unstructured threat reporting is a core pipeline
primitive, and notoriously hard to measure well. This paper describes an evaluation
framework built to be reproducible and honest: ground truth auto-derived from public CISA
advisory tables (zero manual annotation), partial credit for parent–child technique matches,
a substantiation split for the text-only ceiling, and F1 reported as a range across
non-deterministic runs. Accuracy is measured at both the document and sentence level across
three corpora of different provenance.

**Key findings:**
- F1 of 0.84–0.92 on 163 auto-derived ground-truth techniques with precision 0.92–0.94, so the extractor rarely hallucinates technique IDs
- Parent-match partial credit resolves a systematic cross-corpus granularity mismatch that exact-match scoring double-penalizes
- A near-zero threat-model coverage delta is reported as a genuine result: ~84% of cited techniques are already present from actor- and campaign-level signals

**Topics:** ATT&CK technique extraction · zero-annotation corpus construction · parent–child partial-credit scoring · TRAM & AnnoCTR sentence-level benchmarks · non-determinism and multi-run evaluation · downstream coverage measurement

---

### Extracting ATT&CK from Real Advisories: A Leakage-Safe Benchmark and Backend-Model Comparison for TTP Ingestion
**July 2026 · Version 0.1 (draft)**

[→ Download PDF](./ttp-benchmark/Adversarix_TTP_Extraction_Benchmark_Whitepaper.pdf)

Which LLM should read a threat advisory and return its ATT&CK techniques, and how do you
measure that honestly? This paper benchmarks four frontier models (Claude Opus 4.8, Kimi K3,
DeepSeek-V4-Pro, Qwen3-Max) across a synthetic corpus and 25 real CISA advisories. Most of
the difficulty turns out to live in the benchmark, not the models: CISA advisories cite
technique IDs inline in prose, so an unsanitized benchmark measures copy-paste rather than
extraction. Complementary to the *Measuring TTP Extraction* framework above, and a sanitized
public derivation of the same internal methodology.

**Key findings:**
- Synthetic corpora do not discriminate frontier models (all within 0.08 F1); real advisories do (they spread to 0.36–0.53 and the ranking stabilizes)
- The open-weight Kimi K3 is the quality-per-cost backend, within 0.03 F1 of the leader at a third the cost, and beat the proprietary Qwen3-Max outright
- Refusal is framing-dependent: the strongest model refused a synthetic ransomware vignette but zero of 25 real advisories describing the same behavior
- Higher reasoning effort *lowers* extraction F1, by over-specifying correct parent techniques into wrong sub-techniques

**Topics:** inline-ID leakage · synthetic-vs-real evaluation · leakage-safe CISA ingest · frontier model comparison · reasoning-effort ablation · open-vs-closed backend selection · candidate-pool label adjudication

---

### Empirical Detection Posteriors: Closing the Loop from SIEM Firings to Breach Probability
**July 2026 · Version 1.1**

[→ Download PDF](./detection-posteriors/Adversarix_Empirical_Detection_Posteriors_Whitepaper.pdf)

Breach simulations usually model detection as an assumption: a technique is "covered" if a
rule exists for it. But a deployed rule that never fires is not coverage. This paper describes
how Adversarix feeds production SIEM telemetry back into the Monte Carlo breach simulation as a
per-technique *empirical detection posterior*: a Beta distribution fit to real firing evidence
that replaces a global detection constant, raising breach probability where coverage is illusory
and lowering it where rules fire cleanly.

**Key findings:**
- A "deployed-blind" technique (rule present but required log source missing, so it cannot fire) is driven *below* the neutral prior, correcting illusory coverage
- Detection *uncertainty* propagates: the simulation samples the posterior per iteration, so a technique with three firings is treated as less certain than one with three thousand
- A byte-identical fallback guarantees organizations without SIEM telemetry see no change in breach probability, so the mechanism is purely additive

**Topics:** empirical Bayesian detection modeling · SIEM firing telemetry · Beta posterior fitting with count down-weighting · uncertainty propagation in Monte Carlo simulation · detection-posture feedback loops · regression-locked risk scoring

---

### Containing the Simulated Adversary: A Safety Architecture for Autonomous Breach-and-Attack Simulation on Ephemeral Digital Twins
**July 2026 · Version 0.1 (draft)**

[→ Download PDF](./safe-agentic-bas/Adversarix_Safe_Agentic_BAS_Whitepaper.pdf)

Breach-and-attack simulation is moving from human-driven scripts to autonomous agents
that select ATT&CK techniques and detonate them through real offensive frameworks, which
makes the simulator itself a thing that must be contained. This paper threat-models the
BAS engine as its own adversary and describes the safety architecture that makes
autonomous emulation safe to run unattended: five invariants enforced in code rather
than policy, bounded by ephemeral digital twins whose teardown is guaranteed by the
orchestration. It is published as method rather than engine; no offensive tradecraft
or engagement data appears.

**Key ideas:**
- Five runtime invariants (target isolation, default-deny governance, dry-run first, a clean kill switch, and signed simulation markers) whose violation is an error the code raises, not a judgment call an operator makes
- Keyed (HMAC) simulation markers make synthetic telemetry attributable *and* unforgeable, so a BAS run never triggers real incident response and a real intruder cannot hide behind "it's just the sim"
- Ephemeral twins bound blast radius by construction: destructive techniques detonate only on targets whose entire purpose is to be destroyed, with teardown executed even on failure or kill
- Containment and measurement integrity are the same property viewed twice: the controls that keep the simulator in its box are what make its detection-coverage verdicts reproducible and honest

**Topics:** autonomous adversary emulation · BAS self-threat-modeling · default-deny action governance · signed synthetic telemetry · ephemeral digital twins · independent observation & verdict precedence

---

## Code & Tools

### ttp-benchmark — TTP Extraction Benchmark

[→ Browse the code](./ttp-benchmark/)

A model-agnostic test harness measuring how well different LLMs extract MITRE
ATT&CK techniques from threat-intelligence reports — the ingestion step that
feeds the Threat Knowledge Graph. Ships with a 20-report hand-labeled seed
corpus (121 gold labels), scores strict and parent-level F1 with per-report
miss/hallucination drill-downs, and compares any provider with an
OpenAI-compatible endpoint via a single `config.yaml` entry. Related to the
*Measuring TTP Extraction* whitepaper above but methodologically distinct: the
paper evaluates the platform's extractor against auto-derived CISA ground
truth, while this harness compares backend LLMs on a hand-labeled seed corpus
with its own scoring rules.

---

## About Adversarix

Adversarix is an autonomous cybersecurity threat intelligence and response platform
centered on a Threat Knowledge Graph. It continuously ingests threat intelligence,
simulates adversarial behavior against live infrastructure topology, identifies detection
gaps, and synthesizes prioritized advisories without waiting for human initiation.

[adversarix.com](https://adversarix.com) · [contact@adversarix.com](mailto:contact@adversarix.com)

---

## Citation

If you reference this research, please cite the relevant paper as:

```
Galappatti, K. (2026). <Paper Title>. AEGIS Labs, Adversarix, Inc.
https://github.com/Adversarix/aegis-labs
```

---

## License

© 2026 Adversarix, Inc.

**Code** released through AEGIS Labs is dual-licensed under either the
[Apache License, Version 2.0](./LICENSE-APACHE) or the [MIT License](./LICENSE-MIT),
at your option. Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this repository shall be dual-licensed as above, without
any additional terms or conditions.

**Whitepapers** are released for public reference and citation. Reproduction in whole
or in part requires attribution. No rights are granted to the Adversarix platform
software or its implementation.

Third-party corpora referenced in the research (TRAM, Apache 2.0; AnnoCTR, CC-BY-SA-4.0)
remain under their respective licenses. MITRE ATT&CK is a trademark of The MITRE
Corporation.
