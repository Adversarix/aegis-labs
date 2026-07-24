# Research Brief: Organizational Context as Signal for Threat Intelligence Relevance

**AEGIS Labs · Adversarix Research · July 2026 · Status: Internal brief — pre-publication**

---

## 1. Motivation

Every threat intelligence product claims to deliver "relevant" intel, and nearly all of them operationalize relevance the same way: match the intel's industry-sector and geography tags against the customer's profile. Whether those attributes actually predict that a given piece of intel matters to a given organization is a question the industry has largely assumed rather than tested.

This brief summarizes a structured, source-verified literature review (July 2026) on which organizational context attributes carry real, evidence-backed signal for CTI relevance, and translates the findings into a prioritized research and engineering agenda for the AEGIS relevance-scoring layer.

**Scope.** Given a piece of threat intel — actor report, campaign, CVE, IOC set, TTP — which facts about an organization (tech stack, attack surface, sector, geography, size, supply chain, data types, detection coverage, incident history) predict whether that intel matters to it?

**Method note.** Findings below were produced by a multi-agent research pipeline: five parallel search angles (frameworks/standards, vulnerability decision systems, empirical victimology, vendor implementations, critiques), 23 sources fetched, 113 claims extracted, top 25 adversarially verified by independent 3-vote panels (23 confirmed, 2 refuted). Verification votes and caveats are carried inline.

---

## 2. What the evidence supports: a hierarchy of relevance signals

### 2.1 Strongest signal: asset / tech-stack presence

The best-supported organizational relevance filter is simply whether the affected technology exists in the environment, and the base rates make it enormously powerful:

- Only **~44% of CVEs** (published 2016–2018) were ever detected open in *any* corporate environment, across hundreds of enterprises (Kenna data, foundational EPSS paper [1]).
- Only **~3.7% of CVEs** (921 of 25,159) were observed exploited in the wild within 12 months of disclosure [1]. Later estimates place this at ~5–6%; the qualitative conclusion is durable.

*Caveats:* 3.7% is a lower bound (IDS/honeypot signature-coverage bias); the 44% figure conflates asset absence with scanner-signature gaps, so 56%-never-observed is an upper bound on the pure asset-absence effect. (Verified 3-0, 3-0.)

### 2.2 Most predictive power: exploitation-ecosystem attributes

The best-validated predictors of exploitation are vulnerability-intrinsic and ecosystem attributes — **not** organizational attributes: vendor identity, published/weaponized exploit code, vulnerability tags (remote code execution), CVE reference counts. Weaponized PoC code raises observed exploitation from the 3.7% base rate to **37.1%** — a ~10x lift [1] (N=283; corroborated by Suciu et al. and EPSS v3). (Verified 3-0.)

### 2.3 Weak / unvalidated: sector, geography, company size

- **No surviving empirical evidence** in the review tests whether sector or geography independently predict firm-level victimization after controlling for tech stack and attack surface. The frameworks and products that use them *assume* rather than validate them.
- **IBM's patented affectedness engine** (US11194905) uses sector+geography as its only org-profile attributes — but only to *scope* sighting queries. Its core mechanism is empirical sighting frequency, and **first-party observation in the customer's own telemetry receives the single largest default weight (35%, vs. 25% for industry/geo-similar sightings)** [6]. Even a sector-based product ranks direct observation above profile similarity. Note the 35/25 split is an unfitted heuristic, and a patent describes a design, not verified deployed behavior. (Verified 3-0, 3-0, 2-1.)
- **CISA's operational SSVC tree** uses exactly five decision attributes — exploitation status, technical impact, automatability, mission prevalence, public well-being — and **deliberately excludes sector, geography, and company size** [5]. (Verified 3-0.)
- The **one direct empirical test** of org-attribute relevance scoring (McCoy et al. 2024 [2]): joining sector + country + CPE-normalized software inventory to ATT&CK actor-targeting data improved vulnerability ranking **71.5–91.3% over CVSS-only** (23–25% annualized cost savings) across six universities and four government proxy organizations. *Treat as promising, not settled:* the headline claim drew a 2-1 verification vote — weak CVSS-only baseline, partially circular ground truth (exploitation-in-the-wild shared with policy criteria), synthetic government inventories, unreplicated.

### 2.4 Folklore: severity thresholds and single-score inheritance

- **CVSS 7+ remediation yields 6.2% precision**; EPSS achieves equivalent coverage with 28.8–85.9% less remediation effort (AUC 0.838). CVSS base scores contain no data element enumerating a specific threat to an organization — still true in CVSS v4.0, where Exploit Maturity sits in the separate Threat metric group [1][2]. (Verified 3-0.)
- **The four major scoring systems agree at chance level.** CVSS, EPSS, SSVC, and Microsoft Exploitability Index on the same 600 Patch Tuesday CVEs: Cohen's Kappa −0.01 to 0.03 across all pairs, Krippendorff's Alpha predominantly negative (Koscinski et al., ACM CCS 2025 [7]). Partly by design (different constructs), but perceived priority depends mostly on which system was adopted. (Verified 3-0.)
- **KEV membership is a coarse proxy:** only ~32% of KEV entries (483 of 1,488 as of 2026-01-14) are immediately exploitable for initial access (unauthenticated RCE, no user interaction); the lowest-scoring KEV entries have EPSS below 0.001 [8]. Single-vendor snapshot — date-stamp when citing. (Verified 3-0.)

### 2.5 Doctrine: relevance is decision-anchored and dynamic

FIRST's PIR curriculum [3] and SSVC [5] converge on the same design stance: relevance is anchored to a **bounded set of stakeholder decisions** and deployment context, not static attribute matching — and it is **perishable**: "PIRs are fluid and not static. When an operational environment changes, the PIRs and everything the PIRs support or are supported by, must be re-evaluated." CTI-CMM [4] makes crown-jewel asset inventory the core org attribute and reserves org-specific exploitation probability for its top maturity tier (CTI3) — asserting it as the goal without providing a way to measure it. (All verified 3-0; these are normative expert consensus, not empirical measurement.)

---

## 3. Implications for AEGIS

The evidence points to investing where signal is proven but implementations are crude, and treating popular-but-unvalidated signals as research questions rather than product features.

### Tier 1 — Asset presence as the gating filter

The strongest-evidenced signal is exactly what the Threat Knowledge Graph already models, and AEGIS's live topology is a structural advantage over scanner-based, point-in-time approaches. Priority engineering work: rigorous entity resolution between intel artifacts and the graph — CPE/package normalization, version-range matching, resolving vendor advisories to deployed assets. This filter alone discards the majority of vulnerability-flavored intel with high confidence and shrinks the denominator for every downstream score.

### Tier 2 — Exploitation-ecosystem fusion, never single-score inheritance

Ingest EPSS, KEV, PoC weaponization, and observed-exploitation signals as **features into AEGIS's own model**; never inherit any one as the ranking (chance-level inter-system agreement makes that indefensible). Condition KEV/exploitability on topology position — internet-facing vs. internal — which the graph enables and flat scoring systems cannot do.

### Tier 3 — Two AEGIS-native signals (novel, defensible, publishable)

1. **Simulation-derived relevance.** Define relevance as *the change a piece of intel induces in simulated attack-path success probability for this specific environment*, computed via the existing Monte Carlo pipeline. This operationalizes CTI-CMM's top-maturity signal ("probability of exploitation against the enterprise") — which the framework asserts but no one measures — and extends the polymorphic-attack-chains work: intel enabling a new variant chain is relevant even when the direct path is blocked.
2. **Empirically fitted first-party sighting weights.** The IBM patent ranks first-party observation above profile similarity but with unfitted heuristic weights. AEGIS's detection-gap analysis already observes the environment; fitting sighting-vs-similarity weights against real outcomes (advisory accept/dismiss, subsequent detections) is both a product improvement and a paper.

### Deprioritize — sector/geography as scoring inputs

Use sector and geography only as a coarse prior for actor-targeting overlap (per the McCoy result, with its caveats), with no independent weight in the score. Instead, make validation the flagship research question (§4, Q1).

### Design constraints to bake in now

- **Drift triggers, not cadence.** Wire re-scoring to graph-change events (new asset class, decommission, M&A-scale topology shifts) rather than timers — implementing FIRST doctrine natively in an autonomous platform.
- **Pick ground truth before building the model.** Avoid the McCoy circularity trap (scoring features shared with ground-truth definitions). The cleanest label stream AEGIS has is org-specific: analyst accept/dismiss decisions on advisories plus subsequent detection/incident outcomes — not population-level exploitation, which is what everyone else trains on and why their scores disagree at chance level.

---

## 4. Open research questions

1. **Does sector or geography carry independent predictive signal for firm-level victimization after controlling for tech stack and external attack surface — or are they merely coarse correlates?** No DBIR-style victimology or firm-level breach-prediction evidence survived verification; the frameworks that use these attributes assume them. AEGIS's cross-customer graph data is positioned to answer this, and either outcome is publishable.
2. **What re-evaluation triggers operationalize relevance drift?** Which environment-change events (M&A, new products, cloud migrations) invalidate prior relevance judgments, and at what magnitude?
3. **Can org-specific exploitation probability be measured rather than asserted** — by combining first-party telemetry sightings with attack-surface and simulation data — and how should first-party observation be weighted against profile similarity when fitted, not defaulted?
4. **What ground truth should a knowledge-graph relevance layer train and evaluate against** — population-level exploitation, org-specific incident/detection outcomes, or analyst decision quality — and how is feature/label circularity avoided?

---

## 5. Refuted claims — do not cite

Two claims encountered during the review were refuted (0-3) under adversarial verification:

1. ~~CTI-CMM prescribes a continuously updated organizational threat profile whose axes are threat actor groups, tools, and TTPs filtered by sector and geography.~~ (Not supported by CTI-CMM v1.3 text.)
2. ~~Fewer than 20% of KEV CVEs had an EPSS score above 0.5 before KEV addition.~~ (Not supported by the cited source.)

---

## 6. Key sources

1. Jacobs, Romanosky, Edwards, Roytman, Adjerid — *Exploit Prediction Scoring System (EPSS)*, ACM DTRAP (arXiv:1908.04856)
2. McCoy, Gore, Nelson, Weigle — organizational-context vulnerability relevance ranking (arXiv:2406.05933)
3. FIRST CTI SIG — Priority Intelligence Requirements curriculum (first.org/global/sigs/cti/curriculum/pir)
4. CTI-CMM v1.3 (Jan 2025) — cti-cmm.org
5. CISA / CMU SEI — Stakeholder-Specific Vulnerability Categorization (SSVC)
6. IBM — US Patent 11,194,905, affectedness scoring engine
7. Koscinski et al. — inter-system agreement of vulnerability scoring systems, ACM CCS 2025 (arXiv:2508.13644)
8. Beardsley (runZero) — *Kevology*, KEV catalog analysis, snapshot 2026-01-14

Additional sources reviewed: Liu et al. (USENIX Sec '15, incident forecasting), Li et al. (USENIX Sec '19, IOC feed analysis), Bouwman et al. (USENIX Sec '20, commercial TI value), Recorded Future risk rules, ThreatConnect ThreatAssess/CAL and intelligence requirements documentation, Intel 471 CU-GIRH, NIST CSWP 41.

**Evidence-type caveat.** Framework claims (§2.5) are normative expert consensus, not empirical validation. The strongest empirical results concern vulnerability-flavored intel with population-level exploitation as ground truth — a proxy, not org-specific victimization. The empirical case for sector/geography/size as independent predictors remains essentially untested.

---

**Citation.** Galappatti, K. (2026). *Research Brief: Organizational Context as Signal for Threat Intelligence Relevance.* AEGIS Labs, Adversarix, Inc. https://github.com/Adversarix/aegis-labs

© 2026 Adversarix, Inc.
