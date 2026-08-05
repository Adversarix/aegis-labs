# adversarial-harness

A design for a **general-purpose cybersecurity research harness**: an interactive agentic
CLI that drives **any model — local or hosted** — through the full offensive-research
lifecycle — **discover → develop → detonate → observe** — where every action passes through
a code-enforced containment plane. It is a **neutral instrument**: model-agnostic,
target-agnostic, and independent of any single use case or prior research (`DESIGN.md` §1.1).

The top level of this directory is **architecture and method**: design documentation and
governance policy, with no offensive tradecraft, no working exploits, and no munitions
checked in. The design has since been **built** — the runnable harness lives in
[`src/`](./src/README.md), grown out of the week-one spike ([`spike/`](./spike/README.md)).

---

## The thesis

The harness co-designs two goals that appear to conflict:

- **Stronger agent** — elicit real offensive-research capability from *any* model via
  security-native interactive tools (the EnIGMA "Interactive Agent Tools" mechanism) and,
  optionally, model steering.
- **Contained agent** — every action mediated by runtime invariants enforced *in code, not
  policy*, so the harness is safe to run unattended and its results are reproducible.

The tension is the contribution: run a *capable* adversary against a *real* containment
plane and report what holds. Containment here is a **general** property of any
offensive-capable agent — validating a specific containment model (such as the AEGIS Labs
[`safe-agentic-bas`](../safe-agentic-bas/) invariants) is *one thing you can do with the
harness*, not what it is for.

---

## Architecture in one screen

```
  CLI / harness         forked OSS agent CLI (interactive)          ← Goose | OpenCode
  agent loop            turn control, tool dispatch, trajectory
  ─────────────────────────────────────────────────────────────
  ▓ MEDIATION PLANE ▓   default-deny → target-isolation →          ← every tool call
                        sign marker → kill-gate                       crosses here
  ─────────────────────────────────────────────────────────────
  tool layer            discover · develop · detonate · scratch
  provider abstraction  one tool-calling surface for any backend
                        Ollama · llama.cpp · vLLM · SGLang · hosted APIs
  model                 any — local open-weight OR hosted, swappable by config

  target/task + scoring adapters plug in here — ExploitGym, the exploitgym-eval
  scorer, NYU CTF, etc. are OPTIONAL adapters, never core.
```

The lifecycle and its component specs:

```
  DISCOVER          DEVELOP           DELIVER            OBSERVE
  vuln analysis  →  exploit / PoC  →  detonation     →  measurement
  discovery-stage   develop-stage     detonate-stage     (in each stage)
```

---

## Document map

Start with `DESIGN.md`; the rest are components and policies it links.

| Document | Role |
|---|---|
| [`DESIGN.md`](./DESIGN.md) | Architecture spec — layers, containment plane, measurement, open items. The spine. |
| [`discovery-stage.md`](./discovery-stage.md) | **Discover** — static + dynamic vulnerability analysis; the finding artifact; handoff to the store. |
| [`develop-stage.md`](./develop-stage.md) | **Develop** — exploitation engineering up the crash→primitive→control→exploit ladder. |
| [`detonate-stage.md`](./detonate-stage.md) | **Detonate** — red-tier live-fire in the chamber; the dual detection-coverage / containment-integrity measurement. |
| [`disclosure-policy.md`](./disclosure-policy.md) | Coordinated Vulnerability Disclosure for third-party findings (ISO/IEC 29147/30111, CERT-CC). |
| [`munitions-custody-policy.md`](./munitions-custody-policy.md) | Chain-of-custody governance for the munitions store. |
| [`week-one-spike.md`](./week-one-spike.md) | The build runbook — five days, real commands, hard acceptance gates. |
| [`FINDINGS-week-one-spike.md`](./FINDINGS-week-one-spike.md) | Results template for the spike. |
| [`src/`](./src/README.md) | **The implementation** — the `aegis` CLI, the enforcing seam, the develop/operator stages, the munitions store, detonate, and disclosure. |
| [`spike/`](./spike/README.md) | The genuine week-one Day-1..5 spike scaffolding, kept as a dated record. |

---

## Safety & governance posture

This is a defensive-research instrument: *it measures offensive-agent capability inside a
box it cannot leave.* The controls are structural, not advisory:

- **Containment is enforced in code.** Five runtime invariants — target isolation,
  default-deny governance, dry-run-first, kill switch, signed (HMAC) markers — instantiated
  as a dispatch gate every tool call crosses (`DESIGN.md` §6). Violation is an error the
  code raises, not a judgment an operator makes.
- **Analyze a copy, never attack a live system.** A "target" is always something the
  harness instantiates and controls inside the isolation boundary. Bug-hunting third-party
  software means running *its code as a copy in the sandbox* — never reaching a system the
  operator does not control (`DESIGN.md` §2).
- **The harness finds; a human discloses.** The autonomous agent never contacts a vendor or
  publishes; a named human authorizes every external action, and confirmed third-party
  vulns are embargoed under coordinated disclosure (`disclosure-policy.md`).
- **Disclose the vulnerability, never the weapon.** Munitions rest inert and encrypted;
  what is disclosed is a minimal reproducer, never a working exploit
  (`munitions-custody-policy.md`).

Detection-evasion as an end, and action against non-target systems, are **unrepresentable —
not merely restricted** (`DESIGN.md` §2, §6).

---

## Status & where to start

- **Design phase complete** — the full lifecycle and both governance gates are specified.
- **Implemented and running** — the harness lives in [`src/`](./src/README.md): the `aegis`
  CLI over Goose, the enforcing mediation seam, the develop and operator stages, the munitions
  store, the detonate control plane, and the coordinated-disclosure workflow, with passing test
  suites across the components. The green tier runs end to end (the operator cockpit found,
  contained, and characterized a real third-party defect); the red-tier detonate substrate
  (Firecracker) is code-complete and awaiting deploy.
- **How it started:** [`week-one-spike.md`](./week-one-spike.md) resolved the fork choice and
  the tool-call-format risk by building; results in
  [`FINDINGS-week-one-spike.md`](./FINDINGS-week-one-spike.md). The scaffolding from that week
  remains under [`spike/`](./spike/README.md).

Open design questions are tracked in `DESIGN.md` §9 and in each stage/policy doc's own
open-items section (notably the cross-cutting **volume/severity gating** the two policies
share).

---

## Optional connections to other AEGIS Labs work

These are **optional adapters and downstream consumers**, not dependencies (`DESIGN.md`
§1.1). The harness is fully usable with none of them.

- [`safe-agentic-bas`](../safe-agentic-bas/) — one containment model the harness can
  *validate*; the harness does not depend on it.
- [`exploitgym-eval`](../exploitgym-eval/) — its causal-necessity scorer is *one scoring
  adapter* you can plug into the **discover** stage; any scoring adapter works.
- [`detection-posteriors`](../detection-posteriors/) — a possible *downstream consumer* of
  **detonate**-stage detection outcomes, not a coupling in the harness.
- [`agentic-identity-pivots`](../agentic-identity-pivots/) /
  [`polymorphic-attack-chains`](../polymorphic-attack-chains/) — possible downstream
  consumers of blast-radius / lateral-movement measurement.

---

© 2026 Adversarix, Inc. · Released through AEGIS Labs. Method and architecture only; no
offensive tradecraft, exploits, or engagement data appear here.
