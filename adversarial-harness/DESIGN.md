# Adversarial Research Harness — Architecture Spec

**Status:** Draft v0.1 · **Date:** 2026-07-31 · **Owner:** K. Galappatti (AEGIS Labs)

A greenfield, security-native agentic CLI for autonomous adversarial research: **any model
— local or hosted** — driven through a forked OSS agent harness whose tool layer is
purpose-built for offensive-security research **and** whose every action passes through a
code-enforced containment plane. General-purpose and model-agnostic by construction (§1.1).

This is a design doc, not an implementation. It fixes the architecture, the layer
boundaries, the governance model, and a week-one acceptance test before any code is
forked.

---

## 1. Thesis

A **general-purpose cybersecurity research harness**: a security-native agentic CLI that
drives *any* model through the offensive-research lifecycle while every action stays inside
code-enforced containment. It answers, for whatever model and task you point it at:

> **How much offensive-research capability does this agent have, and does the containment
> plane hold while we measure it?**

Two goals that appear to conflict are deliberately co-designed:

- **Stronger agent** (capability) — push what an autonomous agent can do on
  offensive-research tasks, via security-native interactive tools and, optionally, model
  steering.
- **Contained agent** (safety) — every action mediated by runtime invariants enforced
  in code, not policy, so the harness is safe to run unattended and its results are
  reproducible.

The tension is the contribution: run a *capable* adversary against a *real* containment
plane and report what holds. Most offensive-agent work ignores containment; most
containment work uses toy agents.

### 1.1 Neutrality — general-purpose by construction

The harness is an **instrument, not an application of one use case.** Three neutralities
are load-bearing design requirements, not preferences:

- **Model-agnostic.** Runs **local *and* hosted** models interchangeably — Ollama /
  llama.cpp / vLLM / SGLang for local, and any hosted API for the rest — behind a provider
  abstraction (§4 L3). No model, family, or provider is privileged; swapping the model is a
  config change, not a code change.
- **Target/task-agnostic.** The harness is not bound to any one benchmark, task source, or
  target format. Tasks and targets enter through **adapters** behind a stable interface;
  it ships example adapters, it is not built around any of them.
- **Use-case-agnostic.** It carries **no bias from prior AEGIS Labs research.** ExploitGym,
  the `exploitgym-eval` scorer, `detection-posteriors`, `safe-agentic-bas`, and the rest
  are **optional adapters / points of connection**, never dependencies. The harness must
  be fully usable by someone who has never seen any of that work.

Where a later section connects to existing AEGIS Labs work, it does so as *"one adapter you
could plug in,"* not *"the way this works."* If a coupling can't be expressed as a
swappable adapter, it does not belong in the core.

---

## 2. Scope & authorization

This is a **general-purpose cybersecurity research harness** — not scoped to the org's
own assets. It analyzes and attacks **targets it instantiates inside the isolation
boundary**, and that explicitly includes **software the org does not own**: bug-hunting
third-party code is in scope (the OSS-Fuzz / Project-Zero / CyberGym research pattern).

**In scope.**
- Autonomous vuln discovery (§5.1) over source and binaries, **including third-party
  software the org does not own**, under a mandatory coordinated-disclosure obligation
  (§6.2).
- Exploit development and **live-fire detonation of real munitions** (§6.1) against
  targets the harness stands up inside the box.
- Measurement of capability and of containment behavior.

**The load-bearing distinction — analyze a copy ≠ attack a live system.** A "target" is
always something the harness *instantiates and controls inside the isolation boundary*.
Hunting bugs in third-party software means running **its code, as a copy you stand up in
your own sandbox** — never reaching out to a system you do not control. The
target-isolation invariant (§6) *is* this line, and it does not move when scope broadens
to third-party code. "Software you don't own" is in scope to analyze in-box; "systems you
don't control" remain out of scope to act against.

**Out of scope, by construction.** Acting against any live system the org does not own or
is not authorized to test; detection-evasion tradecraft as an end in itself; mass
targeting; anything the containment plane cannot mediate. These are not "discouraged" —
the mediation layer denies them by default (§6).

**Authorization & disclosure posture.** A defensive-research instrument: *it measures
capability inside a box it cannot leave.* Signed synthetic-action markers (§6) make every
run attributable and unforgeable. Because third-party bug-hunting is now in scope, the
harness carries a **coordinated-disclosure obligation** (§6.2): a confirmed vulnerability
in software the org does not own is a responsibility the moment it exists, and its
munition is embargoed until disclosure norms are met.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  CLI / harness            forked OSS agent CLI (interactive)   │  L1
│    ├─ UX, session, history                                    │
│    └─ agent loop: turn control, context mgmt, trajectory log  │  L2
├──────────────────────────────────────────────────────────────┤
│  ▓▓▓  MEDIATION / CONTAINMENT PLANE  ▓▓▓                       │  ← every tool call
│    default-deny → target-isolation → sign marker → kill-gate  │     crosses here
├──────────────────────────────────────────────────────────────┤
│  tool layer               security-native tools (MCP exts)    │  governed dispatch
│    vuln analysis (static/dynamic) · interactive debugger      │
│    remote target · exploit primitives · research scratchpad   │
│    recon/payload/C2 (gated) · live-fire detonation            │
├──────────────────────────────────────────────────────────────┤
│  provider abstraction     one tool-calling surface for any    │  L3
│    backend: Ollama · llama.cpp · vLLM · SGLang · hosted APIs   │
├──────────────────────────────────────────────────────────────┤
│  model                    any — local open-weight OR hosted,  │  L4
│    swappable by config; no model/provider privileged          │
└──────────────────────────────────────────────────────────────┘

  target/task + scoring ADAPTERS bind to the tool layer & measurement (§7);
  ExploitGym, the exploitgym-eval scorer, etc. are optional adapters, not core.
```

The mediation plane sits **between the agent loop and tool execution**, not around the
whole process. The agent *proposes* a tool call; the plane *decides* whether it runs.
This physical placement is what makes containment "in code, not policy": the agent
cannot reach a tool except through the gate.

---

## 4. Layer specifications

### L1 — CLI / harness (fork)

**Decision:** interactive human-in-the-loop CLI (not a batch runner). Human drives,
agent proposes and acts, tight loop — the right mode for capability research with
oversight.

**Fork base — primary: Goose (Block).** Chosen for one structural reason: tools are MCP
extensions, so the offensive tool layer *and the mediation plane* live outside the agent
loop as a governed dispatch layer. That separation is exactly the "enforced in code"
property the invariants require. In a monolithic loop, policy checks get threaded
through agent code — which is how containment rots.

**Fork base — fallback: OpenCode (SST).** TS codebase, faster to hack, provider-agnostic.
Chosen only if the team wants to own the loop directly and is willing to build the
mediation seam by hand.

**Not forkable:** Claude Code (closed) — UX reference only.

**Mined for tool design regardless of base:** EnIGMA (SWE-agent offensive fork). Its
*Interactive Agent Tools* — a persistent debugger and persistent remote target that
coexist with the main shell — are the specific mechanism behind its reported 3.3× gain
on NYU CTF and are the capability lever here (§5).

### L2 — Agent loop

Inherited from the fork. The one addition we own: **first-class trajectory capture**
(§7). A research harness's product is the measured trajectory, and generic coding CLIs
log it poorly.

### L3 — Inference (a provider abstraction, not one engine)

**Decision:** the harness talks to a **provider abstraction**, not a specific engine. Any
backend that speaks the abstraction is first-class:

- **Local:** Ollama / llama.cpp (runs on commodity hardware, incl. Apple Silicon — no CUDA
  needed), or vLLM / SGLang (research-grade GPU serving, logprobs, guided decoding).
- **Hosted:** any provider API — native or OpenAI-compatible.

The common surface is an OpenAI-compatible `/v1/chat/completions` with tool-calling; native
provider formats are reached through thin shims behind the same abstraction. Neutrality
requirement (§1.1): **selecting a backend is configuration.** The same run works against a
laptop Ollama model and a hosted frontier model with only a config change; research-grade
signals (logprobs, guided decoding) are *available where the backend supports them*, not
assumed.

**The load-bearing integration risk — tool-call format.** The forked CLI emits tool schemas
and expects a specific function-calling response shape. Every backend parses/emits tool
calls differently (vLLM's `--tool-call-parser` and chat template; Ollama's templating; each
hosted API's native format). If the emitted format doesn't match what the loop parses,
**the agent looks broken — no tools ever fire — for reasons unrelated to capability.** The
provider abstraction's job is to normalize this; proving the round-trip **across at least
one local and one hosted backend** is the first thing the week-one spike must kill (§8).

### L4 — Model (agnostic)

**Decision:** **model-agnostic — local open-weight and hosted, both first-class,
swappable.** No model or provider is baked in. The choice is per-study, and the tradeoffs
are documented, not decided for the operator:

- **Open-weight (local)** offers full instrumentation (logprobs, ablation), optional
  fine-tuning, and no provider-ToS/refusal constraints on offensive tasks — the right pick
  when the study needs those.
- **Hosted (frontier)** offers strongest raw capability and zero serving ops — the right
  pick for a capability ceiling or a quick baseline, accepting possible refusals/ToS limits.

Comparing *across* models is a first-class use (that is much of what a general-purpose
harness is *for*), so the harness must run them side by side. Any model with usable
tool-calling is a candidate; concrete choices (e.g. Qwen3 or Kimi K3 locally, a hosted
frontier model as a ceiling) are **examples for the spike**, not a fixed roster — and
carry no ranking imported from prior AEGIS Labs benchmarks.

---

## 5. Capability: what makes the agent "stronger"

The harness spans an offensive-research **lifecycle**, and capabilities map onto its
stages:

```
  DISCOVER            DEVELOP              DELIVER              OBSERVE
  vuln analysis  →    exploit / PoC   →    detonation      →   measurement
  (§5.1)             (§5.2)               (§6.1 chamber)       (§7)
```

Component specs: discover → [`discovery-stage.md`](./discovery-stage.md);
develop → [`develop-stage.md`](./develop-stage.md);
detonate → [`detonate-stage.md`](./detonate-stage.md).

Discovery is the front-end that the draft under-specified, and for the "stronger agent"
goal it is the **highest value-per-risk stage**: finding the bug is the hard, valuable
part, it is mostly green-tier (analysis, not action — §6), and it does not need the
detonation chamber. It is the right capability to build *first*, ahead of live-fire.

Capability classes, cheapest-signal-first:

1. **Vulnerability analysis** (discovery) — §5.1. Static + dynamic bug-finding over
   source and binaries. Build-first.
2. **Interactive Agent Tools** (EnIGMA-style, develop — §5.2): persistent debugger
   (gdb/pwndbg) and persistent target connection that coexist with the shell.
   Highest-leverage *develop*-stage addition — measure raw-vs-tool on task one.
3. **Exploit-dev primitives** (develop — §5.2) in-sandbox: pwntools, cyclic offset find,
   ROP/gadget search, checksec/mitigation view, crash-vs-clean-exit parsing (so the model
   reads the signal a generic loop swallows).
4. **Research-specific tools** a coding CLI lacks: a persistent hypothesis/notes
   scratchpad the agent maintains across turns; structured self-reflection on failed
   attempts.
5. **Model steering / fine-tuning** on offensive-research trajectories — deferred until
   the tooled baseline is measured, so we can attribute gains.

### 5.1 Vulnerability analysis (discovery)

> Concrete component spec: [`discovery-stage.md`](./discovery-stage.md) — analysis loop,
> tool interface, finding artifact, munitions handoff, isolation, and the build-first slice.

The model's value here is not replacing the analyzers — it is the **reasoning glue** over
them: hypothesizing where a bug lives, directing the tools at it, triaging their output,
root-causing, and judging exploitability. That glue is exactly what raw fuzzers and
linters lack, and where an agent earns its keep.

- **Static analysis.** Source reading at scale; dataflow/taint; pattern engines
  (Semgrep/CodeQL); **patch-diff / n-day analysis** (diff a fix to locate the bug it
  fixed); binary RE via headless Ghidra/angr and disassembly.
- **Dynamic analysis.** Coverage-guided fuzzing (AFL++/libFuzzer/honggfuzz) with
  sanitizers (ASan/UBSan/MSan); symbolic/concolic execution (angr/KLEE); crash triage,
  root-cause, and exploitability assessment.

**Where it sits in the planes:**

- *Static* analysis is **green-tier** — reading and analyzing authorized code, no target
  executes.
- *Dynamic* analysis **executes the target**, so it runs inside the isolation boundary
  (sandbox), and its outputs — crashing inputs, PoCs — are proto-munitions that flow into
  the munitions store (§6.1) the moment they become weaponizable. Fuzzing a
  deliberately-vulnerable target is still research-benign; the isolation requirement is
  about *the target running*, not about detonating a weapon.
- **The sensitive edge is scope, not technique:** vuln analysis of **real third-party
  code the org does not own** (n-day/0-day hunting — the CyberGym / SEC-bench /
  Bounty-Bench setting) is **in scope** (§2). It is governed, not gated: the code runs as
  a copy inside the isolation boundary, and any confirmed vuln enters coordinated
  disclosure and is embargoed in the store (§6.2).

**Measurement is unusually clean here:** discovery has a crisp ground truth — did the
agent find the *target* vulnerability? Scoring is pluggable (a **scoring adapter**, §7); a
causal-necessity check — of which the `exploitgym-eval` scorer is *one available adapter* —
is a natural fit, but the stage is not bound to it.

### 5.2 Exploit development (develop)

> Concrete component spec: [`develop-stage.md`](./develop-stage.md) — the exploitation
> ladder, the Interactive Agent Tools, tool interface, custody/disclosure/detonate
> handoff, graded measurement, and the build-first slice.

The develop stage turns a crash into a working exploit, climbing an **exploitation ladder**
(crash → triaged → primitive → control → exploit → robust) that makes capability *graded*,
not pass/fail. It is where the Interactive Agent Tools (a persistent debugger and target
connection kept open *together*) do their work — the EnIGMA mechanism — and thus the direct
test of the design's central claim that a security-native tool makes the agent stronger.
Note on `DESIGN.md` §6.1 item 5: develop **engineers an exploit for a specific found bug
using established techniques**; that is standard exploitation engineering, distinct from
synthesizing *novel universal tradecraft* — the two statements are not in tension
(`develop-stage.md` §9).

---

## 6. Containment: the mediation plane

The plane is not a wrapper added at the end — it is the **measurement apparatus** for
the containment research goal, so it is load-bearing from the first commit. Every tool
call crosses it in order:

1. **Default-deny governance.** A tool call executes only if its class is explicitly
   permitted for the current run's authorized scope. Dual-use classes (recon, payload,
   C2) are denied unless the run is scoped to an authorized, isolated target.
2. **Target-isolation assertion.** The call's target must resolve to an ephemeral twin
   inside the run's isolation boundary. Anything else is denied — the agent can only act
   on things built to be acted upon.
3. **Signed-marker injection.** Every synthetic action carries an HMAC-signed marker:
   attributable *and* unforgeable. Real IR is never tripped; a real intruder cannot
   hide behind the harness.
4. **Kill-gate.** A run-level kill switch the agent cannot argue past; violation of any
   invariant is an error the code raises, not a judgment an operator makes.

These are the five `safe-agentic-bas` invariants (target isolation, default-deny,
dry-run-first, kill switch, signed markers) instantiated as a dispatch gate. Ephemeral
twins bound blast radius by construction; teardown is guaranteed even on failure or kill.

**Tool governance tiers:**

| Tier | Classes | Gate |
|---|---|---|
| **Green** | static vuln analysis (authorized code), dynamic analysis/fuzzing in-sandbox, interactive debugger, exploit-dev primitives (sandboxed), research scratchpad, trajectory | permitted by default inside isolation |
| **Amber** | local recon, target enumeration, vuln analysis of real third-party code | permitted only for the run's authorized scope (third-party code additionally requires a disclosure policy — §9) |
| **Red** | payload generation, C2-style capability, live-fire detonation, anything network-reaching beyond scope | denied unless explicitly scoped + isolated; dry-run-first required |

Detection-evasion-as-an-end and action against non-target systems have **no tier** —
they are unrepresentable, not merely restricted.

### 6.1 Detonation chamber (live-fire targets)

> Concrete stage spec: [`detonate-stage.md`](./detonate-stage.md) — the detonation loop,
> guest lifecycle, sensor stack, deception-network tiers, marker injection, and the
> dual detection-coverage / containment-integrity measurement.

Detonating real munitions is the apex red-tier action and the hardest test of the
containment plane: it executes real, potentially self-propagating or destructive code
against a target. The mediation gate (§6) governs *whether* a detonation is authorized;
the **chamber** governs *where* it happens and guarantees it cannot leak. The two are
separate on purpose — the gate can be defeated by a bug, the chamber must hold even then.

**The substrate decision is forced.** Containers are insufficient — a real payload may
carry a kernel exploit or container escape, and a shared kernel is a shared blast
radius. The minimum is **hardware-virtualized isolation**: microVMs (Firecracker) or
full VMs, one disposable guest per detonation, no shared kernel with the host or with
other runs. This retires the "containers vs microVMs" open question for any run that can
reach the red tier: **detonation-capable runs are microVM/VM-isolated, non-negotiable.**

**Chamber invariants** (in addition to the §6 gate — all enforced in code):

1. **Network containment.** Default air-gap. Where a payload must "phone home" to
   exhibit behavior, egress is served by a **deception network** (fake DNS/HTTP/C2
   sinkhole, INetSim-style) inside the isolation boundary — never real egress. Real
   outbound network from a detonation guest is an error the code raises.
2. **Snapshot / rollback + guaranteed teardown.** Each guest boots from a known-clean
   snapshot and is destroyed after detonation — even on failure, kill, or crash. No
   guest is reused; persistence cannot survive teardown.
3. **Dry-run-first.** A detonation is planned and gate-checked in dry-run before any live
   execution. Live-fire requires an explicit, scoped promotion from the dry-run plan —
   never an agent's first action.
4. **Signed detonation markers.** Every detonation and its emitted telemetry/IOCs carry
   the HMAC-signed marker (§6): attributable and unforgeable, so chamber telemetry is
   never confused with a real incident and a real intruder cannot impersonate the sim.
5. **Munitions handling.** Payloads are stored **defanged and encrypted at rest** with
   recorded provenance; they are armed only inside the chamber, only for an authorized
   run. The harness *executes and measures* munitions supplied to it under authorization
   — it does not synthesize novel offensive tradecraft. Full store governance —
   custody ledger, arming/egress controls, retention & disposal — is
   [`munitions-custody-policy.md`](./munitions-custody-policy.md).

**What the chamber produces** is the research signal: behavioral traces, emitted IOCs,
target effect, and the full mediation/detonation log — the empirical data behind both
the capability and the containment claims.

### 6.2 Third-party research & coordinated disclosure

Bug-hunting software the org does not own is **in scope** (§2). That does not loosen
containment — it adds a downstream obligation, because a confirmed vuln in third-party
code is a real-world exposure that exists whether or not anyone else has found it.

**Two invariants keep third-party research legitimate:**

1. **Target-isolation still holds (unchanged).** A third-party "target" is a **copy of
   the software the harness stands up inside the isolation boundary** — its code, its
   binaries, run in your sandbox/microVM. The harness never acts against a system it does
   not control. Analyze a copy, never attack a live system. This is the §6 invariant, not
   a new one.
2. **Confirmed third-party vulns are embargoed by default.** A `confirmed_vuln`/munition
   whose target is third-party code (`target_match` aside — this is about *ownership*,
   tracked as an `ownership = third_party` tag) is registered in the store with
   `disclosure_status = embargoed`. Embargoed munitions may be used **only for in-box
   research against the copy** — they cannot be freely armed or exported until the
   disclosure workflow clears them.

**Disclosure workflow (stub — full policy is the residual §9 item):**

```
confirmed third-party vuln →
  record     { vendor/maintainer, affected versions, finding_id, reproducer_ref }
  notify     open a coordinated-disclosure case with the vendor
  embargo    default 90-day clock; munition stays disclosure_status = embargoed
  advance    → disclosed (vendor fixed / timeline elapsed) → publishable
```

The store gains a `disclosure_status` field (`embargoed | disclosed | published |
n/a`); `n/a` is for owned/benign targets, which carry no disclosure duty. This turns "may
hunt third-party bugs" into a governed capability rather than an unbounded one — the
harness can *find* freely, but what it finds is handled responsibly by construction.

> Full policy: [`disclosure-policy.md`](./disclosure-policy.md) — the complete CVD
> lifecycle, timelines, exceptions, and the two governing rules (*the harness finds, a
> human discloses*; *disclose the vulnerability, never the weapon*).

---

## 7. Measurement

Every run emits a structured trajectory: each tool call (proposed + mediation verdict +
result), token counts, logprobs where available, wall-clock, and outcome. Two things
fall out of this for free:

- **Capability signal** — raw-vs-tool deltas, per-tool contribution, failure taxonomies.
- **Containment signal** — every mediation decision is logged, so "what did the agent
  *try* that the plane denied" is a first-class, reportable result. That log is the
  empirical data behind the containment paper.

> Concrete component spec: [`scoring-adapter.md`](./scoring-adapter.md) — the pluggable
> interface that turns a run's normalized evidence into a standard scored result, so every
> stage reports a comparable capability number (and no scorer is privileged, §1.1). The
> `exploitgym-eval` scorer is one selectable adapter.

---

## 8. Week-one spike (acceptance test)

> Concrete runbook: [`week-one-spike.md`](./week-one-spike.md) — five days, real commands,
> hard acceptance gates per day, guardrails, and a decision log.

Do not build the full CLI to learn what must be learned. In order:

1. **Backend round-trip + neutrality.** Prove **one tool call round-trips** through the
   *unmodified* forked CLI on **at least one local backend (Ollama, no GPU) and one hosted
   backend** — same tool schema, backend swapped by config. *This is the acceptance gate —
   it kills the format risk and proves neutrality before anything else.* (A GPU/vLLM
   re-check is deferred to where the capability signal needs it.)
2. **Mediation seam.** Fork Goose, insert the mediation plane as a **no-op pass-through
   that logs every dispatch.** The containment seam exists before any offensive tool does.
3. **First capability + containment data point.** Add one Interactive Agent Tool
   (persistent debugger/target) behind the seam, on one ephemeral contained task.
   Measure raw-vs-tool. First capability delta *and* first containment trace, together.

**Early-exit signal:** if step 1 shows the chosen model won't engage the task even
untooled, the center of gravity moves to model choice / elicitation — a week-one
discovery, not a month-three one.

---

## 9. Open questions

- **Fork lock-in.** Goose (MCP-clean, younger) vs OpenCode (hackable, TS) — decide after
  a one-day spike on each with the step-1 round-trip.
- **Isolation substrate.** Resolved for detonation-capable (red-tier) runs: microVM/VM,
  one disposable guest per detonation (§6.1). Still open for green/amber-only runs, where
  containers may suffice — trading teardown-guarantee strength against setup cost. Open
  sub-question: run everything on the microVM substrate for uniformity, or tier the
  substrate to the run's capability tier?
- **Deception network fidelity.** Tier model defined (`detonate-stage.md` §5: T0 sinkhole
  / T1 simulated services / T2 simulated internet). Residual: the **default tier** and
  per-run override policy — pick the minimum tier that makes a payload's behavior
  observable. Related residuals now tracked in `detonate-stage.md` §10 (sensor stack,
  detection-rule sourcing, twin richness, third-party pre-disclosure detonation gate).
- **Munitions provenance & chain of custody.** ~~How is the store governed, who
  authorizes arming?~~ **Policy drafted (2026-08-01):**
  [`munitions-custody-policy.md`](./munitions-custody-policy.md) — append-only signed
  custody ledger, inert-by-default with chamber-only arming, human-authorized
  arm/export/dispose, no-egress-of-the-weapon, verified disposal, and *minimize the
  standing arsenal*. Covers both supplied and discovery-produced munitions (on/off-target,
  owned/third-party). Residual sub-items in that doc §10 (key-custody model, retention
  horizons, cross-run reuse, volume gating).
- **Third-party vuln discovery.** ~~Allowed at all?~~ **RESOLVED (2026-08-01): yes —
  general-purpose harness, third-party bug-hunting is in scope (§2).** Governed by
  target-isolation (analyze a copy in-box, never attack a live system) and mandatory
  coordinated disclosure with default embargo (§6.2). **Full policy drafted (2026-08-01):**
  [`disclosure-policy.md`](./disclosure-policy.md) — CVD lifecycle, 90-day embargo +
  exceptions, unresponsive-vendor coordinator path, human-gated disclosure, never-publish
  the weapon. Residual sub-items tracked in that doc §10 (owner-authority model,
  coordinator relationships, publication bar, severity gating on finding volume).
- **Tool-call format stability** across backend/model swaps — each backend (vLLM parser,
  Ollama template, each hosted API) and model may emit tool calls differently; how much of
  that must the L3 provider abstraction normalize, and how much leaks into the harness?
- **Fine-tuning corpus** for phase-4 steering — sourced from the harness's own
  trajectories, or external? Governance of that corpus is itself a question.
- **Reproducibility** under non-deterministic sampling — report capability as a range
  across runs (the lab's established TTP-benchmark discipline).

---

## 10. References

- EnIGMA / SWE-agent — Interactive Agent Tools; 3.3× on NYU CTF
  ([arXiv:2409.16165](https://arxiv.org/pdf/2409.16165),
  [SWE-agent repo](https://github.com/swe-agent/swe-agent)).
- Fork bases — [Goose](https://github.com/block/goose) (primary),
  [OpenCode](https://github.com/sst/opencode) (fallback).
- Inference backends — Ollama / llama.cpp (local), vLLM / SGLang (GPU), hosted APIs; behind
  the L3 provider abstraction.
- Example target/task adapters (not dependencies) — NYU CTF Bench, Cybench, CyberGym, and
  the AEGIS `exploitgym-eval` scorer.
- Optional AEGIS Labs connections (as adapters / downstream consumers, per §1.1) —
  `safe-agentic-bas` (a containment model this harness can validate), `detection-posteriors`
  and `agentic-identity-pivots` (downstream consumers of detonate-stage output).
