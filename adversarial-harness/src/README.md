# adversarial-harness — components

The mature harness, graduated out of the week-one spike (`../spike/`). Each subdirectory
is an independent component wired together through the enforcing mediation seam; the
`aegis` CLI is the entry point. Design docs live one level up (`../DESIGN.md`, the
`*-stage.md` runbooks, the policy docs).

Green tier is enforcing by default; amber/red (detonate) and disclosure are built and
gated. Every tool call an agent makes crosses one logged chokepoint (`mediation-seam/`)
and, on a `deny` verdict, does not execute.

## Entry point — the `aegis` CLI

[`aegis/`](./aegis/) is a thin CLI over Goose that packages the seam wiring, scope, keys, model
selection, and the munitions store behind subcommands (`aegis develop --target ramp1
--interactive`, `aegis store dispose <id> --role custodian --actor alice`, `aegis doctor`). It does
not fork Goose. See [`aegis/README.md`](./aegis/README.md).

```bash
node aegis/bin/aegis.js init && node aegis/bin/aegis.js doctor
( cd aegis && node aegis.test.mjs )   # 26 CLI tests
```

## Enforcing mediation seam

The seam evaluates `../DESIGN.md` §6 invariants — default-deny, target-isolation, signed
markers, kill-gate — and on a `deny` verdict the tool does not execute. See
[`mediation-seam/README.md`](./mediation-seam/README.md) and run
`cd mediation-seam && npm test`.

## Develop stage (exploit dev)

The develop-stage build-first slice (`../develop-stage.md` §8): a mitigations-off
ret2win target ([`develop/`](./develop/)) and the exploit-dev tools including the
**persistent-debugger Interactive Agent Tool**, behind the enforcing seam
([`develop-seam/`](./develop-seam/)). An agent climbed the exploitation ladder to
**L4** (working exploit firing a signed objective marker, 10/10). The
with/without-debugger ablation and the ARM64 substrate note are in
[`develop/FINDINGS-develop-stage.md`](./develop/FINDINGS-develop-stage.md).

## Munitions store + discovery→develop handoff

A real custody store ([`munitions-store/`](./munitions-store/)) implements the munitions
custody policy in code: inert-by-default, an append-only HMAC-signed hash-chained ledger,
AES-256-GCM encryption at rest, human-gated dispose (the harness cannot self-authorize
arm/export/dispose), and verified crypto-shred disposal. It is the through-line for the
**discovery→develop handoff**: the discovery seam's `promote_finding` turns a confirmed crash into
an inert munition; the develop seam's `ingest_munition` / `record_progress` pick it up and climb
the ladder. Both seams share the store via `AEGIS_STORE` + `AEGIS_STORE_KEY`; every custody op
still crosses the enforcing gate. See [`munitions-store/README.md`](./munitions-store/README.md).

```bash
( cd munitions-store && node store.test.mjs )         # 29 store unit tests
( cd develop-seam && node handoff-test.mjs )          # end-to-end handoff through both seams
```

## ExploitGym Path-B adapter

[`exploitgym-adapter/`](./exploitgym-adapter/) runs a model against an ExploitGym-style task
*through* the contained develop-seam (our tools + mediation), then emits an ExploitGym-compatible
result the `../../exploitgym-eval` scorer consumes — Path B to exploitgym-eval's Path A. The develop-seam
gained `AEGIS_TASK_BINARY` to mount an arbitrary target. Proven against a local aarch64 fixture (both
a scripted solver and a live agent capture the flag through our gated tools). Real ExploitGym tasks
need the ExploitGym clone + an x86_64 sandbox — see [`exploitgym-adapter/README.md`](./exploitgym-adapter/README.md).

## Cross-model comparison

[`compare/`](./compare/) runs the same develop task through the same contained seam across several
models (swapped by config) and produces a leaderboard, using the mediation log to turn "solved or
not" into "how it failed". First result on the PIE/ASLR task, spanning a local backend (Ollama) and two hosted ones (Fireworks, DashScope):
qwen3-max, kimi-k3, and the qwen3.6 family solved it cleanly in 3 calls (qwen3-max fastest at 11s), while the
smaller/older models failed by distinct traceable modes — all under identical containment (0 denials).
The neutrality claim holds local and hosted by a config swap; run-to-run non-determinism is visible
(a model flipped solved/failed across batches), which is why a converged comparison reports a range.
See [`compare/FINDINGS-cross-model.md`](./compare/FINDINGS-cross-model.md).

## Red-tier detonate stage (control plane)

[`detonate/`](./detonate/) implements the detonation chamber's substrate-agnostic control plane
(`../detonate-stage.md`, `../DESIGN.md` §6.1): the loop, the six invariants enforced in code, custody
arm/detonate/disarm, the T0 deception sinkhole, and marker injection — with a substrate abstraction.
`LocalHarnessSubstrate` (non-isolating) verifies the whole control plane on any machine, including
the build-first early-exit gate: **teardown guaranteed under a mid-detonation kill**. A real munition
is refused on it; that requires `FirecrackerSubstrate` (real microVM, Linux/KVM), which is
code-complete (`detonate/firecracker-host/`) and ready to deploy on the provisioned GCP host. See
[`detonate/FINDINGS-detonate-build-first.md`](./detonate/FINDINGS-detonate-build-first.md).

```bash
( cd detonate && node detonate.test.mjs )   # 16 tests incl. teardown-under-kill
```

## Operator research cockpit (walking skeleton)

[`operator/`](./operator/) is the **cockpit** face of the harness (vs. the eval face above): point it at
a **real third-party target** and DO the research end to end — ingest + build in the sandbox, hunt with
libFuzzer+ASan (`--network none`), confirm the crash, promote the reproducer to real signed custody,
characterize it honestly, and open a real coordinated-disclosure case. Every op is **seam-mediated**
(`operator.mjs` is an MCP client driving `operator/seam.js`, so hunt/reproduce/triage/promote cross the
enforcing gate with signed markers). Proven on `stb_image` 2.19: a real uncontrolled-allocation defect
(CWE-789) found, contained, taken into custody, characterized as non-weaponizable, and an embargoed
disclosure case opened that the autonomous loop cannot self-report. See
[`operator/FINDINGS-operator-walking-skeleton.md`](./operator/FINDINGS-operator-walking-skeleton.md).

```bash
( cd operator && npm install && docker build -t aegis-operator-stb:latest . && node operator.mjs --seconds 90 )
( cd operator && node operator.test.mjs )   # 20 tests: classifier + seam mediation (no docker)
```

## Coordinated disclosure workflow (§6.2)

[`disclosure/`](./disclosure/) implements the CVD policy for third-party finds: the `disclosure_status`
state machine, a 90-day embargo clock, and a signed case ledger. Two rules enforced in code — **the
harness finds, a human discloses** (every advance out of `embargoed` needs a disclosure-owner token; the
loop cannot self-report) and **disclose the vuln, never the weapon** (a case carries metadata + a
minimal-reproducer description, never the reproducer bytes; guarded by `assertNoWeapon`). Wired into the
operator loop. See [`disclosure/README.md`](./disclosure/README.md).

```bash
( cd disclosure && node disclosure.test.mjs )   # 22 tests: both rules, state machine, embargo, n-day, ledger, store binding
```
