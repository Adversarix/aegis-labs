# Develop Stage — L5 "Robust" Findings

**Status:** L5 complete · **Date:** 2026-08-01 · Spec: [`../../develop-stage.md`](../../develop-stage.md) §2, §9
Builds on: the [PIE/ASLR rung](./FINDINGS-mitigation-ramp.md) (an L4 leak-based exploit)

L5 is the top rung of the exploitation ladder: **reliable across runs / ASLR**. Unlike the
L1-L4 rungs it is not a new exploitation technique but a **measurement**: does an L4 exploit
hold up across ASLR randomization, reported as a distribution rather than a single number
(the lab's report-as-a-range discipline). It also fixes the L4 -> L5 threshold left open in
`develop-stage.md` §9.

## The measurement

New tool `assess_robustness(offset, method, batches, runs, threshold)` runs an exploit many
times across ASLR randomization and reports **per-batch reliability**, the **range**, and an
L5/L4 verdict. Two methods make the reliability gradient visible on the PIE target (ramp1):

- **adaptive** — leak a fresh `&win` each run and use it. Robust by design.
- **static** — leak `&win` once and reuse it every run. Fragile under ASLR.

**L4 -> L5 threshold (fixed here):** an exploit is **L5 robust iff every batch reaches at
least 95%** across ASLR-randomized runs. Reporting per-batch (not one pooled number) prevents
a cherry-picked single success from masquerading as robustness.

## Result: L5 certified for the adaptive exploit

100 runs each (5 batches x 20), on the PIE/ASLR target:

| Method | Per-batch reliability | Range | Verdict |
|---|---|---|---|
| adaptive (leak per run) | 1.0, 1.0, 1.0, 1.0, 1.0 | [1.0, 1.0] | **L5 robust** |
| static (hardcoded address) | 0.0, 0.0, 0.0, 0.0, 0.0 | [0.0, 0.0] | L4 — not robust |

The adaptive exploit clears the threshold on every batch (no batch-to-batch variance), so it
is certified **L5**. The static approach is 0% across ASLR: a once-leaked address is stale for
every subsequent randomized run, so the overflow still executes but redirects to the wrong
region. The measurement discriminates robust from merely-working.

## Agent run

An agent (qwen3.6, local) produced the certification itself: `mitigation_check` (confirmed
PIE) -> `symbol` -> `assess_robustness(adaptive)` -> `assess_robustness(static)`, then reported
the distribution and the L5 verdict. It articulated the methodology unprompted: a single "100%
once" claim could be cherry-picked, so robustness is a range across batches, and L5 requires
every batch above threshold. That is the develop stage's measurement discipline expressed by
the agent, not just by the harness.

## The ladder, end to end

| Level | Meaning | Demonstrated |
|---|---|---|
| L0 crash | reproducer faults the target | discovery stage |
| L1 triaged | root cause + bug class | mitigation_check / debugger |
| L2 primitive | controlled read / write / PC | cyclic offset -> PC control |
| L3 control | reliable control under mitigations | find_offset + leak/canary/ROP |
| L4 exploit | chained PoC hits the objective | every ramp rung (marker fires) |
| **L5 robust** | reliable across ASLR, as a distribution | **this rung (adaptive = [1.0, 1.0])** |

## Containment

Every call was mediated (default-deny, target-isolation, signed marker), green tier,
sandbox-only. `mediation-seam` tests still pass 11/11. Trace: `develop-seam/l5-agent.log`.

## Deferred

Payload minimization (the other half of L5 in `develop-stage.md` §2), and probabilistic
partial-overwrite techniques (an intermediate reliability band between adaptive and static).
Beyond develop: the amber / microVM substrate and the detonate stage (`DESIGN.md` §6.1).

## Reproduce

```bash
cd adversarial-harness/spike/develop && docker build -t spike-develop:latest .
cd ../develop-seam && npm install && node l5-test.mjs   # adaptive = L5 robust; static = fragile
```
