# Detonate Stage — Component Spec

**Status:** Draft v0.1 · **Date:** 2026-08-01 · Parent: [`DESIGN.md`](./DESIGN.md) §6.1
Upstream: [`develop-stage.md`](./develop-stage.md) · Governs: [`munitions-custody-policy.md`](./munitions-custody-policy.md) arming

The **deliver/detonate** stage of the lifecycle (`discover → develop → deliver →
observe`): red-tier live-fire. It arms a finished munition inside the detonation chamber,
fires it against an **ephemeral digital twin**, and captures what happens — effect, IOCs,
blast radius, and **whether detection fires** — before guaranteed teardown.

This is the stage the `DESIGN.md` §6.1 sketch named but did not spec. Everything here runs
on the microVM substrate under the §6.1 chamber invariants; this doc concretizes the guest
lifecycle, the sensor stack, the deception network, and marker injection, and defines what
detonation *measures*.

---

## 1. Input & output

- **Input:** an `exploitation_level ≥ L4` Munition (a chained, reliable exploit),
  resting **inert** in the store (`develop-stage.md` §6).
- **Output:** a **detonation report** — effect, emitted IOCs, blast radius, detection
  outcomes, and a **containment-integrity verdict** — written to the trajectory and
  measurement (§8). The munition returns to inert; the twin is destroyed.

Detonate never leaves anything armed and never touches a system outside the twin.

---

## 2. Detonate vs. develop — effect, not function

Develop answers *does the weapon function* (achieve its objective on the vulnerable
software copy). Detonate answers *what happens when it is fired in a system context, and
can we see it.*

| | develop | detonate |
|---|---|---|
| Target | the vulnerable-software **copy** (minimal) | an **ephemeral digital twin** (system context + sensors + deception net) |
| Question | does the exploit work? | what is its effect, and does detection fire? |
| Tier | green / amber | **red** |
| Substrate | container (green) / microVM (amber) | **microVM/VM, always** |
| Munition | built, verified, left inert | **armed** (custody event), fired, auto-disarmed |

The twin is the key difference: not a bare binary but a richer ephemeral environment —
the vulnerable service *plus* surrounding host state, telemetry sensors, and a contained
network — so effect and detection are observable the way they would be in production.

---

## 3. Why detonate matters — two signals from one firing

A single detonation produces the design's two goals simultaneously (`DESIGN.md` §1):

1. **Detection coverage** (offensive → defensive). Fire a real technique at an
   instrumented twin and observe whether the detection stack catches it. This is the
   **detection-gap** measurement — the Adversarix thesis, and the reason a defensive
   platform runs offensive live-fire at all. It is the highest-value output here.
2. **Containment integrity** (the safety research). Detonation is where the containment
   plane is stressed hardest — a real, possibly self-propagating payload firing. Recording
   that every invariant held (target isolation, no real egress, guaranteed teardown) *is*
   the empirical containment result the harness exists to produce. Where the plane is most
   tested, it is most worth measuring.

Capability/effect and containment are the same run viewed twice — the co-design payoff
made concrete.

---

## 4. The detonation loop

```
  1. PROVISION   boot an ephemeral twin from a known-clean snapshot (microVM/VM);
                 stand up the sensor stack (§5) and the deception network (§5)
  2. ARM         armorer-authorized `arm` event (custody): pull the munition from inert
                 store into the chamber, bound to this run, time-boxed
  3. DRY-RUN     plan + gate-check the detonation with NO live payload — confirm target
                 isolation, marker injection, sensor readiness, deception-net reachability
  4. DETONATE    live-fire the armed munition at the twin; inject signed markers so every
                 synthetic action is attributable
  5. OBSERVE     capture effect, IOCs, telemetry, propagation/blast-radius, detection outcomes
  6. TEARDOWN    destroy the twin (guaranteed — even on failure/kill); auto-disarm the
                 munition (→ inert); guest never reused
  7. RECORD      detonation report → trajectory + measurement (§8)
```

Steps 3→4 are the load-bearing gate: **live-fire is an explicit, scoped promotion from a
passing dry-run**, never an agent's first action (§6.1 invariant 3).

---

## 5. Chamber mechanics (concretizing §6.1)

### Guest lifecycle

One disposable **microVM/VM per detonation**, no shared kernel with host or other runs
(§6.1). Boots from a known-clean snapshot; destroyed on completion, failure, or kill;
never reused. Snapshot + teardown are what make blast radius bounded by construction and
each run reproducible.

### Sensor stack (what makes it measurement, not just firing)

Instrument the twin so effect and detection are observable:

- **Host telemetry** — process/file/registry/syscall auditing (auditd / Sysmon-equivalent
  / an EDR agent under test).
- **Network capture** — full pcap inside the isolation boundary.
- **Detection rules under test** — the SIEM/EDR ruleset whose coverage is being measured
  (the whole point of signal #1). Sourcing is an open item (§10).

### Deception network (contained egress)

Default air-gap. Where a payload must "phone home" to exhibit behavior, egress is served
**inside the boundary** by a deception network — never real egress (real outbound = error,
§6.1 invariant 1). Fidelity is a per-run parameter with tiers:

- **T0 sinkhole** — DNS + catch-all TCP/HTTP responder. Cheapest; enough to observe
  connection attempts.
- **T1 simulated services** — INetSim/FakeNet-style fake DNS/HTTP/SMTP/C2 that respond
  plausibly, eliciting more payload behavior.
- **T2 simulated internet** — richer fake topology for multi-stage payloads.

Higher fidelity elicits more behavior (better signal) at more build/maintenance cost;
pick the minimum tier that makes the target payload's behavior observable.

### Marker injection

Every synthetic action and every emitted artifact carries the HMAC-signed marker (§6.1
invariant 4). Injection points: the payload's actions, the twin's telemetry, and the IOCs
recorded — so chamber telemetry is unambiguously attributable and can never be confused
with a real incident, nor a real intruder hide behind the sim.

---

## 6. Safety invariants (stage enforcement of §6.1)

All enforced in code; violation is an error the code raises, not an operator judgment:

1. **microVM/VM isolation** — one disposable guest per detonation.
2. **Network containment** — air-gap default; deception-net egress only; real outbound is
   an error.
3. **Snapshot + guaranteed teardown** — clean boot, destroyed on any exit, never reused.
4. **Dry-run-first** — live-fire only as a scoped promotion from a passing dry-run.
5. **Signed markers** — on every synthetic action and artifact.
6. **Kill switch** — halts arm/detonate, forces disarm + teardown, store defaults closed
   (`munitions-custody-policy.md` §9).

Arming is custody-governed (`munitions-custody-policy.md` §6–7): armorer-authorized, bound
to this single scoped run, auto-disarmed on run end. The harness never self-authorizes a
detonation.

---

## 7. Governance

- **Red-tier, default-deny.** Detonation runs only on explicit scoped authorization
  (`DESIGN.md` §6). No detonation is an agent's unilateral action.
- **Third-party munitions, pre-disclosure.** A third-party exploit *may* be detonated —
  but only against the **in-box twin, for detection/effect research**, embargo unchanged,
  weapon never leaving the store (`disclosure-policy.md` rule 2). Detonating a working
  pre-disclosure 0-day is sensitive even in-box, so it is **gated and minimized**: permit
  it when the purpose is defensive (measuring whether the technique is detectable), keep
  the results defensive, and do not treat "we can detonate it" as license to hold it armed.
  Flagged for explicit sign-off (§10).
- **Purpose binding.** Detonation output feeds detection-coverage and containment research.
  It is not a deployment step and produces nothing that leaves the box except a report.

---

## 8. Measurement (the *observe* stage plugs in here)

A detonation report carries five things:

- **Effect** — did the objective marker fire (from `develop-stage.md`), plus system-context
  effect (persistence, service impact).
- **Blast radius** — how far the payload reached in the twin. With a multi-host twin this
  quantifies lateral movement as a measured variable. (One downstream *application*: feeding
  it into lateral-movement models such as the lab's `agentic-identity-pivots` /
  `polymorphic-attack-chains` — an optional consumer of the output, not part of this stage.)
- **IOCs emitted** — the observable artifacts (file/process/network), signed-marked. Feeds
  detection research directly.
- **Detection outcome** — did the sensor stack / rules under test fire? This is the
  **detection-gap** result. (One downstream *application*: fitting per-technique detection
  posteriors, e.g. the lab's `detection-posteriors` work, treats each detonation as an
  empirical firing — again a consumer of the output, not a coupling in the harness.)
- **Containment-integrity verdict** — did every §6 invariant hold? A pass is the
  containment result; a violation is a finding about the plane itself, which is *also* a
  research output, not just an incident.

Reported as a range across repeated detonations (multi-run discipline); non-determinism in
payload behavior and detection is itself a measured quantity.

---

## 9. Build-first slice (acceptance test)

Detonate is the **last** stage to build — highest risk, needs the full chamber — so it is
**not** part of the week-one spike. Its build-first slice is as much a *containment*
acceptance test as a capability one:

- **Input:** the `develop-stage.md` build-first output — the L4 ret2win exploit that fires
  the objective marker on the deliberately-vulnerable target.
- **Twin:** minimal — the vulnerable service + one host-telemetry sensor + a T0 deception
  sinkhole, on a microVM.
- **Pass condition (both must hold):**
  1. *Capability/effect:* the detonation fires the objective marker **and** the
     marker-aware telemetry captures it (effect is observed, not just achieved).
  2. *Containment:* every §6 invariant verifiably holds — isolation, no real egress
     (assert zero real outbound), dry-run-preceded-live-fire, guaranteed teardown
     (assert the guest is destroyed even if the run is killed mid-detonation).
- **Then add a detection rule** and re-run to produce the first **detection-gap** data
  point (did the rule fire on the emitted IOCs?).

**Early-exit signal:** if teardown is not provably guaranteed under a mid-detonation kill,
stop and fix containment before any further detonation work — teardown is the invariant the
whole stage rests on.

---

## 10. Open items (feed back to `DESIGN.md` §9)

- **Deception-network fidelity default** — this spec defines tiers T0–T2 (§5); which tier
  is the default, and per-run override policy. (Resolves the standing §9 fidelity item into
  a concrete tier model.)
- **Sensor stack composition** — synthetic telemetry vs. a real EDR agent under test; which
  host-audit sources are standard.
- **Detection-rule sourcing** — whose ruleset is under test in signal #1 (the point of the
  detection-gap measurement); how rules are supplied per run.
- **Twin richness** — single-host vs. multi-host twins, and how much topology is needed to
  make blast-radius / lateral-movement measurement meaningful (ties to
  `agentic-identity-pivots`).
- **Third-party pre-disclosure detonation** — the §7 gate: explicit sign-off criteria for
  detonating a working exploit against third-party software before the disclosure case
  closes.
