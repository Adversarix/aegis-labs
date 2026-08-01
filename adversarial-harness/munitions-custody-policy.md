# Munitions Chain-of-Custody Policy

**Status:** Draft v0.1 · **Date:** 2026-08-01 · Parent: [`DESIGN.md`](./DESIGN.md) §6.1
Related: [`disclosure-policy.md`](./disclosure-policy.md) · [`discovery-stage.md`](./discovery-stage.md) §6

Governs every artifact in the **munitions store** — the defanged, encrypted-at-rest
repository of exploit material the harness holds. Resolves the munitions chain-of-custody
item in `DESIGN.md` §9. Its job is to make every munition **accountable from creation to
destruction**: who made it, where it came from, everything done to it, and that it was
disposed of when done.

The store is a **high-value asset**. A general-purpose harness pointed at real software
accumulates weaponizable artifacts — including embargoed third-party 0-days
(`disclosure-policy.md`) and off-target real bugs (`discovery-stage.md` §6). Custody is
what keeps that from becoming an ungoverned arsenal.

---

## 1. Principles

1. **Inert by default.** Munitions rest **defanged and unarmed** (`armed = false`).
   Arming is a transient state that exists only inside the detonation chamber
   (`DESIGN.md` §6.1) and reverts on run end. Nothing is armed at rest.
2. **Every touch is logged.** Create, read, arm, detonate, export, dispose — each is a
   signed, append-only **custody event** (§4). No unlogged access to any munition.
3. **No silent egress.** Nothing leaves the store except through an authorized, logged
   transaction. The only external egress path is coordinated disclosure of a *minimal
   reproducer* — the **armed weapon never leaves** (`disclosure-policy.md` rule 2).
4. **Least privilege, need-to-use.** Access is scoped to a specific authorized run and
   role, not standing. Default-deny (`DESIGN.md` §6).
5. **Minimize the standing arsenal.** Prefer retaining the **inert reproducer +
   provenance** and destroying armed forms. Do not stockpile weaponized exploits; dispose
   on disposition. A smaller store is a smaller liability.
6. **Guaranteed disposal.** Destruction is real (crypto-shred + ephemeral-guest
   teardown), verified, and logged. "Deleted" means unrecoverable.

---

## 2. Scope — what is under custody

Every store object, regardless of origin:

- **Discovery-produced** proto-munitions — crashing input + build recipe, inert
  (`discovery-stage.md` §6).
- **Supplied** munitions — real payloads provided under authorization for detonation
  research (`DESIGN.md` §6.1).
- **Armed** munitions — the transient in-chamber form of either of the above.
- Associated crash artifacts, reproducers, and trigger metadata.

Out of scope: disclosure reports and minimal reproducers *after* they leave for a vendor
— those are governed by `disclosure-policy.md`. Custody governs what stays in the store.

---

## 3. The custody record

Each munition is one record: the artifact (encrypted) plus immutable identity and a
mutable state, wrapped by an append-only event ledger (§4).

```
Munition {
  id                     # stable, store-assigned
  artifact_ref           # encrypted blob: reproducer input + recipe (+ payload if supplied)
  origin                 # discovered | supplied
  provenance             # {finding_id | supply_authorization, trajectory_ref, tools_used}
  ownership              # owned | third_party            (drives disclosure interplay §7)
  target_match           # true | false | n/a             (on/off-target, discovery §6)
  disclosure_status      # embargoed | disclosed | published | n/a   (disclosure-policy)
  custody_state          # §5 state machine
  armed                  # false at rest, ALWAYS
  retention              # {class, expires_at}
  ledger[]               # append-only custody events §4
}
```

`ownership`, `target_match`, and `disclosure_status` are the tags the last three
decisions added; custody is where they gain teeth.

---

## 4. The custody ledger (the "chain")

Per-munition, **append-only, signed, hash-chained** (each event references the prior
event's hash, so gaps or edits are detectable). Uses the §6 HMAC signed markers.

Each event records: **actor** (human or system identity), **action**, **timestamp**,
**run_id** (if any), **authorization reference**, and **reason**.

```
event actions:
  create        munition enters the store (discovery promotion | supply ingest)
  access        record read / metadata queried
  arm           armed for a specific in-chamber run   → requires armorer authz (§6)
  detonate      fired inside the chamber
  disarm        reverted to inert (auto, on run end)
  export        minimal reproducer released to disclosure  → requires disclosure owner (§7)
  dispose       destroyed (crypto-shred) + verified
```

The ledger is the accountability record. It is auditable (§8) and reconcilable against
the store's contents; a munition whose ledger does not close with `disarm`/`dispose`
consistent with its `armed`/`custody_state` is an integrity alarm.

---

## 5. Custody state machine

Distinct from and orthogonal to `disclosure_status` (which tracks the *external* vendor
process). `custody_state` tracks the *internal* lifecycle:

```
  created ──► at_rest ──► armed ──► detonated ──► at_rest ──► disposed
   (inert)   (inert)   (chamber   (chamber)     (inert,      (destroyed,
                        only,                    re-inert)     verified)
                        transient)
                │
                └──► disposed   (from at_rest, on retention expiry / withdrawal)
```

- **created / at_rest** — inert, encrypted, in the store. The resting state.
- **armed** — transient, **chamber-only**, time-boxed to one authorized run; auto-reverts
  (`disarm`) to `at_rest` on run end, kill, or crash. Never persists.
- **detonated** — fired in-chamber; telemetry captured; guest destroyed (`DESIGN.md`
  §6.1); the munition record re-inerts to `at_rest`.
- **disposed** — terminal; artifact crypto-shredded, verified, ledger closed.

`armed` the boolean and `armed` the state are the same fact viewed two ways; the invariant
is **`armed = true` ⟺ `custody_state = armed` ⟺ inside the chamber, mid-run.**

---

## 6. Roles & authorization

| Role | Authorizes |
|---|---|
| **Custodian** | named human, accountable for the store; owns retention/disposal, audits the ledger |
| **Armorer** | authorizes each `arm` — for a specific, scoped, isolated run only (may be same person as custodian) |
| **Disclosure owner** | authorizes each `export` (minimal reproducer to a vendor) per `disclosure-policy.md` |
| **Harness** | creates, tracks, tags, enforces embargo — **never self-authorizes `arm`, `export`, or `dispose`** |

The harness cannot arm, export, or destroy its own munitions on its own authority. A
human is in the loop at every irreversible or outward-facing custody event — the same
principle as the disclosure policy, applied to the store.

---

## 7. Access, arming, and egress controls

- **Access** is scoped to an authorized run and role; no standing read access to armed
  material. Embargoed third-party munitions are readable/usable **only for in-box research
  against the discovered copy** (`disclosure-policy.md` §8).
- **Arming** happens only via an `arm` event: armorer-authorized, bound to one scoped run,
  dry-run-first (`DESIGN.md` §6.1), time-boxed, auto-disarmed on run end. Arming against
  anything outside the run's isolated target is denied by the mediation plane (`DESIGN.md`
  §6) — custody and mediation enforce the same boundary from two sides.
- **Egress** — the only path out of the store is `export` of a **minimal reproducer** for
  coordinated disclosure, disclosure-owner-authorized. **Armed munitions are
  non-exportable, unconditionally** — no run, disclosure state, or authorization unlocks
  the weapon for release. `disclosed`/`published` changes what is *publicly known*, never
  what *leaves the store*.

---

## 8. Retention & disposal

- **Retention classes** (retain the *minimum* consistent with the research purpose):
  - *owned / benign* — retain for the study; dispose on study close.
  - *off-target discovered* — retain the inert reproducer + provenance (it is a real
    result); reassess at a default retention horizon.
  - *third-party embargoed* — retain while the disclosure case is open; on `disclosed`,
    retain the reproducer for the record and **dispose of any armed form**.
- **Disposal is verified destruction:** crypto-shred the artifact, tear down any ephemeral
  guest, write a `dispose` event with verification. Recoverability after `dispose` is an
  incident.
- **Bias to disposal:** per Principle 5, when a munition's research purpose is served,
  destroy the armed form and keep at most the inert reproducer. The default is *destroy*,
  not *keep*.

---

## 9. Integrity, audit & incident handling

- **Tamper-evidence:** the hash-chained signed ledger makes edits/gaps detectable;
  periodic audit reconciles ledger ↔ store contents.
- **Reconciliation alarms:** any munition `armed` outside a live run, present without a
  `create` event, or missing after `dispose` raises an integrity alarm.
- **Containment binding:** a kill (`DESIGN.md` §6.1 kill switch) halts all `arm`/
  `detonate`, forces `disarm`, and the store defaults closed.
- **Loss/leak incident:** a suspected store compromise is treated as a security incident —
  scope via the ledger (what was accessible), and for any third-party embargoed munition
  potentially exposed, expedite the disclosure case (`disclosure-policy.md` §6 active-
  exploitation exception applies if exposure is confirmed).

---

## 10. Residual items

- **Key-custody model** — where the at-rest encryption keys live, and whether arming
  requires a separate key ceremony (armorer-held key) so the harness alone cannot decrypt
  to an armed form.
- **Retention horizons** — concrete durations per class; the off-target retention horizon
  in particular (a general-purpose harness will generate many).
- **Cross-run reuse** — may a munition discovered in one run be armed in a later,
  differently-scoped run, or is arming authorization single-run by default?
- **Volume governance** — shared with `disclosure-policy.md` §10: severity-gating which
  discovered munitions are retained at all vs. recorded-and-immediately-disposed.
