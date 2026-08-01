# Coordinated Vulnerability Disclosure Policy

**Status:** Draft v0.1 · **Date:** 2026-08-01 · Parent: [`DESIGN.md`](./DESIGN.md) §6.2

Governs how the harness handles vulnerabilities it discovers in **software the
organization does not own** (`DESIGN.md` §2). Resolves the residual disclosure-policy
item in `DESIGN.md` §9. Grounded in the recognized CVD standards — ISO/IEC 29147
(vulnerability disclosure), ISO/IEC 30111 (vulnerability handling), and the CISA /
CERT-CC coordinated-disclosure guidance.

The harness is a **general-purpose** research instrument that may find real bugs in real
software. Finding is legitimate; the responsibility is in the handling. This policy is
that handling, expressed concretely enough to implement.

---

## 1. Two rules everything else serves

1. **The harness finds; a human discloses.** The autonomous agent MUST NOT conduct
   external disclosure on its own — it never contacts a vendor, opens a public advisory,
   or publishes anything. It *prepares* a disclosure case; a named human **disclosure
   owner** authorizes every external action and every state advance past `embargoed`
   (§4). No autonomous state machine reaches out into the world.
2. **Disclose the vulnerability, never the weapon.** What is disclosed is the
   vulnerability — affected component, versions, root cause, and a *minimal* reproducer
   sufficient for the vendor to confirm and fix. The **weaponized munition** (a reliable,
   armed exploit) is NEVER published or shared externally. It stays inert in the store
   (`DESIGN.md` §6.1) and, for third-party finds, embargoed (§4). Vulnerability
   disclosure ≠ exploit release.

Everything below is machinery in service of these two.

---

## 2. Scope

- **Applies to:** any `confirmed_vuln` with `ownership = third_party` (discovery-stage
  §6) — a real bug in software the org does not own, found against a copy run inside the
  isolation boundary.
- **Does not apply to:** owned/benign targets (`ownership = owned`,
  `disclosure_status = n/a`) — no external party, no disclosure duty.
- **Already-public (n-day):** if the vulnerability is already publicly known (a known
  CVE, public advisory, or upstream-fixed), the disclosure duty is reduced to
  *confirmation and reference* — record the public identifier, skip notification, and the
  munition may advance to `disclosed` without a new embargo. n-day research is not
  re-disclosure.

---

## 3. Roles

| Role | Who | Responsibility |
|---|---|---|
| **Disclosure owner** | named human, accountable | authorizes every external action; owns each case end to end |
| **Harness** | automated | discovers, prepares the case package, tracks state, enforces embargo — never acts externally |
| **Vendor / maintainer** | third party | receives the report, confirms, fixes |
| **Coordinator** | e.g. CERT/CC, a CNA, national CSIRT | engaged for unresponsive vendors, multi-party bugs, or critical-infrastructure/safety cases |

---

## 4. Disclosure lifecycle (the `disclosure_status` state machine)

The store's `disclosure_status` field is this machine. **Every transition out of
`embargoed` requires disclosure-owner authorization.**

```
  discovered
     │  (auto) third-party confirmed_vuln promoted
     ▼
  embargoed ──────────────────────────────────────────► withdrawn
     │  owner authorizes report                    (owner: not a real
     ▼                                              vuln / out of scope)
  reported ──► acknowledged ──► fix_in_progress ──► fixed
     │              │                                  │
     │  (no ack within window → engage coordinator)    │  owner authorizes
     ▼                                                 ▼
  ................................................► disclosed ──► published?
                                                                 (details only,
                                                                  never the weapon)
```

- **embargoed** — default on promotion. Munition usable **only for in-box research
  against the copy**; cannot be armed for anything else, exported, or shared. This is the
  resting state until a human moves it.
- **reported** — owner has sent the case to the vendor (§5). The embargo clock starts here.
- **acknowledged / fix_in_progress / fixed** — vendor engagement states, updated as the
  vendor responds.
- **disclosed** — the vulnerability details are released (to the vendor's users, a CVE
  record, or an advisory). Trigger is **whichever comes first**: vendor fix shipped, or
  the embargo window elapses (§6).
- **published** — optional public write-up (details + minimal reproducer). Owner-gated.
  The armed munition is excluded, always.
- **withdrawn** — owner determines it is not a real/eligible vuln; case closed, munition
  reverts to inert in-box only.

---

## 5. Notification procedure

When the owner authorizes `embargoed → reported`, the harness has already assembled the
package; the owner sends it.

**Finding the contact, in order:** `security.txt` (RFC 9116) → published security/PSIRT
contact → platform advisory channel (e.g. GitHub Security Advisory / private report) →
the relevant CNA → a coordinator (CERT/CC) if none of the above exists.

**Report contents (minimal-sufficient):**
- Affected component and version range; environment to reproduce.
- Root-cause description and bug class (CWE).
- A **minimal reproducer** — the smallest input/steps that demonstrate the flaw. Not the
  weaponized exploit.
- Proposed embargo timeline and this policy's reference.
- A single point of contact (the disclosure owner).

**Channel:** encrypted where the vendor offers it (PGP/security portal). The report is
sent to the vendor only — never posted publicly at this stage.

---

## 6. Timelines

- **Default embargo: 90 days** from `reported`, aligned with prevailing industry practice
  (the Project-Zero-style 90-day norm; more generous than the CERT/CC 45-day default,
  chosen to bias toward giving vendors time to fix).
- **Grace period: +14 days** if the vendor is actively working a fix and requests it near
  deadline. Grace is owner-approved, not automatic, and granted once by default.
- **Clock is transparent:** the vendor is told the deadline at `reported`. Disclosure at
  deadline is expected behavior, not a threat.
- **Disclosure trigger:** `min(vendor fix shipped, embargo elapsed)`. A shipped fix
  discloses early (coordinated with the vendor's release); an elapsed clock discloses
  regardless, per the stated timeline.

### Exceptions (all owner-authorized, all logged)

| Situation | Adjustment |
|---|---|
| **Active exploitation in the wild** | Expedite. Shorten embargo; prioritize a coordinator and, where users are at acute risk, defensive guidance. Protecting users outranks the fix window. |
| **Critical infrastructure / safety-of-life** | More caution, not less. Engage CERT/CC / national CSIRT before acting; extend timelines if a rushed disclosure would endanger. |
| **Vendor unresponsive** | No acknowledgement within a reasonable window (default 30 days) → engage a coordinator (CERT/CC) to manage multi-party or hand off disclosure. Silence does not extend the embargo indefinitely. |
| **Vendor disputes / refuses to fix** | Owner + coordinator decide; disclosure may proceed at deadline with a clear, factual write-up. |
| **Already public (n-day)** | §2 — reference the public identifier; no new embargo. |

---

## 7. What is disclosed vs. what is never disclosed

| Artifact | External disclosure |
|---|---|
| Affected component, versions, bug class, root cause | Yes — to the vendor, then per timeline |
| Minimal reproducer (confirm + fix) | Yes — to the vendor; in a public write-up only after `disclosed` |
| **Weaponized / armed exploit (the munition)** | **Never** — inert and embargoed in the store; not shared, sold, or published |
| Harness internals, other embargoed cases | Never bundled into a disclosure |

The line between a *minimal reproducer* and a *weaponized exploit* is a judgment the
disclosure owner makes per case; when in doubt, disclose less. The purpose is to let the
vendor fix, not to hand anyone a working weapon.

---

## 8. Binding to the munitions store

`disclosure_status` gates what the store permits:

- `embargoed` → arm/use **only** for in-box research against the discovered copy; no
  export, no external sharing, no arming against anything else.
- `withdrawn` → inert, in-box only, closed.
- `disclosed` / `published` → details are public; the **armed munition remains
  non-exportable** regardless (rule 2). Disclosure never unlocks the weapon.
- `n/a` (owned targets) → governed by the ordinary munitions chain-of-custody policy, no
  disclosure overlay.

Every transition is written to the signed audit log (`DESIGN.md` §6 markers): who
authorized it, when, and why. The record is the accountability.

---

## 9. Legal & good-faith posture

- **Analysis of copies in-box** keeps research on the right side of unauthorized-access
  law: the harness runs the third party's *code as a copy it controls*, never touching a
  system it is not authorized to access (`DESIGN.md` §2). This policy assumes that
  invariant holds; it does not authorize live-system testing.
- **Good-faith research:** coordinate, minimize harm, honor vendor safe-harbor terms
  where offered, and never leverage a finding against a live system or for extortion.
- **No exploit trade:** findings are disclosed to fix, not sold, traded, or stockpiled.

---

## 10. Residual items

- **Disclosure-owner authority model** — one named owner vs. a small approving group for
  high-severity or critical-infrastructure cases.
- **Coordinator relationships** — establish a standing CERT/CC / CNA path before the
  first unresponsive-vendor case, not during it.
- **Publication venue & bar** — when (if) the org publishes disclosed findings, and the
  minimal-reproducer bar for public write-ups.
- **Volume** — a general-purpose harness may generate many findings; triage/severity
  gating on *which* confirmed third-party vulns enter the disclosure pipeline (all, or
  above a severity floor) needs a policy of its own.
