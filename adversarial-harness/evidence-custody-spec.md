# Evidence Chain-of-Custody Spec

**Status:** Draft v0.1 · **Date:** 2026-11-16 · Parent: [`DESIGN.md`](./DESIGN.md)
Related: [`munitions-custody-policy.md`](./munitions-custody-policy.md) · [`disclosure-policy.md`](./disclosure-policy.md) · [`discovery-stage.md`](./discovery-stage.md) · [`develop-stage.md`](./develop-stage.md) · [`detonate-stage.md`](./detonate-stage.md)

Specifies how the harness binds every **finding** to the immutable **evidence** that
proves it, from the moment an agent observes something through to a disclosure bundle a
human hands a vendor. The munitions policy governs the *weapon*; this governs the
*receipts*. A finding without custody-bound evidence is an unproven claim and MUST be
treated as one.

> **Clean-room provenance.** This is an independent specification written from the
> problem, not from any third-party implementation. Implementers build from THIS
> document and the sibling policies only. Do **not** read, copy, translate, or
> structurally mirror any AGPL-licensed source (ARTEX, `BaaRai/*`, or any fork) while
> building against this spec. All names here are our own. The design goal was shared
> with such a tool; the expression below is not derived from it.

---

## 1. Principles

1. **No finding without proof.** Every `finding` carries at least one **evidence
   binding** to a sealed capture. The planner/operator MUST refuse to promote a claim to
   `finding` state (`discovery-stage.md`) until a binding exists. An LLM assertion is not
   evidence; the captured bytes that justify it are.
2. **Evidence is immutable and content-addressed.** A capture is sealed once, named by
   the hash of its bytes, and never edited. Corrections are new captures, not rewrites.
3. **Quote by reference, never by copy.** A finding's rationale cites a **byte span**
   inside a sealed capture (`capture_id` + offset + length), not a pasted string. The
   quote is re-derived from the sealed bytes on read, so it cannot drift from its source.
4. **The chain is tamper-evident.** Bindings and custody events are append-only, signed,
   and hash-chained with the same signed-marker scheme the munitions ledger uses
   (`munitions-custody-policy.md` §4, §6), so gaps or edits are detectable.
5. **Capture at the seam, not in the agent.** Evidence is recorded by harness-owned
   infrastructure on the request/response and tool-I/O path (`mediation-seam`), never
   self-reported by the model. The agent cannot author its own proof.
6. **The sealed original never egresses.** Raw captures stay inside the isolation
   boundary. Only a scrubbed, minimized **disclosure view** leaves, through the
   disclosure seam, and the weapon is never in it (`disclosure-policy.md` rule 2).
7. **Secrets are masked in views, preserved in the seal.** Redaction is a derived
   projection over immutable bytes, not a mutation of them. The unredacted seal is
   retained under the isolation boundary; redacted views are what humans and exports see.

---

## 2. Scope

**Under custody:** every observation the harness captures that could substantiate a
finding, across all stages:

- HTTP request/response pairs from the recording proxy (`mediation-seam`).
- Tool invocations and their output: argv, exit status, stdout/stderr, duration.
- Network captures (pcap), screenshots, DOM snapshots, and file artifacts pulled from a
  target copy.
- Agent reasoning transcripts **as context**, tagged non-probative (see §3, `weight`).

**Not under this spec:** the weaponized exploit itself (that is a munition,
`munitions-custody-policy.md`), and disclosure artifacts *after* they leave for a vendor
(`disclosure-policy.md`). Evidence custody governs proof-of-finding inside the boundary
and the manifest that accompanies a disclosure, not the weapon and not post-egress state.

---

## 3. The evidence model

Three record types plus a ledger. All identifiers are store-assigned except
`capture_id`, which is the content hash.

### 3.1 Capture — the sealed observation

```
Capture {
  capture_id        # = hash(bytes)  — content address, stable, immutable
  bytes_ref         # encrypted-at-rest blob; the exact observed bytes, sealed once
  media_type        # http_exchange | tool_io | pcap | screenshot | dom | file
  captured_at       # seal timestamp
  captured_by       # seam identity that recorded it (NOT the agent)
  run_id            # authorized run this belongs to
  source_meta       # {target_ref, host, tool_name, argv_hash, ...}  (typed per media_type)
  size_bytes
  seal_sig          # signed marker over (capture_id, captured_at, run_id)
}
```

A capture is write-once. Re-observing the same bytes yields the same `capture_id`
(dedup). The blob is encrypted at rest like munitions; the index row is not secret.

### 3.2 Finding — the claim (owned by the stage docs, referenced here)

The finding record is defined by `discovery-stage.md`. This spec adds one hard
invariant: a finding in `confirmed` state MUST have `len(evidence_bindings) >= 1`. The
fields this spec relies on:

```
Finding {
  id
  state             # candidate | confirmed_vuln | rejected   (discovery-stage)
  ownership         # owned | third_party                     (drives disclosure)
  trajectory_ref    # the run trajectory that produced it
  evidence_bindings[]   # §3.3, append-only
  ...                   # (rest owned by discovery-stage.md)
}
```

### 3.3 EvidenceBinding — the proof link

The core object this spec introduces. One per piece of proof.

```
EvidenceBinding {
  binding_id
  finding_id
  capture_id            # the sealed capture that proves it
  span                  # optional {offset, length} — the exact bytes cited
  role                  # trigger | response | side_effect | precondition | retest
  weight                # probative | corroborating | context
  claim                 # one-line statement this span supports
  asserted_by           # agent/system identity that drew the inference
  created_at
  prev_hash             # hash-chain link (§4)
  sig                   # signed marker over the whole binding
}
```

`weight = context` is for agent-reasoning transcripts and anything non-probative; those
MAY be bound for traceability but MUST NOT be the sole support for a `confirmed_vuln`. At
least one `probative` binding is required to confirm.

---

## 4. The custody chain

Per finding, an **append-only, signed, hash-chained** sequence of custody events, reusing
the munitions ledger's signed-marker primitive so there is one chain implementation, not
two. Each event references the prior event's hash; a missing or altered event breaks the
chain and fails verification.

```
event actions:
  capture_sealed      # a Capture was recorded and sealed
  bound               # an EvidenceBinding was created
  retested            # finding re-proven; new capture + binding, same finding_id
  superseded          # a binding marked stale by a later one (not deleted)
  view_derived        # a redacted/minimized projection was generated (§6)
  exported            # a disclosure bundle left the boundary (§7)
  disposed            # captures crypto-shredded on retention expiry (§8)
```

Each event records **actor**, **action**, **timestamp**, **run_id**, **authorization
reference**, and **reason**, identical in shape to `munitions-custody-policy.md` §4.
Verification walks the chain and recomputes every `capture_id` from its bytes; a finding
whose chain or content hashes do not verify is reported as **custody-broken** and is
ineligible for disclosure.

---

## 5. Capture pipeline

Capture is a function of the seam, invoked on four event sources, in order of trust:

1. **HTTP path.** The recording proxy on the `mediation-seam` tees every
   request/response for in-scope targets into a `http_exchange` capture. Scope and deny
   rules decide what is recorded; out-of-scope traffic is dropped, not sealed.
2. **Tool I/O.** The tool runner wraps each invocation and seals a `tool_io` capture
   (argv, exit, stdout, stderr, timing). The agent sees tool output *after* it is sealed,
   so what the agent reasons over is already under custody.
3. **Artifacts.** Screenshots, DOM snapshots, pcap, and pulled files are sealed as their
   respective media types with `source_meta` tying them to the originating tool call.
4. **Reasoning.** The agent transcript is sealed as `context`-weight capture for
   traceability only.

Sealing is: `bytes -> encrypt-at-rest -> capture_id = hash(plaintext bytes) -> index row
+ seal_sig -> emit capture_sealed event`. Hash is over plaintext so dedup and span-quoting
work; encryption protects the blob at rest. The seam, not the model, holds the signing key.

**Ordering guarantee:** a binding can only reference a `capture_id` whose
`capture_sealed` event already exists. Binding to an unsealed or unknown capture is
rejected. This is what prevents a model from "proving" a finding against bytes that were
never actually observed.

---

## 6. Redaction and derived views

Humans, the UI, and exports never read raw seals directly; they read **views**.

- A **view** is a deterministic projection over one or more captures: span extraction,
  secret masking, and size minimization. It is itself content-addressed and logged with a
  `view_derived` event referencing its source `capture_id`s.
- **Masking** runs a secret scrubber (credentials, tokens, session cookies, PII,
  customer data) over the projected bytes. The masker is conservative: when unsure, it
  masks. Masking failures fail closed (the view is not produced), never open.
- The **unredacted seal is never mutated and never exported.** If a reviewer needs the
  raw bytes, they read them inside the boundary under a logged `view_derived` with
  `role = raw`, which requires the munitions/evidence reviewer role, not standing access.

This mirrors `munitions-custody-policy.md` principle 3 (no silent egress): the only bytes
that cross the boundary are a minimized, masked view, produced through a logged transaction.

---

## 7. Disclosure bundle

When a `third_party` finding advances toward disclosure (`disclosure-policy.md` §4, human
authorized), the harness assembles an **evidence bundle**:

```
EvidenceBundle {
  finding_id
  minimal_reproducer      # from disclosure-policy — the smallest trigger, NOT the weapon
  proof_views[]           # masked views of the probative captures only
  custody_manifest        # the finding's chain (§4): capture_ids, hashes, timestamps,
                          #   actors — enough for a vendor to verify integrity
  attestation            # signed statement: these views project these sealed captures,
                          #   recorded by the seam at these times, chain verified
  excludes               # explicit: weapon/munition NOT included (disclosure rule 2)
}
```

The bundle carries **probative and corroborating** bindings only; `context`-weight
reasoning is dropped. The custody manifest lets the vendor confirm the proof is intact
without the harness handing over raw internal captures. Assembly is the only path by which
anything evidence-derived leaves the boundary, it emits an `exported` custody event, and a
named human disclosure owner authorizes it (`disclosure-policy.md` rule 1). The autonomous
agent never assembles or sends a bundle on its own.

---

## 8. Retention and disposal

- **Retention class** is set per capture at seal time (default: tied to the finding's
  lifecycle; longer for `confirmed_vuln`, short for captures bound only to rejected
  claims).
- **Disposal** is crypto-shred of the blob plus an index tombstone, logged as `disposed`.
  The custody manifest (hashes, timestamps, actors) MAY be retained after the bytes are
  destroyed, so the record that a finding *was* proven survives even when the proving
  bytes are gone. "Disposed" means the bytes are unrecoverable, consistent with
  `munitions-custody-policy.md` principle 6.

---

## 9. Threat model — what this defends against

1. **Hallucinated findings.** A model claims a vuln it never actually triggered. Defense:
   §1.1 + §5 ordering — no binding without a seam-recorded capture, no confirm without a
   probative binding.
2. **Evidence tampering.** Someone edits a capture to strengthen or fabricate proof.
   Defense: content addressing + hash-chained ledger (§3.1, §4); verification recomputes
   hashes and fails closed.
3. **Quote drift.** A pasted rationale diverges from what was observed. Defense:
   quote-by-reference (§1.3); the quote is re-derived from sealed bytes.
4. **Weapon/evidence confusion on export.** The munition leaks inside a proof bundle.
   Defense: §7 `excludes` + disclosure rule 2; bundles carry views of probative captures,
   never munition blobs.
5. **Secret leakage.** Credentials or customer data in captured traffic egress in a
   bundle. Defense: §6 conservative masking, fail-closed, seal-never-exported.
6. **Replay/scope laundering.** Proof recorded against an out-of-scope or unauthorized
   target. Defense: §5.1 scope gate at capture; `run_id` + authorization reference on
   every capture and event.

---

## 10. API surface (internal)

Minimal, seam-side. Names are ours.

```
seal(bytes, media_type, source_meta, run_id) -> capture_id      # idempotent on bytes
bind(finding_id, capture_id, span?, role, weight, claim) -> binding_id
retest(finding_id, run_id) -> {capture_id, binding_id}          # re-prove, same finding
derive_view(capture_ids, projection, mask=true) -> view_id       # logged, masked
verify_custody(finding_id) -> {ok, broken_at?}                   # recompute chain+hashes
assemble_bundle(finding_id, authorized_by) -> EvidenceBundle     # human-authorized only
dispose(capture_id, reason, authorized_by) -> tombstone          # crypto-shred, logged
```

`seal`, `bind`, and `verify_custody` are the load-bearing three; everything else composes
them. All writes emit a §4 custody event.

---

## 11. Acceptance criteria

A conformant implementation MUST:

1. Reject promotion of a finding to `confirmed_vuln` with zero `probative` bindings.
2. Produce identical `capture_id` for identical bytes (dedup) and refuse to bind to an
   unsealed `capture_id`.
3. Detect, via `verify_custody`, any post-hoc edit to a capture blob or any gap/reorder in
   the custody chain, and mark the finding custody-broken.
4. Re-derive a cited span from sealed bytes on read (no stored free-text copy of the quote).
5. Never emit raw sealed bytes through `assemble_bundle`; every exported byte passes through
   a masked, logged view, and no munition blob is included.
6. Fail closed on masking error (no view produced) rather than export unmasked bytes.
7. Retain a verifiable custody manifest after `dispose` destroys the underlying bytes.
8. Record every `seal`/`bind`/`retest`/`derive_view`/`export`/`dispose` as a signed,
   hash-chained custody event with actor, run_id, authorization, and reason.

A test fixture SHOULD cover each of the §9 threats with a red case (attempt) and a green
case (expected rejection or detection).

---

## 12. Build notes

- **Reuse, don't re-invent.** The signed-marker + hash-chain primitive already exists for
  the munitions ledger (`munitions-custody-policy.md` §6). Factor it into one shared
  module consumed by both the munitions store (`src/munitions-store`) and evidence custody;
  do not fork a second chain implementation.
- **Home.** Evidence custody is a cross-stage concern; it is produced at discovery and
  develop, verified before detonate promotion, and consumed by disclosure. Suggested home:
  a `src/evidence-store` sibling to `src/munitions-store`, with the bundle assembler living
  behind the `src/disclosure` seam.
- **Content hash + signing are independent of ARTEX.** The design above is standard
  content-addressing and append-only ledgering. Implement it from this spec and the sibling
  policies; nothing here requires reading external AGPL source.
