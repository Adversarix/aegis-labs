# evidence-store

Filesystem-backed implementation of the evidence chain-of-custody model
([`evidence-custody-spec.md`](../../evidence-custody-spec.md)), green tier. Binds every
finding to the immutable captures that prove it, so a finding is an accountable claim and
not an assertion. Sibling to [`munitions-store`](../munitions-store/) (which governs the
weapon); both share the signed, hash-chained ledger in [`custody-ledger`](../custody-ledger/).

## What it enforces

- **Content-addressed, immutable captures.** `capture_id = sha256(observed bytes)`;
  sealing the same bytes twice dedups. Bytes rest encrypted (AES-256-GCM).
- **No binding without a sealed capture.** `bind()` to an unknown `capture_id` is refused
  (`BIND_UNSEALED`). This is the ordering guarantee that stops a model "proving" a finding
  against bytes that were never observed (spec §5).
- **Quote by reference.** A binding cites `{offset,length}` into sealed bytes; `quote()`
  re-derives the span on read, never a stored copy (spec §1.3).
- **Tamper-evident chain + content integrity.** `verifyCustody()` recomputes the custody
  ledger and the content hash of every referenced capture, and fails closed.
- **Sealed original never egresses.** `assembleBundle()` emits only masked views of
  probative/corroborating bindings plus a custody manifest; raw bytes, context-weight
  reasoning, and the weapon never leave (spec §6/§7, `disclosure-policy.md` rule 2).
- **Human gates.** `assembleBundle` (exported) and `dispose` require an explicit human
  authorization `{role, actor}`; the harness cannot self-authorize egress or destruction.

## API

```
openEvidenceStore(dir, { key })
  seal(bytes, { media_type, captured_by, run_id, source_meta }) -> { capture_id, deduped }
  bind(finding_id, { capture_id, span?, role, weight, claim }) -> { binding_id, ... }
  retest(finding_id, { capture_id }) -> { binding_id, ... }
  supersede(finding_id, binding_id, { reason })
  hasProbativeBinding(finding_id) -> bool            // the confirm gate (spec §1.1)
  quote(capture_id, span?) -> Buffer                 // re-derived from the seal
  deriveView(finding_id, { capture_id, span?, mask }) -> { view_id, bytes }  // fail-closed
  verifyCustody(finding_id) -> { ok, reason? }
  assembleBundle(finding_id, { authorization, minimal_reproducer }) -> EvidenceBundle
  dispose(capture_id, { authorization, reason }) -> { shredded }
```

## Known limitations (green tier)

- **Secret masking is pattern-based**, not exhaustive. Extend `SECRET_PATTERNS` per
  engagement; it errs toward masking and `deriveView` fails closed on a masker error.
- **Tail truncation of a ledger is not self-detectable** (inherited from
  `custody-ledger`). Anchor the head HMAC and event count externally when this store is
  promoted past green tier.

Run the tests: `node --test src/evidence-store/store.test.mjs`
