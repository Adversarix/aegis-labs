# Operator Research Loop — Walking-Skeleton Findings

**Status:** the operator cockpit runs end to end on a REAL third-party target — contained, seam-mediated (increment 2), with real coordinated disclosure (increment 3) · **Date:** 2026-08-03
Spec of: [`../../DESIGN.md`](./../../DESIGN.md) §1 (autonomous adversarial research), §2 (third-party in scope), §5.1 (discovery)

## Why this exists

The harness had drifted toward its *eval* face (benchmark models against fixed tasks). This is the first
build of its *operator* face: point it at a **real target** and DO the research — find a real bug, take
custody, characterize it, draft disclosure — where the output is a finding, not a leaderboard. This is
what `DESIGN.md` §1/§2/§5.1 actually lead with.

## What ran

A single real target driven through the whole loop, thin, on the native aarch64 sandbox (no x86_64 host
needed):

- **Target:** `stb_image` 2.19 (`github.com/nothings/stb`, pinned commit `f54acd4e…`), MIT/public-domain
  (permissive-deps-only). A real, widely-embedded single-header image decoder.
- **Ingest:** the target is fetched and built with `clang -fsanitize=fuzzer,address` inside the sandbox
  image (`Dockerfile`). Build has network; runs do not.
- **Hunt:** coverage-guided libFuzzer + AddressSanitizer in a `--network none` container. It found a real
  defect in seconds-to-90s and libFuzzer wrote a reproducer artifact.
- **Confirm:** the reproducer replays deterministically to the same finding.
- **Custody:** the crashing input is promoted to a real munition in the store (encrypted at rest,
  append-only signed ledger), `ownership=third-party`, `disclosure_status=embargoed`. Ledger `verify()`
  returns ok.
- **Characterize:** the crash is classified and recorded onto the munition — honestly.
- **Disclose:** a coordinated-disclosure DRAFT advisory is emitted (a STUB, see limits).

Actual end-to-end run:

```
[hunt]         FOUND a out-of-memory: oom-185bcbb1643150de…
[confirm]      reproduced deterministically
[custody]      promoted to munition d352f940-… (ownership=third-party, disclosure=embargoed)
[characterize] uncontrolled-resource-consumption (CWE-789) in stb_image decode path — low (DoS); weaponizable=false
[custody]      ledger verify: ok=true events=2
[disclose]     wrote DRAFT advisory (STUB)
=== loop complete: real bug in real code, contained, in custody, disclosure drafted ===
```

## The finding (and honest severity)

The hunt reliably surfaces an **uncontrolled memory allocation (CWE-789)**: a crafted image header
declares enormous dimensions and stb allocates `width*height*channels` before validating, exhausting
memory. It is a real, reproducible, DoS-class defect. The loop **characterizes it honestly as
non-weaponizable** (`weaponizable=false`, `low (DoS)`) rather than dressing it up as memory corruption —
exactly the not-over-claiming discipline the harness exists to enforce (the CRUCIBLE-confabulation
lesson, applied to our own output).

During tuning we also observed, on the same target, a reachable assertion-abort in `stbi__bmp_load` and,
with a dimension guard, deeper decode paths. A clean heap-buffer-overflow was not reached within the
hunt budget on this hardened-ish version; the loop is finding-agnostic and will classify whatever it
finds (`classify()` handles OOM / buffer-overflow / reachable-crash).

## Increment 2 (done): seam-mediated

The loop now runs through `operator/seam.js`, an MCP seam mirroring the develop/discovery seams:
`hunt` / `reproduce` / `triage` / `promote_finding` each cross the enforcing `mediate()` gate
(default-deny, tier, target-isolation, signed markers, kill-gate; reusing `policy.js` + `marker.js`)
and land in `MEDIATION_LOG`. `operator.mjs` is now an MCP **client** driving the seam (like the
ExploitGym adapter drives the develop-seam), so an agent (Goose) could drive the same seam identically.
A live run logged all four ops as allowed with signed markers:

```
seq 1: hunt             allow  marker=yes  actor=operator
seq 2: reproduce        allow  marker=yes  actor=operator
seq 3: triage           allow  marker=yes  actor=operator
seq 4: promote_finding  allow  marker=yes  actor=operator
```

The mediation unit tests confirm the run scope default-denies `run_shell`, out-of-scope develop tools,
and unknown tools, and that the kill-gate overrides an otherwise-allowed op.

## Increment 3 (done): real coordinated disclosure

The disclosure stub is replaced by the real §6.2 workflow ([`../disclosure/`](./../disclosure)). The
loop opens an **embargoed** case, assembles the vendor package + advisory (metadata + a
minimal-reproducer *description*, never the reproducer bytes), and then **stops** — reporting requires a
human disclosure owner. Live run:

```
[disclose] case ba2c10b6-… opened EMBARGOED; vendor package + advisory prepared (no weapon, rule 2)
[disclose] self-report refused=true -> awaiting a human disclosure owner (rule 1); ledger {ok:true,...}
```

Both §6.2 rules are enforced in code and demonstrated: **the harness finds, a human discloses** (the
autonomous loop cannot self-report — `OWNER_REQUIRED`), and **disclose the vuln, never the weapon** (the
generated package/advisory carry the CWE and root cause but no reproducer bytes; `assertNoWeapon` +
`verify` guard it). 19 disclosure unit tests cover both rules, the state machine, the 90-day embargo
clock, the n-day fast path, and ledger integrity.

## Honest scope (remaining)

- **Discovery is a single fuzz tool.** No crash triage/dedup/minimization, no static analysis / RE
  (`DESIGN.md` §5.1). One reproducer, one munition.
- **DoS-class finding.** A memory-corruption target would exercise the develop/weaponize stage more
  fully; the loop supports it (`classify()` grades an OOB as weaponizable), this target/version just did
  not yield one quickly.
- **Store-perms binding to `disclosure_status`** (policy §8: embargoed gates arm/export) is the disclosure
  workflow's next tie-in.

## What it proves

The operator cockpit is real, not a diagram: a real third-party library, a real fuzzer-found defect, a
real reproducer, real signed custody, an honest characterization, all inside the containment boundary,
end to end. It also makes the two remaining stubs concrete and measurable: **seam-mediated discovery**
and the **disclosure workflow** are the next increments.

## Reproduce

```bash
( cd operator && npm install )                                   # MCP SDK for the seam + client
( cd operator && docker build -t aegis-operator-stb:latest . )   # ingest + build the real target
( cd operator && node operator.mjs --seconds 90 )                # run the seam-mediated loop
( cd operator && node operator.test.mjs )                        # 20 tests: classifier + seam mediation (no docker)
```
