# operator — the research cockpit (walking skeleton)

The **operator** face of the harness: point it at a **real target** and DO the research (find a real
bug, take custody, characterize, draft disclosure), rather than score a model against a fixed task.
This is a thin, end-to-end walking skeleton of the loop `DESIGN.md` §1/§2/§5.1 describe.

## The loop

```
ingest  -> hunt -> confirm -> custody -> characterize -> disclose
(image)   (fuzz    (replay)   (store)    (classify)      (draft STUB)
          --net none)
```

Every op is **seam-mediated**: `operator.mjs` is an MCP client that drives `seam.js` (an MCP seam
mirroring the develop/discovery seams), so `hunt` / `reproduce` / `triage` / `promote_finding` each
cross the enforcing `mediate()` gate (default-deny, tier, target-isolation, signed markers, kill-gate)
and land in `MEDIATION_LOG`. An agent (Goose) could drive the same seam.

- **ingest** — a real third-party target (`stb_image`, MIT, pinned commit) fetched and built with
  `clang -fsanitize=fuzzer,address` in the sandbox image (`Dockerfile`). Build has network; runs do not.
- **hunt** — coverage-guided libFuzzer + ASan in a `--network none` container; captures a reproducer.
- **confirm** — deterministic replay of the crashing input.
- **characterize** — classify the crash (class, CWE, weaponizability), honestly (`triage.js`).
- **custody** — promote the reproducer to a real munition (encrypted, signed ledger; `ownership=third-party`,
  `disclosure_status=embargoed`).
- **disclose** — open a real coordinated-disclosure case ([`../disclosure/`](./../disclosure), §6.2):
  embargoed, vendor package + advisory assembled (no weapon), and the autonomous loop stops — reporting
  needs a human disclosure owner.

## Run

```bash
npm install                                       # MCP SDK for the seam + client
docker build -t aegis-operator-stb:latest .       # ingest + build the real target
node operator.mjs --seconds 90                     # run the seam-mediated loop
node operator.test.mjs                             # 20 tests: classifier + seam mediation (no docker)
```

Options: `--seconds <n>` hunt budget, `--out <dir>` run artifacts + store, `--store <dir>`.

## Honest scope (remaining)

Discovery is a single fuzz tool (no triage/dedup/minimization or static/RE). The stb finding is a
DoS-class uncontrolled-allocation (CWE-789), characterized honestly as non-weaponizable. Binding
`disclosure_status` to store arm/export permissions (policy §8) is the disclosure workflow's next tie-in.
See [`FINDINGS-operator-walking-skeleton.md`](./FINDINGS-operator-walking-skeleton.md).
