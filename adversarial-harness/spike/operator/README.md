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

- **ingest** — a real third-party target (`stb_image`, MIT, pinned commit) fetched and built with
  `clang -fsanitize=fuzzer,address` in the sandbox image (`Dockerfile`). Build has network; runs do not.
- **hunt** — coverage-guided libFuzzer + ASan in a `--network none` container; captures a reproducer.
- **confirm** — deterministic replay of the crashing input.
- **custody** — promote the reproducer to a real munition (encrypted, signed ledger; `ownership=third-party`,
  `disclosure_status=embargoed`).
- **characterize** — classify the crash (class, CWE, weaponizability) onto the munition, honestly.
- **disclose** — emit a coordinated-disclosure DRAFT (a **STUB**: the §6.2 workflow is unbuilt).

## Run

```bash
docker build -t aegis-operator-stb:latest .      # ingest + build the real target
node operator.mjs --seconds 90                    # run the loop (fresh hunt each time)
node operator.test.mjs                            # 12 pure-classifier tests (no docker)
```

Options: `--seconds <n>` hunt budget, `--out <dir>` run artifacts + store, `--store <dir>`.

## Honest scope (increment 1)

Not yet behind the MCP mediation seam (the loop is orchestrated directly here; wiring the fuzz/triage
tools behind the enforcing gate is increment 2). Discovery is a single fuzz tool (no triage/dedup/
minimization or static/RE). Disclosure is a stub. The stb finding is a DoS-class uncontrolled-allocation
(CWE-789), characterized honestly as non-weaponizable. See
[`FINDINGS-operator-walking-skeleton.md`](./FINDINGS-operator-walking-skeleton.md).
