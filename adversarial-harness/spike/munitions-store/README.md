# Munitions store + discovery→develop handoff

A filesystem-backed implementation of the munitions custody policy
([`../../munitions-custody-policy.md`](../../munitions-custody-policy.md)), green tier, plus the
discovery→develop handoff it enables (`discovery-stage.md` §6 → `develop-stage.md` §1). Pure Node
builtins, so it is importable by both seams and unit-testable with no dependencies.

## What the store enforces, in code

- **Inert by default.** `armed` is `false` at rest, always. Arming exists only inside the
  detonation chamber, which is red-tier and unavailable here, so `arm`/`detonate` are refused with
  a clear reason (`CHAMBER_UNAVAILABLE`) even when handed a human token.
- **Every touch logged.** `create` / `access` / `update` / `dispose` append to a per-munition,
  append-only, **HMAC-signed, hash-chained** ledger. Any edit or gap breaks the chain and
  `verify()` reports exactly where.
- **Encrypted at rest.** The artifact (reproducer input + recipe + crash report) is AES-256-GCM
  encrypted. Disposal **crypto-shreds** the ciphertext, so "disposed" is unrecoverable.
- **The harness never self-authorizes arm / export / dispose.** Those demand an explicit human
  `authorization` object `{role, actor}`; the harness cannot fabricate one. `create` / `access` /
  `update` are harness-authorized. (And those three are the only custody ops exposed to the agent
  as tools; arm/export/dispose live only on the store's human/custodian path.)

## API

```js
import { openStore } from "./store.js";
const store = openStore(dir, { key });        // key: AEGIS_STORE_KEY or a passphrase
store.create({ artifact, provenance, ... });  // discovery promotes a crash -> inert munition
store.open(id);                               // develop ingests: decrypts artifact, logs access
store.update(id, { level, primitives, ... }); // develop records ladder progress
store.list();                                 // summaries
store.dispose(id, { authorization });         // human-gated crypto-shred, terminal
store.arm(id, { authorization });             // refused at green tier (chamber unavailable)
store.verify(id);                             // hash-chain + signature + state reconciliation
```

## The handoff (how the two stages connect)

Discovery and develop are separate MCP seams; the store is the shared through-line. Both open the
same store via `AEGIS_STORE` (dir) + `AEGIS_STORE_KEY`.

- **Discovery seam** (`../mediation-seam`) exposes `promote_finding` — turns a confirmed crash into
  an inert munition (`custody_state = at_rest`, `exploitation_level = crash`).
- **Develop seam** (`../develop-seam`) exposes `ingest_munition` (decrypts the reproducer, logs an
  access), `record_progress` (writes the ladder level / primitives / reliability back), and
  `list_munitions`.

Every custody tool still crosses the enforcing mediation gate (green, signed marker). So each
munition ends up with **two** records for two purposes: the mediation log (the agent called the
tool) and the custody ledger (what happened to the munition).

## Tests

```bash
node store.test.mjs                 # 20 unit tests: lifecycle, encryption, authz, tamper, shred
node ../develop-seam/handoff-test.mjs   # end-to-end through both seams against a shared store
```

Observed handoff, through the real seams:

```
discovery: promote_finding  -> munition at_rest, level=crash        (ledger: create)
develop:   ingest_munition  -> decrypted reproducer + recipe        (ledger: create,access)
develop:   record_progress  -> level=exploit, reliability=1.0       (ledger: create,access,update)
verify: ok
```

## Deferred (red tier / future)

`arm` / `detonate` / `export` and the full disclosure interplay attach to the detonation chamber
and the coordinated-disclosure workflow (`disclosure-policy.md`), neither of which exists yet. The
store already models their states and refuses them safely; wiring the chamber and a human
custodian CLI is the next step when red tier lands.
