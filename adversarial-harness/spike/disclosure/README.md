# disclosure — coordinated vulnerability disclosure workflow

Implements the CVD policy ([`../../disclosure-policy.md`](./../../disclosure-policy.md), `DESIGN.md`
§6.2) for third-party finds: the state machine, the embargo clock, and a signed case ledger. It is the
operator cockpit's endgame — how a real bug found in software the org does not own gets handled.

## The two rules, enforced in code

1. **The harness finds; a human discloses.** Every transition out of `embargoed`
   (`report` / `disclose` / `publish` / `withdraw`) requires a disclosure-owner authorization
   `{role:"disclosure_owner", actor}`. The autonomous loop cannot self-authorize any external action —
   it prepares the case and stops (`OWNER_REQUIRED`).
2. **Disclose the vulnerability, never the weapon.** A case carries only vuln metadata (component,
   versions, CWE, root cause, a *minimal-reproducer description*) and a reference to the munition id —
   never the reproducer bytes. `assertNoWeapon()` guards `open()` and every package/advisory, and
   `verify()` re-checks it (`WEAPON_IN_DISCLOSURE`).

## State machine (`disclosure_status`)

```
embargoed ─(owner)→ reported → acknowledged → fix_in_progress → fixed ─(owner)→ disclosed ─(owner)→ published
embargoed ─(owner)→ withdrawn
embargoed ─(n-day, public reference)→ disclosed        (already public: no new embargo)
```

- **Embargo:** default 90 days from `reported`; owner-granted +14d grace once. Disclosure is due on
  `min(vendor fix shipped, embargo elapsed)` (`due()`).
- **Vendor engagement** (`acknowledged` / `fix_in_progress` / `fixed`) is harness-recorded (no owner
  token); only owner *advances* need the token.
- **Ledger:** every transition is an append-only HMAC-signed hash-chained event; `verify()` checks
  integrity and re-asserts no weapon leaked into the case.

## API

```js
const d = openDisclosure(dir, { key });
const c = d.open(munition, { vuln, target });        // third-party + embargoed; vuln is metadata only
d.report(c.id, { authorization: owner, contact });    // owner-gated; starts the 90d clock
d.recordVendor(c.id, "acknowledged");                 // vendor response (no token)
d.due(c.id);                                          // { deadline, elapsed, disclose_now }
d.disclose(c.id, { authorization: owner });           // owner-gated
d.packageForVendor(c.id); d.advisory(c.id);           // metadata only, never the weapon
d.verify(c.id);
```

## Test

```bash
node disclosure.test.mjs   # 19 tests: both rules, state machine, embargo clock, n-day, ledger
```
