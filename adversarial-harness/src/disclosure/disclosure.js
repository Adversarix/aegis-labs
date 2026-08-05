// Coordinated-disclosure workflow — a filesystem-backed implementation of the CVD
// policy (disclosure-policy.md, DESIGN.md §6.2) for third-party finds. Realizes the
// two rules in code:
//
//   1. The harness finds; a HUMAN discloses. Every transition out of `embargoed`
//      (report / disclose / publish / withdraw) requires a disclosure-owner
//      authorization {role:"disclosure_owner", actor}. The autonomous loop cannot
//      self-authorize any external action — it prepares the case and stops.
//   2. Disclose the vulnerability, NEVER the weapon. A case stores only vuln metadata
//      (component, versions, CWE, root cause, a minimal-reproducer DESCRIPTION) and a
//      reference to the munition id — never the reproducer bytes. assertNoWeapon()
//      guards open() and every package/advisory, and verify() re-checks it.
//
// The disclosure_status state machine (policy §4):
//   embargoed -> reported -> acknowledged -> fix_in_progress -> fixed -> disclosed -> published
//   embargoed -> withdrawn ;  embargoed -> disclosed (n-day, with a public reference)
//
// Pure Node builtins; append-only HMAC-signed hash-chained ledger like the store.
import { createHmac, createHash, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const canonical = (o) => JSON.stringify(o, Object.keys(o).sort());
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

// Transitions that are external owner actions (need a disclosure-owner token). Vendor
// engagement states (acknowledged/fix_in_progress/fixed) are harness-recorded, no token.
const NEEDS_OWNER = new Set(["reported", "disclosed", "published", "withdrawn"]);
const VENDOR_STATES = new Set(["acknowledged", "fix_in_progress", "fixed"]);
const DEFAULT_EMBARGO_DAYS = 90;
const DAY_MS = 24 * 60 * 60 * 1000;

// A weapon is the reproducer bytes / an armed exploit. It must never enter a case.
function assertNoWeapon(obj, where) {
  const bad = ["reproducer_input_hex", "reproducer_hex", "artifact_enc", "exploit", "payload_bytes"];
  const scan = (o, path = "") => {
    if (o && typeof o === "object") for (const [k, v] of Object.entries(o)) {
      if (bad.includes(k)) { const e = new Error(`disclosure ${where}: refuses to carry the weapon ('${path}${k}'); disclose the vuln, never the weapon (§6.2 rule 2)`); e.code = "WEAPON_IN_DISCLOSURE"; throw e; }
      scan(v, `${path}${k}.`);
    }
  };
  scan(obj);
}

function requireOwner(action, authorization) {
  if (!NEEDS_OWNER.has(action)) return;
  if (!authorization || authorization.role !== "disclosure_owner" || !authorization.actor) {
    const e = new Error(`'${action}' requires a disclosure-owner authorization {role:"disclosure_owner", actor}; the harness cannot disclose on its own (§6.2 rule 1)`);
    e.code = "OWNER_REQUIRED";
    throw e;
  }
}

export function openDisclosure(dir, opts = {}) {
  const key = createHash("sha256").update(String(opts.key || process.env.AEGIS_DISCLOSURE_KEY || "disclosure-dev-key")).digest();
  const caseDir = join(dir, "cases");
  mkdirSync(caseDir, { recursive: true });
  // Optional binding to the munitions store: keep its disclosure_status (which gates
  // arm/export, policy §8) in sync with the case state. Best-effort — a store hiccup
  // never breaks the disclosure case itself.
  const STORE = opts.store || null;
  const syncStore = (c) => { if (STORE) { try { STORE.set_disclosure_status(c.munition_id, c.state, { reason: `disclosure case ${c.id} -> ${c.state}` }); } catch { /* non-fatal */ } } };
  const path = (id) => join(caseDir, `${id}.json`);
  const load = (id) => { if (!existsSync(path(id))) throw new Error(`no disclosure case ${id}`); return JSON.parse(readFileSync(path(id), "utf8")); };
  const save = (c) => writeFileSync(path(c.id), JSON.stringify(c, null, 2));

  function appendEvent(c, { action, actor = "harness", authorization = null, note = "", extra = {} }) {
    const prev = c.ledger.length ? c.ledger[c.ledger.length - 1].hmac : "GENESIS";
    const body = { seq: c.ledger.length, prev, action, actor,
      authorization_ref: authorization ? sha256(canonical(authorization)) : null, note, ...extra };
    const event_hash = sha256(canonical(body) + prev);
    const hmac = createHmac("sha256", key).update(event_hash).digest("hex");
    c.ledger.push({ ...body, event_hash, hmac });
  }

  function advance(c, toState, { authorization = null, actor = "harness", note = "", extra = {}, now } = {}) {
    requireOwner(toState, authorization);
    c.state = toState;
    appendEvent(c, { action: toState, actor: authorization?.actor || actor, authorization, note, extra });
    save(c);
    syncStore(c);
    return summary(c);
  }

  return {
    // Open a case for a THIRD-PARTY, embargoed munition. `vuln` is metadata only.
    open(munition, { vuln, target, embargo_days = DEFAULT_EMBARGO_DAYS, coordinator = null, public_reference = null } = {}) {
      const own = String(munition.ownership || "").replace("_", "-");
      if (own !== "third-party") throw new Error(`disclosure applies to third-party finds only (got ownership='${munition.ownership}')`);
      if (!vuln || !vuln.cwe || !vuln.class) throw new Error("open requires vuln { class, cwe, root_cause, minimal_reproducer_description }");
      assertNoWeapon(vuln, "open");
      const c = {
        id: randomUUID(), munition_id: munition.id, target: target || null,
        vuln: { class: vuln.class, cwe: vuln.cwe, root_cause: vuln.root_cause || "", minimal_reproducer_description: vuln.minimal_reproducer_description || "" },
        ownership: "third-party", state: public_reference ? "disclosed" : "embargoed",
        public_reference, coordinator,
        embargo: { days: embargo_days, reported_at: null, deadline: null, grace_days: 0 },
        vendor: { contact: null, acknowledged_at: null }, ledger: [],
      };
      appendEvent(c, { action: "open", note: public_reference ? `n-day: public reference ${public_reference}` : "case opened, embargoed" });
      if (public_reference) appendEvent(c, { action: "disclosed", note: "already public (n-day); no new embargo" });
      save(c);
      syncStore(c);
      return summary(c);
    },

    // embargoed -> reported. Owner-authorized. Starts the embargo clock.
    report(id, { authorization, contact = null, now = Date.now() } = {}) {
      const c = load(id);
      if (c.state !== "embargoed") throw new Error(`report requires state 'embargoed' (is '${c.state}')`);
      c.vendor.contact = contact;
      c.embargo.reported_at = now;
      c.embargo.deadline = now + c.embargo.days * DAY_MS;
      return advance(c, "reported", { authorization, note: `reported to ${contact || "vendor"}; embargo ${c.embargo.days}d`, extra: { deadline: c.embargo.deadline } });
    },

    // Vendor engagement recordings (no owner token; informational).
    recordVendor(id, state, { note = "", now = Date.now() } = {}) {
      if (!VENDOR_STATES.has(state)) throw new Error(`not a vendor state: ${state}`);
      const c = load(id);
      if (state === "acknowledged") c.vendor.acknowledged_at = now;
      c.state = state;
      appendEvent(c, { action: state, actor: "harness", note });
      save(c);
      syncStore(c);
      return summary(c);
    },

    // Owner grants the vendor a one-time grace extension.
    grant_grace(id, { authorization, days = 14 } = {}) {
      requireOwner("reported", authorization);   // owner-gated like other advances
      const c = load(id);
      if (c.embargo.grace_days) throw new Error("grace already granted");
      c.embargo.grace_days = days; c.embargo.deadline += days * DAY_MS;
      appendEvent(c, { action: "grace", actor: authorization.actor, authorization, note: `+${days}d grace` });
      save(c);
      return summary(c);
    },

    disclose(id, { authorization, now = Date.now(), reason = "" } = {}) {
      const c = load(id);
      if (!["reported", "acknowledged", "fix_in_progress", "fixed"].includes(c.state))
        throw new Error(`disclose requires an active reported case (is '${c.state}')`);
      return advance(c, "disclosed", { authorization, note: reason || "details released per timeline", extra: { at: now } });
    },
    publish(id, { authorization } = {}) {
      const c = load(id);
      if (c.state !== "disclosed") throw new Error(`publish requires state 'disclosed' (is '${c.state}')`);
      return advance(c, "published", { authorization, note: "public write-up (details + minimal reproducer; never the weapon)" });
    },
    withdraw(id, { authorization, reason = "" } = {}) {
      const c = load(id);
      return advance(c, "withdrawn", { authorization, note: reason || "not a real/eligible vuln" });
    },

    // The vendor case package — metadata + minimal reproducer DESCRIPTION only. No weapon.
    packageForVendor(id) {
      const c = load(id);
      const pkg = { component: c.target?.name, version: c.target?.version, source: c.target?.source,
        bug_class: c.vuln.class, cwe: c.vuln.cwe, root_cause: c.vuln.root_cause,
        minimal_reproducer: c.vuln.minimal_reproducer_description,
        munition_ref: c.munition_id, contact: "disclosure owner (see case)", policy: "disclosure-policy.md" };
      assertNoWeapon(pkg, "packageForVendor");
      return pkg;
    },

    advisory(id) {
      const c = load(id);
      const p = this.packageForVendor(id);
      return `# Advisory — ${p.component} ${p.version || ""}

- **State:** ${c.state}${c.public_reference ? ` (public ref ${c.public_reference})` : ""}
- **Bug class:** ${p.bug_class} (${p.cwe})
- **Root cause:** ${p.root_cause || "see case"}
- **Minimal reproducer:** ${p.minimal_reproducer || "provided to vendor privately"}
- **Weapon:** withheld — the armed reproducer stays inert and embargoed in the store (never published)
- **Reference:** ${p.source || ""}
`;
    },

    // Embargo status: deadline, elapsed, and whether disclosure is due.
    due(id, now = Date.now()) {
      const c = load(id);
      if (!c.embargo.deadline) return { reported: false, disclose_now: false };
      const elapsed = now >= c.embargo.deadline;
      return { reported: true, deadline: c.embargo.deadline, remaining_ms: c.embargo.deadline - now,
        elapsed, fixed: c.state === "fixed", disclose_now: elapsed || c.state === "fixed" };
    },

    // Ledger integrity + never-weapon re-check.
    verify(id) {
      const c = load(id);
      let prev = "GENESIS";
      for (let i = 0; i < c.ledger.length; i++) {
        const { event_hash, hmac, ...body } = c.ledger[i];
        if (body.seq !== i || body.prev !== prev) return { ok: false, reason: `chain break at ${i}` };
        const eh = sha256(canonical(body) + prev);
        if (eh !== event_hash) return { ok: false, reason: `event_hash mismatch at ${i}` };
        if (createHmac("sha256", key).update(eh).digest("hex") !== hmac) return { ok: false, reason: `bad signature at ${i}` };
        prev = hmac;
      }
      try { assertNoWeapon(c, "verify"); } catch (e) { return { ok: false, reason: e.message }; }
      return { ok: true, events: c.ledger.length, state: c.state };
    },

    get: (id) => summary(load(id)),
    list() { return existsSync(caseDir) ? readdirSync(caseDir).filter((f) => f.endsWith(".json")).map((f) => summary(JSON.parse(readFileSync(join(caseDir, f), "utf8")))) : []; },
  };

  function summary(c) {
    return { id: c.id, munition_id: c.munition_id, target: c.target, state: c.state,
      ownership: c.ownership, public_reference: c.public_reference, cwe: c.vuln.cwe,
      embargo: c.embargo, events: c.ledger.length };
  }
}
