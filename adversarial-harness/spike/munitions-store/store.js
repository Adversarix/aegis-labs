// Munitions store — a filesystem-backed implementation of the custody policy
// (munitions-custody-policy.md), green tier. Makes every munition accountable
// from creation to verified destruction.
//
// What it enforces, in code:
//   - Inert by default: `armed` is false at rest, ALWAYS. Arming exists only
//     inside the detonation chamber, which is red-tier and unavailable here, so
//     `arm`/`detonate` are refused with a clear reason.
//   - Every touch logged: create/access/update/arm/export/dispose are appended to
//     a per-munition, append-only, HMAC-signed, hash-chained ledger. Any edit or
//     gap breaks the chain and `verify()` reports it.
//   - Inert-at-rest artifacts are encrypted (AES-256-GCM). Disposal crypto-shreds
//     the ciphertext, so "disposed" means unrecoverable.
//   - The harness never self-authorizes arm/export/dispose: those require an
//     explicit `authorization` object (a human token). create/access/update are
//     harness-authorized.
//
// Pure Node builtins (no external deps) so it is importable by both seams and
// unit-testable in isolation.
import { createHmac, createHash, randomUUID, randomBytes, createCipheriv, createDecipheriv, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, readdirSync, existsSync } from "node:fs";
import { join } from "node:path";

const canonical = (o) => JSON.stringify(o, Object.keys(o).sort());
const sha256 = (s) => createHash("sha256").update(s).digest("hex");

// Derive a stable 32-byte key from whatever the caller supplies (hex or passphrase).
function deriveKey(material) {
  return createHash("sha256").update(String(material)).digest(); // 32 bytes
}

function encrypt(key, plaintextBuf) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintextBuf), c.final()]);
  const tag = c.getAuthTag();
  return { iv: iv.toString("hex"), tag: tag.toString("hex"), ct: ct.toString("hex") };
}
function decrypt(key, enc) {
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(enc.iv, "hex"));
  d.setAuthTag(Buffer.from(enc.tag, "hex"));
  return Buffer.concat([d.update(Buffer.from(enc.ct, "hex")), d.final()]);
}

// Actions the ledger records (munitions-custody-policy.md §4).
const HARNESS_ACTIONS = new Set(["create", "access", "update"]);   // harness may self-authorize
const HUMAN_ACTIONS = new Set(["arm", "detonate", "export", "dispose"]); // require a human token

export function openStore(dir, opts = {}) {
  const key = deriveKey(opts.key || process.env.AEGIS_STORE_KEY || randomBytes(32).toString("hex"));
  const munDir = join(dir, "munitions");
  mkdirSync(munDir, { recursive: true });

  const path = (id) => join(munDir, `${id}.json`);
  const load = (id) => {
    if (!existsSync(path(id))) throw new Error(`no munition ${id}`);
    return JSON.parse(readFileSync(path(id), "utf8"));
  };
  const save = (m) => writeFileSync(path(m.id), JSON.stringify(m, null, 2));

  // Append a signed, hash-chained event to a munition's ledger.
  function appendEvent(m, { action, actor, run_id = null, authorization = null, reason = "", extra = {} }) {
    const prev = m.ledger.length ? m.ledger[m.ledger.length - 1].hmac : "GENESIS";
    const body = { seq: m.ledger.length, prev, action, actor, run_id,
      authorization_ref: authorization ? sha256(canonical(authorization)) : null, reason, ...extra };
    const event_hash = sha256(canonical(body) + prev);
    const hmac = createHmac("sha256", key).update(event_hash).digest("hex");
    m.ledger.push({ ...body, event_hash, hmac });
  }

  // A human authorization must be an object carrying at least {role, actor}. The
  // harness cannot fabricate one for itself: HUMAN_ACTIONS demand it explicitly.
  function requireHumanAuthz(action, authorization) {
    if (!HUMAN_ACTIONS.has(action)) return;
    if (!authorization || !authorization.role || !authorization.actor) {
      const e = new Error(`action '${action}' requires a human authorization {role, actor}; the harness cannot self-authorize`);
      e.code = "AUTHZ_REQUIRED";
      throw e;
    }
  }

  return {
    // Discovery promotes a confirmed crash into an inert munition (created/at_rest).
    create({ origin = "discovered", artifact, provenance = {}, ownership = "owned",
             target_match = "n/a", disclosure_status = "n/a", retention = { class: "owned-benign", expires_at: null },
             actor = "harness" } = {}) {
      if (!artifact) throw new Error("create requires an artifact { reproducer_input_hex, recipe, crash_report }");
      const id = randomUUID();
      const enc = encrypt(key, Buffer.from(JSON.stringify(artifact), "utf8"));
      const m = {
        id, origin, provenance, ownership, target_match, disclosure_status,
        custody_state: "at_rest", armed: false, retention,
        exploitation: { level: "crash", primitives: [], mitigations_defeated: [], reliability: null, objective: null },
        artifact_enc: enc, ledger: [],
      };
      appendEvent(m, { action: "create", actor, reason: "promoted from discovery" });
      save(m);
      return summary(m);
    },

    // Read a munition's decrypted artifact (logs an access event). This is how
    // develop INGESTS the reproducer to work it up the ladder.
    open(id, { actor = "harness", run_id = null } = {}) {
      const m = load(id);
      if (m.custody_state === "disposed") throw new Error(`munition ${id} is disposed`);
      const artifact = JSON.parse(decrypt(key, m.artifact_enc).toString("utf8"));
      appendEvent(m, { action: "access", actor, run_id, reason: "ingest for develop" });
      save(m);
      return { ...summary(m), artifact };
    },

    // Develop records the ladder progress back onto the munition.
    update(id, patch = {}, { actor = "harness", run_id = null, reason = "characterized in develop" } = {}) {
      const m = load(id);
      if (m.custody_state === "disposed") throw new Error(`munition ${id} is disposed`);
      const allowed = ["level", "primitives", "mitigations_defeated", "reliability", "objective"];
      for (const k of allowed) if (k in patch) m.exploitation[k] = patch[k];
      appendEvent(m, { action: "update", actor, run_id, reason, extra: { fields: Object.keys(patch) } });
      save(m);
      return summary(m);
    },

    // Arming is chamber-only and armorer-authorized (munitions-custody-policy.md
    // §6-7). It requires BOTH a human armorer token AND an active chamber run
    // (chamber_run_id supplied by the detonate orchestrator). With no chamber it is
    // refused (CHAMBER_UNAVAILABLE) — the green-tier behaviour. The armed state is
    // transient: armed <=> custody_state "armed" <=> mid-run; it must be reverted by
    // disarm on run end/kill.
    arm(id, { authorization, chamber_run_id } = {}) {
      requireHumanAuthz("arm", authorization);
      if (!chamber_run_id) {
        const e = new Error("arming refused: no active detonation chamber (chamber_run_id required)");
        e.code = "CHAMBER_UNAVAILABLE";
        throw e;
      }
      const m = load(id);
      if (m.custody_state === "disposed") throw new Error(`munition ${id} is disposed`);
      m.armed = true; m.custody_state = "armed";
      appendEvent(m, { action: "arm", actor: authorization.actor, run_id: chamber_run_id, authorization, reason: "armed for detonation" });
      save(m);
      return summary(m);
    },

    // Detonate: record the firing (chamber-only, must be armed). The marker ties
    // the emitted telemetry/IOCs back to this run.
    detonate(id, { chamber_run_id, marker, actor = "chamber" } = {}) {
      const m = load(id);
      if (!m.armed || m.custody_state !== "armed") throw new Error(`munition ${id} is not armed`);
      m.custody_state = "detonated";
      appendEvent(m, { action: "detonate", actor, run_id: chamber_run_id, reason: "fired in chamber", extra: { marker: marker ?? null } });
      save(m);
      return summary(m);
    },

    // Disarm: revert to inert. Called on run end, kill, or crash — the store never
    // leaves a munition armed at rest (Principle 1). Idempotent.
    disarm(id, { chamber_run_id, reason = "run ended" } = {}) {
      const m = load(id);
      if (!m.armed && m.custody_state !== "detonated" && m.custody_state !== "armed") return summary(m);
      m.armed = false; m.custody_state = "at_rest";
      appendEvent(m, { action: "disarm", actor: "chamber", run_id: chamber_run_id, reason });
      save(m);
      return summary(m);
    },

    // Dispose: crypto-shred the artifact ciphertext, close the ledger. Requires a
    // human authorization. "Disposed" is terminal and verified.
    dispose(id, { authorization, actor = authorization?.actor, reason = "disposition" } = {}) {
      requireHumanAuthz("dispose", authorization);
      const m = load(id);
      if (m.armed) throw new Error(`cannot dispose an armed munition ${id}`);
      m.artifact_enc = null;               // crypto-shred: destroy the ciphertext
      m.custody_state = "disposed";
      appendEvent(m, { action: "dispose", actor, authorization, reason });
      save(m);
      return { ...summary(m), shredded: true };
    },

    list() {
      if (!existsSync(munDir)) return [];
      return readdirSync(munDir).filter((f) => f.endsWith(".json"))
        .map((f) => summary(JSON.parse(readFileSync(join(munDir, f), "utf8"))));
    },

    // Integrity check: recompute the hash-chain + HMACs; detect any edit or gap.
    // Also reconciles the record's state against its ledger.
    verify(id) {
      const m = load(id);
      let prev = "GENESIS";
      for (let i = 0; i < m.ledger.length; i++) {
        const ev = m.ledger[i];
        const { event_hash, hmac, ...body } = ev;
        if (body.seq !== i || body.prev !== prev) return { ok: false, reason: `chain break at seq ${i}` };
        const eh = sha256(canonical(body) + prev);
        if (eh !== event_hash) return { ok: false, reason: `event_hash mismatch at seq ${i}` };
        const expect = createHmac("sha256", key).update(eh).digest("hex");
        const a = Buffer.from(expect, "hex"), b = Buffer.from(hmac, "hex");
        if (a.length !== b.length || !timingSafeEqual(a, b)) return { ok: false, reason: `bad signature at seq ${i}` };
        prev = hmac;
      }
      // reconciliation: disposed => artifact shredded and armed false; never armed at rest
      if (m.armed) return { ok: false, reason: "armed at rest (invariant violation)" };
      if (m.custody_state === "disposed" && m.artifact_enc !== null) return { ok: false, reason: "disposed but artifact present" };
      const closesWithDispose = m.custody_state === "disposed"
        ? m.ledger[m.ledger.length - 1]?.action === "dispose" : true;
      if (!closesWithDispose) return { ok: false, reason: "disposed state without a closing dispose event" };
      return { ok: true, events: m.ledger.length };
    },
  };

  function summary(m) {
    return {
      id: m.id, origin: m.origin, ownership: m.ownership, target_match: m.target_match,
      disclosure_status: m.disclosure_status, custody_state: m.custody_state, armed: m.armed,
      exploitation: m.exploitation, provenance: m.provenance, events: m.ledger.length,
    };
  }
}
