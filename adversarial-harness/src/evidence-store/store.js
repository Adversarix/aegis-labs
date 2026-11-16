// Evidence store — filesystem-backed implementation of the evidence chain-of-custody
// model (evidence-custody-spec.md), green tier. Binds every finding to the immutable
// captures that prove it, so a finding is an accountable claim and not an assertion.
//
// What it enforces, in code:
//   - Content-addressed, immutable captures: capture_id = sha256(observed bytes).
//     Sealing the same bytes twice dedups. Bytes rest encrypted (AES-256-GCM).
//   - No binding without a sealed capture: bind() to an unknown capture_id is refused
//     (BIND_UNSEALED). This is what stops a model "proving" a finding against bytes
//     that were never observed (spec §5 ordering guarantee).
//   - Quote by reference: a binding cites {offset,length} into sealed bytes; the quote
//     is re-derived on read, never stored as a free-text copy (spec §1.3).
//   - Tamper-evident chain: seal/bind/retest/supersede/view/export/dispose are appended
//     to signed, hash-chained custody ledgers via the shared module (src/custody-ledger).
//     verifyCustody() recomputes the chain AND the content hash of every referenced
//     capture, and fails closed.
//   - The sealed original never egresses: assembleBundle() emits only masked views of
//     probative/corroborating captures plus a custody manifest; raw bytes and the weapon
//     never leave (spec §6/§7).
//   - Human gates: assembleBundle (exported) and dispose require an explicit human
//     authorization {role, actor}; the harness cannot self-authorize egress or destruction.
//
// Pure Node builtins so both seams can import it and it is unit-testable in isolation.
import { createHash, createCipheriv, createDecipheriv, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { createLedger } from "../custody-ledger/ledger.js";

const sha256 = (buf) => createHash("sha256").update(buf).digest("hex");
const deriveKey = (material) => createHash("sha256").update(String(material)).digest();

function encrypt(key, plaintextBuf) {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([c.update(plaintextBuf), c.final()]);
  return { iv: iv.toString("hex"), tag: c.getAuthTag().toString("hex"), ct: ct.toString("hex") };
}
function decrypt(key, enc) {
  const d = createDecipheriv("aes-256-gcm", key, Buffer.from(enc.iv, "hex"));
  d.setAuthTag(Buffer.from(enc.tag, "hex"));
  return Buffer.concat([d.update(Buffer.from(enc.ct, "hex")), d.final()]);
}

const MEDIA_TYPES = new Set(["http_exchange", "tool_io", "pcap", "screenshot", "dom", "file"]);
const ROLES = new Set(["trigger", "response", "side_effect", "precondition", "retest"]);
const WEIGHTS = new Set(["probative", "corroborating", "context"]);
// Actions the evidence ledger requires a human token for (spec §10).
const HUMAN_ACTIONS = ["exported", "dispose"];

// Conservative secret scrubber for derived views (spec §6). Masks common credential
// shapes; errs toward masking. NOT exhaustive — extend per engagement. Throws only on
// a programming error, in which case deriveView fails closed and produces no view.
const SECRET_PATTERNS = [
  // Labeled header/field, colon style (e.g. "Authorization: Bearer x", "Cookie: sid=y"):
  // redact the whole value to end of line, so a scheme word like Bearer never shields
  // the token after it.
  [/\b(authorization|cookie|set-cookie|x-api-key|api[_-]?key|password|passwd|secret|token)\b[ \t]*:[ \t]*[^\n]*/gi, "$1: <redacted>"],
  // Labeled field, = style (query strings, kv): redact the token.
  [/\b(password|passwd|secret|token|api[_-]?key)\b(\s*=\s*)(\S+)/gi, "$1$2<redacted>"],
  [/\bBearer\s+[A-Za-z0-9._\-]+/g, "Bearer <redacted>"],
  [/\beyJ[A-Za-z0-9._\-]+\b/g, "<redacted-jwt>"],                  // JWT
  [/\bAKIA[0-9A-Z]{16}\b/g, "<redacted-aws-key>"],                 // AWS access key id
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "<redacted-private-key>"],
];
function mask(text) {
  let out = String(text);
  for (const [re, repl] of SECRET_PATTERNS) out = out.replace(re, repl);
  return out;
}

export function openEvidenceStore(dir, opts = {}) {
  const key = deriveKey(opts.key || process.env.AEGIS_EVIDENCE_KEY || randomBytes(32).toString("hex"));
  const ledger = createLedger({ key, humanActions: HUMAN_ACTIONS });

  const capDir = join(dir, "captures");
  const findDir = join(dir, "findings");
  mkdirSync(capDir, { recursive: true });
  mkdirSync(findDir, { recursive: true });
  const capLedgerPath = join(dir, "captures-ledger.json");

  const capPath = (id) => join(capDir, `${id}.json`);
  const findPath = (id) => join(findDir, `${id}.json`);
  const readJson = (p, fallback) => (existsSync(p) ? JSON.parse(readFileSync(p, "utf8")) : fallback);
  const writeJson = (p, o) => writeFileSync(p, JSON.stringify(o, null, 2));

  const loadCapLedger = () => readJson(capLedgerPath, { ledger: [] });
  const loadFinding = (id) => readJson(findPath(id), { finding_id: id, bindings: [], ledger: [] });

  // Seal an observation: content-address it, encrypt at rest, dedup, and log
  // capture_sealed. The seam passes the bytes; the agent never calls this with its
  // own fabrication because the seam, not the model, holds the key and invokes seal.
  function seal(bytes, { media_type, captured_by = "seam", run_id = null, source_meta = {} } = {}) {
    if (!MEDIA_TYPES.has(media_type)) throw new Error(`seal: unknown media_type '${media_type}'`);
    const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), "utf8");
    const capture_id = sha256(buf);
    if (existsSync(capPath(capture_id))) return { capture_id, deduped: true, size_bytes: buf.length };
    const rec = {
      capture_id, media_type, captured_at: new Date().toISOString(), captured_by, run_id,
      source_meta, size_bytes: buf.length, enc: encrypt(key, buf), disposed: false,
    };
    writeJson(capPath(capture_id), rec);
    const cl = loadCapLedger();
    ledger.append(cl.ledger, { action: "capture_sealed", actor: captured_by, run_id,
      extra: { capture_id, media_type, size_bytes: buf.length } });
    writeJson(capLedgerPath, cl);
    return { capture_id, deduped: false, size_bytes: buf.length };
  }

  function captureExists(capture_id) {
    return existsSync(capPath(capture_id));
  }

  // Bind a sealed capture to a finding as proof. Refuses an unsealed capture_id and
  // validates role/weight. A cited span is recorded by {offset,length}; the quote is
  // re-derived on read, never copied in.
  function bind(finding_id, { capture_id, span = null, role, weight, claim = "", asserted_by = "operator" } = {}) {
    if (!finding_id) throw new Error("bind requires a finding_id");
    if (!captureExists(capture_id)) {
      const e = new Error(`bind refused: capture '${capture_id}' is not sealed [spec §5]`);
      e.code = "BIND_UNSEALED"; throw e;
    }
    if (!ROLES.has(role)) throw new Error(`bind: unknown role '${role}'`);
    if (!WEIGHTS.has(weight)) throw new Error(`bind: unknown weight '${weight}'`);
    const f = loadFinding(finding_id);
    const binding = {
      binding_id: randomUUID(), finding_id, capture_id, span, role, weight, claim,
      asserted_by, status: "active", created_at: new Date().toISOString(),
    };
    f.bindings.push(binding);
    ledger.append(f.ledger, { action: "bound", actor: asserted_by, reason: claim,
      extra: { binding_id: binding.binding_id, capture_id, role, weight } });
    writeJson(findPath(finding_id), f);
    return { binding_id: binding.binding_id, finding_id, capture_id, role, weight };
  }

  // Retest: re-prove a finding against a (new) capture. Same finding_id, role "retest".
  function retest(finding_id, { capture_id, claim = "re-proven", asserted_by = "operator" } = {}) {
    if (!captureExists(capture_id)) {
      const e = new Error(`retest refused: capture '${capture_id}' is not sealed [spec §5]`);
      e.code = "BIND_UNSEALED"; throw e;
    }
    const f = loadFinding(finding_id);
    const binding = { binding_id: randomUUID(), finding_id, capture_id, span: null,
      role: "retest", weight: "corroborating", claim, asserted_by, status: "active",
      created_at: new Date().toISOString() };
    f.bindings.push(binding);
    ledger.append(f.ledger, { action: "retested", actor: asserted_by, reason: claim,
      extra: { binding_id: binding.binding_id, capture_id } });
    writeJson(findPath(finding_id), f);
    return { binding_id: binding.binding_id, finding_id, capture_id };
  }

  // Supersede a binding (mark stale, never delete).
  function supersede(finding_id, binding_id, { by = null, reason = "superseded", actor = "operator" } = {}) {
    const f = loadFinding(finding_id);
    const b = f.bindings.find((x) => x.binding_id === binding_id);
    if (!b) throw new Error(`no binding ${binding_id} on finding ${finding_id}`);
    b.status = "superseded";
    ledger.append(f.ledger, { action: "superseded", actor, reason, extra: { binding_id, by } });
    writeJson(findPath(finding_id), f);
    return { binding_id, status: "superseded" };
  }

  // The confirm gate (spec §1.1 / discovery-stage): a finding needs at least one active
  // probative binding before it may be promoted to confirmed_vuln. The promotion code
  // calls this; the evidence store does not own finding state.
  function hasProbativeBinding(finding_id) {
    const f = loadFinding(finding_id);
    return f.bindings.some((b) => b.weight === "probative" && b.status === "active");
  }

  // Re-derive a cited quote from sealed bytes (never a stored copy).
  function quote(capture_id, span) {
    const rec = readJson(capPath(capture_id), null);
    if (!rec || rec.disposed || !rec.enc) throw new Error(`capture ${capture_id} unavailable`);
    const bytes = decrypt(key, rec.enc);
    if (!span) return bytes;
    return bytes.subarray(span.offset, span.offset + span.length);
  }

  // Derive a masked, minimized view over captures (spec §6). Fails closed: if masking
  // throws, no view is produced. Logs view_derived on each finding that owns a capture
  // reference is out of scope here; the view is content-addressed and returned.
  function deriveView(finding_id, { capture_id, span = null, mask: doMask = true } = {}) {
    const raw = quote(capture_id, span); // Buffer
    let viewText;
    try {
      viewText = doMask ? mask(raw.toString("utf8")) : raw.toString("utf8");
    } catch (e) {
      const err = new Error(`deriveView failed closed (masking error): ${e.message}`);
      err.code = "MASK_FAILED"; throw err;
    }
    const view_id = sha256(Buffer.from(viewText, "utf8"));
    const f = loadFinding(finding_id);
    ledger.append(f.ledger, { action: "view_derived", actor: "harness",
      reason: doMask ? "masked view" : "raw view (in-boundary)",
      extra: { view_id, capture_id, masked: doMask } });
    writeJson(findPath(finding_id), f);
    return { view_id, capture_id, masked: doMask, bytes: viewText };
  }

  // Verify a finding's custody: the chain integrity AND the content hash of every
  // referenced capture. A capture whose bytes no longer hash to its id is tampered;
  // a disposed capture is allowed (manifest survives the bytes, spec §8).
  function verifyCustody(finding_id) {
    const f = loadFinding(finding_id);
    const chain = ledger.verify(f.ledger);
    if (!chain.ok) return { ok: false, reason: chain.reason ?? `chain break at ${chain.brokenAt}` };
    for (const b of f.bindings) {
      const rec = readJson(capPath(b.capture_id), null);
      if (!rec) return { ok: false, reason: `binding ${b.binding_id} references missing capture ${b.capture_id}` };
      if (rec.disposed) continue; // bytes gone by design; the sealed-id record remains
      let actual;
      try { actual = sha256(decrypt(key, rec.enc)); }
      catch { return { ok: false, reason: `capture ${b.capture_id} failed to decrypt (tampered or wrong key)` }; }
      if (actual !== b.capture_id) return { ok: false, reason: `capture ${b.capture_id} content hash mismatch (tampered)` };
    }
    return { ok: true, bindings: f.bindings.length, events: f.ledger.length };
  }

  // Assemble a disclosure bundle (spec §7). Human-authorized. Carries masked views of
  // probative + corroborating bindings only, plus the custody manifest; context-weight
  // reasoning is dropped and no raw bytes or munition leave.
  function assembleBundle(finding_id, { authorization, minimal_reproducer = null, actor = authorization?.actor } = {}) {
    ledger.requireAuthz("exported", authorization);
    const chk = verifyCustody(finding_id);
    if (!chk.ok) { const e = new Error(`bundle refused: custody broken (${chk.reason})`); e.code = "CUSTODY_BROKEN"; throw e; }
    const f = loadFinding(finding_id);
    const proofBindings = f.bindings.filter((b) => b.status === "active" && b.weight !== "context");
    const proof_views = proofBindings.map((b) => {
      const v = deriveView(finding_id, { capture_id: b.capture_id, span: b.span, mask: true });
      return { binding_id: b.binding_id, role: b.role, weight: b.weight, claim: b.claim,
        capture_id: b.capture_id, view_id: v.view_id, view: v.bytes };
    });
    const custody_manifest = f.ledger.map((e) => ({ seq: e.seq, action: e.action, actor: e.actor,
      run_id: e.run_id, event_hash: e.event_hash, hmac: e.hmac }));
    ledger.append(f.ledger, { action: "exported", actor, authorization, reason: "disclosure bundle",
      extra: { finding_id, views: proof_views.length } });
    writeJson(findPath(finding_id), f);
    return {
      finding_id, minimal_reproducer, proof_views, custody_manifest,
      attestation: { statement: "masked views project these sealed captures, seam-recorded, chain verified",
        at: new Date().toISOString(), by: actor },
      excludes: ["weapon/munition (disclosure-policy.md rule 2)", "context-weight reasoning", "raw sealed bytes"],
    };
  }

  // Dispose a capture: crypto-shred the ciphertext, keep the id/metadata record so the
  // manifest that it WAS proven survives (spec §8). Human-authorized.
  function dispose(capture_id, { authorization, reason = "retention expiry", actor = authorization?.actor } = {}) {
    ledger.requireAuthz("dispose", authorization);
    const rec = readJson(capPath(capture_id), null);
    if (!rec) throw new Error(`no capture ${capture_id}`);
    rec.enc = null; rec.disposed = true; // crypto-shred
    writeJson(capPath(capture_id), rec);
    const cl = loadCapLedger();
    ledger.append(cl.ledger, { action: "dispose", actor, authorization, reason, extra: { capture_id } });
    writeJson(capLedgerPath, cl);
    return { capture_id, shredded: true };
  }

  return {
    seal, bind, retest, supersede, hasProbativeBinding, quote, deriveView,
    verifyCustody, assembleBundle, dispose, captureExists,
    getFinding(id) { const f = loadFinding(id); return { finding_id: f.finding_id, bindings: f.bindings.length, events: f.ledger.length }; },
  };
}
