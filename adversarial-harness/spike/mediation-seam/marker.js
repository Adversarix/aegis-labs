// Signed synthetic-action markers (DESIGN.md §6 invariant 3).
//
// Every action the seam ALLOWS carries an HMAC-SHA256 marker over its canonical
// fields, keyed by a per-run secret. The marker is attributable (says which run
// produced the action) and unforgeable (a third party without the key cannot
// mint or alter one). It is recorded in the mediation log and injected into the
// sandbox run as $AEGIS_MARKER, so chamber telemetry can never be confused with
// a real incident and a real intruder cannot impersonate the sim.

import { createHmac, timingSafeEqual } from "node:crypto";

// Stable serialization: sort keys so the MAC is order-independent.
function canonical(fields) {
  return JSON.stringify(fields, Object.keys(fields).sort());
}

export function signMarker(key, fields) {
  const hmac = createHmac("sha256", key).update(canonical(fields)).digest("hex");
  return { ...fields, hmac };
}

export function verifyMarker(key, marker) {
  if (!marker || typeof marker.hmac !== "string") return false;
  const { hmac, ...fields } = marker;
  const expect = createHmac("sha256", key).update(canonical(fields)).digest("hex");
  const a = Buffer.from(expect, "hex");
  const b = Buffer.from(hmac, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}
