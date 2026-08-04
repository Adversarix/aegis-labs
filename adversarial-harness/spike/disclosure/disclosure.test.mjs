// Tests for the coordinated-disclosure workflow (disclosure-policy.md, DESIGN §6.2).
// Pure (filesystem in a temp dir); no docker. Run: node disclosure.test.mjs
import { openDisclosure } from "./disclosure.js";
import { openStore } from "../munitions-store/store.js";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let pass = 0, fail = 0;
const ok = (name, cond) => { cond ? (pass++, console.log(`  ok  ${name}`)) : (fail++, console.error(`FAIL  ${name}`)); };
const threw = (fn, code) => { try { fn(); return false; } catch (e) { return code ? e.code === code : true; } };

const dir = mkdtempSync(join(tmpdir(), "disc-"));
const d = openDisclosure(dir, { key: "test-key" });

const munition = { id: "mun-123", ownership: "third-party" };
const target = { name: "stb_image", version: "2.19", source: "github.com/nothings/stb" };
const vuln = { class: "uncontrolled-resource-consumption", cwe: "CWE-789",
  root_cause: "unbounded allocation from crafted dimensions", minimal_reproducer_description: "a 70-byte BMP with huge declared dimensions" };
const OWNER = { role: "disclosure_owner", actor: "alice" };

// --- open: third-party only, embargoed by default ---
const c = d.open(munition, { vuln, target });
ok("opens in embargoed state", c.state === "embargoed");
ok("refuses an owned munition", threw(() => d.open({ id: "m2", ownership: "owned" }, { vuln, target })));

// --- RULE 1: harness cannot self-advance out of embargoed ---
ok("report without owner is refused (OWNER_REQUIRED)", threw(() => d.report(c.id, {}), "OWNER_REQUIRED"));
ok("report with a non-owner role is refused", threw(() => d.report(c.id, { authorization: { role: "harness", actor: "bot" } }), "OWNER_REQUIRED"));
ok("withdraw without owner is refused", threw(() => d.withdraw(c.id, {}), "OWNER_REQUIRED"));

// --- RULE 2: never the weapon ---
ok("open refuses vuln carrying the reproducer bytes",
  threw(() => d.open({ id: "m3", ownership: "third-party" }, { vuln: { ...vuln, reproducer_input_hex: "deadbeef" }, target }), "WEAPON_IN_DISCLOSURE"));
ok("vendor package contains NO weapon field",
  !JSON.stringify(d.packageForVendor(c.id)).match(/reproducer_input_hex|reproducer_hex|deadbeef/));
ok("advisory carries the CWE but not the weapon", /CWE-789/.test(d.advisory(c.id)) && !/reproducer_input_hex/.test(d.advisory(c.id)));

// --- lifecycle with owner authorization + embargo clock ---
const t0 = 1_000_000_000_000;
d.report(c.id, { authorization: OWNER, contact: "security@vendor", now: t0 });
ok("owner can report (embargoed -> reported)", d.get(c.id).state === "reported");
const due0 = d.due(c.id, t0);
ok("embargo deadline is 90 days out", Math.round((due0.deadline - t0) / (24 * 3600 * 1000)) === 90);
ok("not due before the deadline", d.due(c.id, t0 + 89 * 24 * 3600 * 1000).disclose_now === false);
ok("due once the embargo elapses", d.due(c.id, t0 + 91 * 24 * 3600 * 1000).disclose_now === true);

d.recordVendor(c.id, "acknowledged", { now: t0 + 1000 });
ok("vendor acknowledgement is recorded (no owner token)", d.get(c.id).state === "acknowledged");
d.recordVendor(c.id, "fixed");
ok("fixed state triggers early-disclosure due", d.due(c.id, t0).disclose_now === true);

ok("disclose without owner is refused even when reportable", threw(() => d.disclose(c.id, {}), "OWNER_REQUIRED"));
d.disclose(c.id, { authorization: OWNER });
ok("owner can disclose", d.get(c.id).state === "disclosed");
d.publish(c.id, { authorization: OWNER });
ok("owner can publish", d.get(c.id).state === "published");

// --- n-day fast path: already public -> disclosed, no embargo ---
const nday = d.open({ id: "mun-nday", ownership: "third-party" }, { vuln, target, public_reference: "CVE-2019-11835" });
ok("n-day opens straight to disclosed", nday.state === "disclosed" && nday.public_reference === "CVE-2019-11835");

// --- ledger integrity + never-weapon re-check ---
const v = d.verify(c.id);
ok("case ledger verifies", v.ok === true && v.events >= 5);

// --- store binding (§8): case transitions sync the munition's disclosure_status ---
const store = openStore(mkdtempSync(join(tmpdir(), "disc-store-")), { key: "k" });
const mun = store.create({ artifact: { reproducer_input_hex: "ab", recipe: "r", crash_report: "c" },
  ownership: "third-party", target_match: "t@1", disclosure_status: "embargoed" });
const db = openDisclosure(mkdtempSync(join(tmpdir(), "disc-b-")), { key: "k", store });
const cb = db.open(mun, { vuln, target });
db.report(cb.id, { authorization: OWNER, contact: "sec@t" });
ok("report syncs store disclosure_status to 'reported'", store.get(mun.id).disclosure_status === "reported");
db.withdraw(cb.id, { authorization: OWNER });
ok("withdraw syncs store to 'withdrawn'", store.get(mun.id).disclosure_status === "withdrawn");
ok("store now refuses arming the withdrawn munition",
  threw(() => store.arm(mun.id, { authorization: { role: "armorer", actor: "x" }, chamber_run_id: "C", target: "t@1" }), "DISCLOSURE_CLOSED"));

console.log(`\n${pass} passed, ${fail} failed`);
process.exit(fail === 0 ? 0 : 1);
